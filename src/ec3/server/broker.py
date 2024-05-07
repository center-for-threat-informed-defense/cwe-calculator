"""Utility class to handle the construction of Cvss31Calculators.

Typical usage example:
    broker = ec3.server.Cvss31CalculatorBroker()
    broker.start()
    calculator = broker.request_calculator()
    broker.stop()

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import logging
import os
import pickle
from threading import Lock, RLock

from nvdlib import classes as nvd_classes  # type: ignore
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ec3 import data_default_file, normalization_default_file
from ec3.calculator import Cvss31Calculator

logger = logging.getLogger(__name__)


class Cvss31CalculatorBroker(FileSystemEventHandler):
    """Instantiates and configures `Cvss31Calculators`.

    A `Cvss31CalculatorBroker` monitors a specified vulnerability and normalization file
    for changes and updates internal representations of these files when changes are
    detected. All `Cvss31Calculators` produced by a broker are configured with the
    latest vulnerability and normalization data available from these files.

    Brokers are completely thread-safe. They can be started and stopped from any thread.
    Multiple threads can request new calculators from the same broker simultaneously.
    """

    @property
    def is_running(self) -> bool:
        """A property that represents the broker's running state.

        Returns:
            bool: `True` if the broker is running, `False` otherwise.
        """
        with self.__service_lock:
            return self.__is_running

    @property
    def data_file_str(self) -> str:
        """The broker's vulnerability file path.

        Returns:
            str: The broker's vulnerability file path.
        """
        with self.__service_lock:
            return self.__data_file_str

    @property
    def normalization_file_str(self) -> str:
        """The broker's normalization file path.

        Returns:
            str: The broker's normalization file path.
        """
        with self.__service_lock:
            return self.__normalization_file_str

    def __init__(
        self,
        data_default_file: str = data_default_file,
        normalization_default_file: str = normalization_default_file,
    ) -> None:
        """Instantiates a new Calculator Broker.

        Args:
            (optional) data_file_str: The vulnerability file's path. If a path is not
                specified, the default vulnerability file is used.
            (optional) normalization_file_str: The normalization file's path. If a path
                is not specified, the default normalization file is used.
        """
        self.__data_lock = Lock()
        self.__service_lock = RLock()
        self.__observer = Observer()
        self.__event_handler = ModifiedCalculatorDataHandler(self)
        self.__data_file_str: str = data_default_file
        self.__normalization_file_str: str = normalization_default_file
        self.__vulnerability_data: list[nvd_classes.CVE] = []
        self.__normalization_data: list[list] = []
        self.__is_running = False

    def start(
        self,
        data_file_str: None | str = None,
        normalization_file_str: None | str = None,
    ):
        """Starts the Calculator Broker.

        To reset an already running broker, simply invoke this function again with the
        preferred vulnerability and normalization files, `stop()` doesn't need to be
        invoked beforehand.

        If no vulnerability or normalization files are specified, the previously
        specified files will be used instead. If no files were previously specified, the
        default vulnerability and normalization files will be used.

        Args:
            (optional) data_file_str: The vulnerability file's path.
            (optional) normalization_file_str: The normalization file's path.
        """
        with self.__service_lock:
            self.stop()

            # Configure vulnerability and normalization file
            if data_file_str is not None:
                self.__data_file_str = data_file_str
            if normalization_file_str is not None:
                self.__normalization_file_str = normalization_file_str

            logger.info("Starting Cvss31 Calculator Broker...")

            # Configure and start the observer
            self.__observer = Observer()
            vuln_file_dir = os.path.dirname(self.data_file_str)
            norm_file_dir = os.path.dirname(self.normalization_file_str)
            self.__observer.schedule(self.__event_handler, vuln_file_dir)
            if norm_file_dir != vuln_file_dir:
                self.__observer.schedule(self.__event_handler, norm_file_dir)
            self.__observer.start()

            # Initialize internal vulnerability and normalization structures
            self.update_vulnerability_data()
            self.update_normalization_data()

            # Flag the service as started
            self.__is_running = True

            logger.info("Started Cvss31 Calculator Broker.")

    def stop(self):
        """Stops the Calculator Broker."""
        with self.__service_lock:
            if not self.__is_running:
                return

            logging.info("Stopping Cvss31 Calculator Broker...")

            # Destroy existing observer
            self.__observer.stop()
            self.__observer.unschedule_all()

            # Flag the service as stopped
            self.__is_running = False

            logger.info("Stopped Cvss31 Calculator Broker.")

    def request_calculator(self) -> Cvss31Calculator:
        """Returns a new `Cvss31Calculator`.

        Instantiates and configures a new `Cvss31Calculator` with the latest
        vulnerability and normalization data available (from the configured sources).

        Returns:
            Cvss31Calculator: A newly configured Cvss31Calculator.
        """
        calculator = Cvss31Calculator(support_defaults=True)
        with self.__data_lock:
            calculator.set_normalization_data(self.__normalization_data)
            calculator.set_vulnerability_data(self.__vulnerability_data)
        return calculator

    def update_vulnerability_data(self):
        """Updates the internal representation of the vulnerability file.

        Using the configured vulnerability file path, this function updates the internal
        representation of the vulnerability data. As long as the broker is running,
        there's no need to invoke this function manually. However, it can be invoked at
        anytime if desired.
        """
        logging.debug("Updating vulnerability data...")
        try:
            with self.__data_lock:
                self.__vulnerability_data = Cvss31Calculator.restricted_load(
                    self.__data_file_str
                )
                logger.info(f"Vulnerability data updated. [{self.__data_file_str}]")
        except FileNotFoundError:
            logger.error(
                "Failed to update vulnerability data. "
                "Data file was not found."
                f"({ self.__data_file_str })"
            )
        except PermissionError:
            logger.error(
                "Failed to update vulnerability data. "
                "Insufficient permissions to access data file."
                f"({ self.__data_file_str })"
            )
        except pickle.UnpicklingError:
            logger.error(
                "Failed to update vulnerability data. "
                "Data file uses an invalid pickle format."
                f"({ self.__data_file_str })"
            )

    def update_normalization_data(self):
        """Updates the internal representation of the normalization file.

        Using the configured normalization file path, this function updates the internal
        representation of the normalization data. As long as the broker is running,
        there's no need to invoke this function manually. However, it can be invoked at
        anytime if desired.
        """
        logging.debug("Updating normalization data...")
        try:
            with self.__data_lock:
                self.__normalization_data = Cvss31Calculator.parse_normalization_file(
                    file_str=self.__normalization_file_str
                )
                logger.info(
                    f"Normalization data updated. [{self.__normalization_file_str}]"
                )
        except TypeError:
            logger.error(
                "Failed to update normalization data. "
                "Normalization file is not in the correct format."
                f"({ self.__data_file_str })"
            )
        except FileNotFoundError:
            logger.error(
                "Failed to update normalization data. "
                "Normalization file was not found."
                f"({ self.__normalization_file_str })"
            )
        except PermissionError:
            logger.error(
                "Failed to update normalization data. "
                "Insufficient permissions to access normalization file."
                f"({ self.__data_file_str })"
            )


class ModifiedCalculatorDataHandler(FileSystemEventHandler):
    """A custom event handler that responds to file modification events.

    This class is designed to work in conjunction with a `Cvss31CalculatorBroker`
    instance. It checks if a modified file is the vulnerability or normalization file
    being monitored by the `Cvss31CalculatorBroker`. If so, it triggers the
    `Cvss31CalculatorBroker` to update its internal representation of this data.
    """

    def __init__(self, broker: Cvss31CalculatorBroker) -> None:
        super().__init__()
        self.__broker = broker

    def on_modified(self: "ModifiedCalculatorDataHandler", event: FileSystemEvent):
        """File modification event handler.

        This function is inherited from `FileSystemEventHandler` and is invoked by
        by the associated `Cvss31CalculatorBroker`'s `Observer`. This event handler
        updates the `Cvss31CalculatorBroker`'s internal vulnerability and normalization
        data when changes are detected in the associated files.

        Args:
            event (FileModifiedEvent): The file modification event.
        """

        # Check if the vulnerability file was updated
        logging.debug(f"Detected change to file '{event.src_path}'.")
        is_vuln_file = False
        try:
            is_vuln_file = os.path.samefile(event.src_path, self.__broker.data_file_str)
        except FileNotFoundError:
            logging.debug(
                "Failed to compare modified file to vulnerability file. "
                "Modified file no longer exists."
            )
            is_vuln_file = False
        # Update vulnerability data
        if is_vuln_file:
            self.__broker.update_vulnerability_data()
            return True

        # Check if the normalization file was updated
        is_norm_file = False
        try:
            is_norm_file = os.path.samefile(
                event.src_path, self.__broker.normalization_file_str
            )
        except FileNotFoundError:
            is_norm_file = False
            logging.debug(
                "Failed to compare modified file to normalization file. "
                "Modified file no longer exists."
            )
        # Update normalization data
        if is_norm_file:
            self.__broker.update_normalization_data()
            return True

        return False
