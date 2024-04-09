"""Utility function to handle the configuration of application logging.

Logs are output to both the console and to a specified log file.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import logging
import sys


def setup_logging(log_file: str, verbose: bool = False) -> None:
    """Configure logging.

    Args:
        log_file: A string representing the location of the log file.
        verbose: Boolean value representing whether to use the more verbose
            logging.DEBUG over the default logging.INFO

    Returns:
        None
    """

    # Define log file and console logging parameters
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    log_date_format = "%Y-%m-%d %H:%M:%S"
    log_filename = log_file
    log_formatter = logging.Formatter(log_format, log_date_format)

    console_format = "%(message)s"
    console_formatter = logging.Formatter(console_format)

    # Write to both standard console output, and a log file
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)
    log_handler = logging.FileHandler(filename=log_filename)
    log_handler.setFormatter(log_formatter)
    logger = logging.getLogger()
    logger.addHandler(console_handler)
    logger.addHandler(log_handler)
    logger.setLevel(log_level)
