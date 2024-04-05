"""Utility class to handle the acquisition of source data.

Currently only supports the NVD 2.0 API via the NvdCollector class.

Typical usage example:
    source_collector = ec3.collector.NvdCollector()
    api_data = source_collector.pull_target_data()
    source_collector.save_data_to_file(api_data)

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import logging
import pickle
from datetime import datetime, timedelta
from typing import Generator

import nvdlib  # type: ignore
from nvdlib import classes as nvd_classes  # type: ignore

from ec3 import data_default_file

# Define the NVD 2.0 API's maximum number of days between parameter date ranges.
max_date_range: int = 120

# Default integer value for how many prior days to acquire data.
# Maximum value allowed is [ec3.collector.max_date_range]
date_difference_default: int = 30

logger = logging.getLogger(__name__)


class NvdCollector:
    """Obtain data from the NVD API via calls to nvdlib.

    Set available API parameters such as the api_key, pubStartDate, and pubEndDate.

    Known API restrictions:
        - Date ranges are a maximum of [max_date_range] days (pubEndDate - pubStartDate)
        - Rate limited to 50 requests per 30 seconds scrolling window (with API key)
        - Rate limited to 5 requests per 30 seconds scrolling window (without API key)
    """

    def __init__(
        self,
        api_key: str | None = None,
        start_date: datetime = datetime.now() - timedelta(days=date_difference_default),
        end_date: datetime = datetime.now(),
    ) -> None:
        """Initialize a NvdCollector class instance using the provided parameters.

        Args:
            api_key: Defaults to None. Used to improve the API rate limits.
            start_date: Defaults to [date_difference_default] day(s) ago from the
                current date and time. Represents the earliest date boundary to obtain
                data. This value will be restricted to 2020/1/1 or later.
            end_date: Defaults to the current date and time. Represents the most
                current date boundary to obtain data. This value will be restricted to
                be equal to the current date and time or earlier.

        Returns:
            A NvdCollector instance with the default/specified dates adjusted to valid
                ranges. The api_key will be stored for later use when calling the API.
        """

        self.api_key = api_key

        [self.start_date, self.end_date] = self.adjust_valid_dates(
            start_date=start_date, end_date=end_date
        )

        logger.info(
            f"Initialized NvdCollector to search CVEs from "
            f"{self.start_date} until {self.end_date}."
        )

    @staticmethod
    def adjust_valid_dates(start_date: datetime, end_date: datetime) -> list[datetime]:
        """Adjust datetime values to more appropriate start and end ranges.

        The start_date limit was determined on the basis that the CWE View 1003 was
        adjusted just before this time to coincide with the 2019 CWE Top 25 effort.
        This event marked the removal of CWE Categories and changed the entries within
        the View. Mapped CWE IDs prior to this have a higher potential to map to CWE
        Categories or contain less relevant mappings.

        Args:
            start_date: A desired API start date and time. This class will restrict
                this value to be 2020/1/1 at the earliest and be equal to the current
                date and time if provided a future date and time.
            end_date: A desired API end date and time. This class will restrict this
                value to be equal to the current date and time if provided a future
                date and time.

        Returns:
            list[datetime]: A list of two datetimes representing the adjusted
                [start_date, end_date]
        """

        # Conduct date range validations: 2020-1-1 <= start_date <= end_date <= cur_date
        cur_date = datetime.now()

        if start_date < datetime(2020, 1, 1, 0, 0, 0):
            logger.warning("start_date is prior to 2020-1-1. Adjusting to 2020-1-1.")
            start_date = datetime(2020, 1, 1, 0, 0, 0)

        if cur_date < start_date:
            logger.warning(
                f"start_date is later than the current date. Adjusting to {cur_date}."
            )
            start_date = cur_date

        if end_date < start_date:
            logger.warning(
                f"end_date is earlier than start_date. Adjusting to {start_date}."
            )
            end_date = start_date

        if cur_date < end_date:
            logger.warning(
                f"end_date is later than the current date and time. "
                f"Adjusting to {cur_date}."
            )
            end_date = cur_date

        return [start_date, end_date]

    def pull_target_data(self) -> list[nvd_classes.CVE]:
        """Call the nvdlib.searchCVE API wrapper with the set class parameters.

        The nvdlib API call reaches out to
        'https://services.nvd.nist.gov/rest/json/cves/2.0?'. SSL verification is
        enabled by default.

        Returns:
            A list of CVE objects
        """

        cve_search: list[nvd_classes.CVE] = []
        for temp_range_start, temp_range_end in self.generate_time_ranges(
            self.start_date, self.end_date
        ):
            logger.debug(
                f"Calling from ({temp_range_start}) through ({temp_range_end})."
            )
            temp_cve_search: list[nvd_classes.CVE] = nvdlib.searchCVE(
                key=self.api_key,
                pubStartDate=temp_range_start,
                pubEndDate=temp_range_end,
            )
            cve_search.extend(temp_cve_search)

        return cve_search

    @staticmethod
    def generate_time_ranges(
        start_date: datetime, end_date: datetime
    ) -> Generator[list[datetime], None, None]:
        """Create datetime ranges within the API maximum limits for the desired bounds.

        The NVD 2.0 API can only handle a max date range of [max_date_range] days.
        Requested ranges larger than this will need to be split across multiple API
        calls.

        Args:
            start_date: The earliest datetime range bound to pass to the NVD API.
            end_date: The latest datetime range bound to pass to the NVD API.

        Yields:
            A list of two datetime values representing the start and end bounds for the
            API call, which are [max_date_range] days apart or less.
        """
        if end_date - start_date > timedelta(days=max_date_range):
            logger.debug(
                f"Target range {start_date} through {end_date} is larger "
                f"than {max_date_range} days. Splitting into multiple calls for a "
                f"scrolling {max_date_range} day time range."
            )
            temp_range_start: datetime = start_date
            temp_range_end: datetime = start_date + timedelta(days=max_date_range)

            # The datetime difference was more than the maximum range, yield a set of
            # [start, end] datetime values then shift the scrolling window.
            # The loop ends if (temp_range_end = end_date), after we yielded the range
            # values for the previous window.
            while True:
                yield [temp_range_start, temp_range_end]
                if not temp_range_end < end_date:
                    break

                temp_range_start = temp_range_end
                temp_range_end = min(
                    temp_range_start + timedelta(days=max_date_range),
                    end_date,
                )
        else:
            yield [start_date, end_date]

    @staticmethod
    def save_data_to_file(
        new_data: list[nvd_classes.CVE], data_file_str: str | None = None
    ) -> None:
        """Save JSON data from the NVD API into a pickle file to re-load without
            calling the API again.

        Args:
            new_data: A list of new vulnerability records to save to the data_file_str.
            data_file_str: A filename to write the saved NVD JSON data in pickle format,
                preserving the NVD object.

        Returns:
            None

        Raises:
            FileNotFoundError: Unable to find to the specified path to write data.
        """

        if data_file_str is None:
            logger.debug(
                f"No data_file provided, setting to default file: {data_default_file}"
            )
            data_file_str = data_default_file

        try:
            with open(data_file_str, "wb") as pickle_fh:
                pickle.dump(new_data, pickle_fh, pickle.HIGHEST_PROTOCOL)
        except FileNotFoundError:
            raise

        return None
