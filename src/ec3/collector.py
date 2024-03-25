"""Utility class to handle the acquisition of source data.

Currently only supports the NVD 2.0 API via the NvdCollector class.

Typical usage example:
    source_collector = ec3.collector.NvdCollector()
    api_data = source_collector.pull_target_data()
    source_collector.save_data_to_file(api_data)

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import pickle
from datetime import datetime, timedelta

import nvdlib  # type: ignore
from nvdlib import classes as nvd_classes  # type: ignore

from ec3 import data_default_file

# Define the NVD 2.0 API's maximum number of days between parameter date ranges.
max_date_range: int = 120

# Default integer value for how many prior days to acquire data. Maximum value allowed is [ec3.collector.max_date_range]
date_difference_default: int = 30


class NvdCollector:
    """Obtain data from the NVD API via calls to nvdlib.

    Set available API parameters such as the api_key, lastModStartDate, and lastModEndDate.
    Set an optional verbose flag to display more details.

    Known API restrictions:
        - Date ranges have a maximum of [max_date_range] days (lastModEndDate - lastModStartDate)
        - Rate limited to 50 requests every 30 seconds within a scrolling window (with API key)
        - Rate limited to 5 requests every 30 seconds within a scrolling window (without API key)
    """

    def __init__(
        self,
        api_key: str | None = None,
        start_date: datetime = datetime.now() - timedelta(days=date_difference_default),
        end_date: datetime = datetime.now(),
        verbose: bool = False,
    ) -> None:
        """Initialize a NvdCollector class instance using the provided parameters.

        Args:
            api_key: Defaults to None. If provided, this is used to improve the API rate limits.
            start_date: Defaults to [date_difference_default] day(s) ago from the current date and time.
              Represents the earliest date boundary to obtain data. This value will be restricted to 1/1/2020 or later.
            end_date: Defaults to the current date and time. Represents the most current date boundary
              to obtain data. This value will be restricted to be equal to the current date and time or earlier.
            verbose: Defaults to False. A boolean flag to signal whether additional statements should be displayed.

        Returns:
            A NvdCollector instance with the default/specified dates adjusted to valid ranges. The api_key will be
              stored for later use when calling the API.
        """

        self.verbose = verbose
        self.api_key = api_key

        [self.start_date, self.end_date] = self.adjust_valid_dates(
            start_date=start_date, end_date=end_date
        )

        if self.verbose:
            print(
                f"Initialized NvdCollector to search CVEs from {self.start_date} until {self.end_date}."
            )
            print()  # print blank line

    def adjust_valid_dates(
        self, start_date: datetime, end_date: datetime
    ) -> list[datetime]:
        """Adjust datetime values to more appropriate start and end ranges.

        The start_date limit was determined on the basis that the CWE View 1003 was adjusted just before this
        time to coincide with the 2019 CWE Top 25 effort. This event marked the removal of CWE Categories and changed
        the entries within the View. Mapped CWE IDs prior to this have a higher potential to map to CWE Categories or
        contain less relevant mappings.

        Args:
            start_date: A desired API start date and time. This class will restrict this value to be
              1/1/2020 at the earliest and be equal to the current date and time if provided a future date and time.
            end_date: A desired API end date and time. This class will restrict this value to be equal
              to the current date and time if provided a future date and time.

        Returns:
            list[datetime]: A list of two datetimes representing the adjusted [start_date, end_date]
        """

        # Conduct date range validations: 2020-1-1 <= start_date <= end_date <= cur_date
        cur_date = datetime.now()

        if start_date < datetime(2020, 1, 1, 0, 0, 0):
            if self.verbose:
                print("start_date is prior to 2020-1-1. Adjusting to 2020-1-1.")
            start_date = datetime(2020, 1, 1, 0, 0, 0)

        if cur_date < start_date:
            if self.verbose:
                print(
                    f"start_date is later than the current date. Adjusting to {cur_date}."
                )
            start_date = cur_date

        if end_date < start_date:
            if self.verbose:
                print(
                    f"end_date is earlier than start_date. Adjusting to {start_date}."
                )
            end_date = start_date

        if cur_date < end_date:
            if self.verbose:
                print(
                    f"end_date is later than the current date and time. Adjusting to {cur_date}."
                )
            end_date = cur_date

        return [start_date, end_date]

    def pull_target_data(self) -> list[nvd_classes.CVE]:
        """Call the nvdlib.searchCVE API wrapper with the set NvdCollector class parameters.

        The nvdlib API call reaches out to 'https://services.nvd.nist.gov/rest/json/cves/2.0?'. SSL verification is
        enabled by default.

        Returns:
            A list of CVE objects
        """

        cve_search: list[nvd_classes.CVE] = []

        # If the date range is not within the [max_date_range] number of days, set a scrolling temporary date
        # window for each API call. Otherwise, only call the API once.
        if self.end_date - self.start_date > timedelta(days=max_date_range):
            # The NVD 2.0 API can only handle a max date range of [max_date_range] days. Ranges provided larger than
            # this will need to be split across multiple API calls. We set a scrolling window and aggregate the data.
            if self.verbose:
                print(
                    f"Target range {self.start_date} through {self.end_date} is larger than "
                    f"{max_date_range} days. Splitting into multiple calls for a scrolling {max_date_range} "
                    f"day time range."
                )
                print()  # print blank line
            temp_range_start: datetime = self.start_date
            temp_range_end: datetime = self.start_date + timedelta(days=max_date_range)

            # Call the API for the current temporary date range, then check if we have reached the end of the range.
            # Append the data returned from this scrolling date window's API call to the aggregate results.
            # The loop ends if (temp_range_end = self.end_date), after we called the API for this last window.
            # If the loop is not over, adjust the scrolling date window range and call the API again.
            while True:
                if self.verbose:
                    print(
                        f"Calling from ({temp_range_start}) through ({temp_range_end})."
                    )
                temp_cve_search: list[nvd_classes.CVE] = nvdlib.searchCVE(
                    key=self.api_key,
                    pubStartDate=temp_range_start,
                    pubEndDate=temp_range_end,
                )
                cve_search.extend(temp_cve_search)

                if not temp_range_end < self.end_date:
                    break

                temp_range_start = temp_range_end
                temp_range_end = min(
                    temp_range_start + timedelta(days=max_date_range),
                    self.end_date,
                )
        else:
            cve_search = nvdlib.searchCVE(
                key=self.api_key,
                pubStartDate=self.start_date,
                pubEndDate=self.end_date,
            )

        return cve_search

    def save_data_to_file(
        self, new_data: list[nvd_classes.CVE], data_file_str: str | None = None
    ) -> None:
        """Save JSON data from the NVD API into a pickle file that we can re-load without calling the API again.

        Args:
            new_data: A list of new vulnerability records to save to the data_file_str.
            data_file_str: A filename to write the saved NVD JSON data in pickle format, preserving the NVD object.

        Returns:
            None

        Raises:
            FileNotFoundError: Unable to find to the specified path to write data.
        """

        if data_file_str is None:
            if self.verbose:
                print(
                    f"No data_file provided, setting to default file: {data_default_file}"
                )
                print()  # print blank line
            data_file_str = data_default_file

        try:
            with open(data_file_str, "wb") as pickle_fh:
                pickle.dump(new_data, pickle_fh, pickle.HIGHEST_PROTOCOL)
        except FileNotFoundError:
            raise

        return None
