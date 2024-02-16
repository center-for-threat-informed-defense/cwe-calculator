"""
Utility class to handle the acquisition of source data.

Currently only supports the NVD 2.0 API via the NvdCollector class.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

from datetime import datetime, timedelta

import nvdlib  # type: ignore
from nvdlib import classes as nvd_classes  # type: ignore

# Define the NVD 2.0 API's maximum number of days between parameter date ranges.
max_date_range: int = 120

# Default integer value for how many prior days to acquire data. Maximum value allowed is [ec3.collector.max_date_range]
date_difference_default: int = 1


class NvdCollector:
    """
    Wrapper class to obtain data from the NVD API via calls to nvdlib.
    Set available API parameters such as the api_key, lastModStartDate, and lastModEndDate
    Optional verbose flag to display more details.

    Known API restrictions:
        - Date ranges have a maximum of [max_date_range] days (lastModEndDate - lastModStartDate)
        - Rate limited to 50 requests every 30 seconds within a scrolling window (with API key)
        - Rate limited to 5 requests every 30 seconds within a scrolling window (without API key)
    """

    def __init__(
        self,
        api_key: str | None = None,
        target_range_start: datetime = datetime.now() - timedelta(days=1),
        target_range_end: datetime = datetime.now(),
        verbose: bool = False,
    ) -> None:
        """
        Initialize a NvdCollector class instance using the provided parameters.

        :param api_key: Defaults to None. If provided, this is used to improve the API rate limits.
        :param target_range_start: Defaults to one day ago from the current date and time. Represents the
        earliest date boundary to obtain data. This class will restrict this value to be 1/1/2020 at the earliest.
        :param target_range_end: Defaults to the current date and time. Represents the most current date boundary
        to obtain data. This class will restrict this value to be equal to the current date and time if provided
        a future date and time.
        :param verbose: Defaults to False. A boolean flag to signal whether additional statements should be displayed.
        :return None
        """

        self.verbose = verbose
        self.api_key = api_key

        [self.target_range_start, self.target_range_end] = self.adjust_valid_dates(
            target_range_start=target_range_start, target_range_end=target_range_end
        )

        if self.verbose:
            print(
                f"Initialized NvdCollector to search CVEs from {self.target_range_start} until {self.target_range_end}."
            )

    def adjust_valid_dates(
        self, target_range_start: datetime, target_range_end: datetime
    ) -> list[datetime]:
        """
        Utility function to adjust datetime values to more appropriate start and end ranges. The target_range_start
        limit was determined on the basis that the CWE View 1003 was adjusted just before this time to coincide with the
        2019 CWE Top 25 effort. This event marked the removal of Categories and changed the entries within the View.
        Mapped CWE IDs prior to this have a higher potential to map to CWE Categories or contain less relevant mappings.

        :param target_range_start: A desired API start date and time. This class will restrict this value to be
        1/1/2020 at the earliest and be equal to the current date and time if provided a future date and time.
        :param target_range_end: A desired API end date and time. This class will restrict this value to be equal
        to the current date and time if provided a future date and time.
        :return list[datetime]: A list of two datetimes representing the adjusted [target_range_start, target_range_end]
        """

        # Conduct date range validations: 1/1/2020 <= target_range_start <= target_range_end <= cur_date
        cur_date = datetime.now()

        if target_range_start <= datetime(2020, 1, 1, 0, 0, 0):
            if self.verbose:
                print("target_range_start is prior to 1/1/2020. Adjusting to 1/1/2020.")
            target_range_start = datetime(2020, 1, 1, 0, 0, 0)

        if cur_date < target_range_start:
            if self.verbose:
                print(
                    f"target_range_start is later than the current date. Adjusting to {cur_date}."
                )
            target_range_start = cur_date

        if target_range_end <= target_range_start:
            if self.verbose:
                print(
                    f"target_range_end is earlier than target_range_start. Adjusting to {target_range_start}."
                )
            target_range_end = target_range_start

        if cur_date < target_range_end:
            if self.verbose:
                print(
                    f"target_range_end is later than the current date and time. Adjusting to {cur_date}."
                )
            target_range_end = cur_date

        return [target_range_start, target_range_end]

    def pull_target_data(self) -> list[nvd_classes.CVE]:
        """
        Call the nvdlib.searchCVE API wrapper with the set NvdCollector class parameters.
        The nvdlib API call reaches out to 'https://services.nvd.nist.gov/rest/json/cves/2.0?'.
        SSL verification is enabled by default.

        :return: list of CVE objects
        """

        cve_search: list[nvd_classes.CVE] = []

        # If the date range is not within the [max_date_range] number of days, set a scrolling temporary date
        # window for each API call. Otherwise, only call the API once.
        if self.target_range_end - self.target_range_start > timedelta(
            days=max_date_range
        ):
            # The NVD 2.0 API can only handle a max date range of [max_date_range] days. Ranges provided larger than
            # this will need to be split across multiple API calls. We set a scrolling window and aggregate the data.
            if self.verbose:
                print(
                    f"Target range {self.target_range_start} through {self.target_range_end} is larger than {max_date_range} days. "
                    f"Splitting into multiple calls for a scrolling {max_date_range} day time range..."
                )
            temp_range_start: datetime = self.target_range_start
            temp_range_end: datetime = self.target_range_start + timedelta(
                days=max_date_range
            )

            # Call the API for the current temporary date range, then check if we have reached the end of the range.
            # Append the data returned from this scrolling date window's API call to the aggregate results.
            # The loop ends if (temp_range_end = self.target_range_end), after we called the API for this last window.
            # If the loop is not over, adjust the scrolling date window range and call the API again.
            while True:
                if self.verbose:
                    print(
                        f"Calling from ({temp_range_start}) through ({temp_range_end})."
                    )
                temp_cve_search: list[nvd_classes.CVE] = nvdlib.searchCVE(
                    key=self.api_key,
                    lastModStartDate=temp_range_start,
                    lastModEndDate=temp_range_end,
                )
                cve_search.extend(temp_cve_search)

                if not temp_range_end < self.target_range_end:
                    break

                temp_range_start = temp_range_end
                temp_range_end = min(
                    temp_range_start + timedelta(days=max_date_range),
                    self.target_range_end,
                )
        else:
            cve_search = nvdlib.searchCVE(
                key=self.api_key,
                lastModStartDate=self.target_range_start,
                lastModEndDate=self.target_range_end,
            )

        return cve_search


if __name__ == "__main__":
    # If called directly, initialize to default parameters and get updated data
    source_collector = NvdCollector()
    raw_cve_data = source_collector.pull_target_data()
