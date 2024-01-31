"""
Utility class to handle the acquisition of source data.

Currently only supports the NVD 2.0 API via the NvdUpdater class.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

from datetime import datetime, timedelta

import nvdlib  # type: ignore
from nvdlib import classes as nvd_classes  # type: ignore


class NvdUpdater:
    """
    Wrapper class to obtain data from the NVD API via calls to nvdlib.
    Set available API parameters such as the api_key, lastModStartDate, and lastModEndDate
    Optional verbose flag to display more details.

    Known API restrictions:
        - Date ranges have a maximum of 120 days (lastModEndDate - lastModStartDate)
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
        self.verbose = verbose
        if self.verbose:
            print("Initializing NvdUpdater...")
        self.api_key = api_key

        # Conduct date range validations: 1/1/2020 <= target_range_start <= target_range_end <= now
        if target_range_start <= datetime(2020, 1, 1, 0, 0, 0):
            if self.verbose:
                print(
                    f"target_range_start is prior to 1/1/2020. Adjusting to 1/1/2020."
                )
            target_range_start = datetime(2020, 1, 1, 0, 0, 0)
        if target_range_end <= target_range_start:
            if self.verbose:
                print(
                    f"target_range_end is earlier to target_range_start. Adjusting to {target_range_start}."
                )
            target_range_end = target_range_start
        cur_date = datetime.now()
        if cur_date < target_range_end:
            if self.verbose:
                print(
                    f"target_range_end is later than the current date and time. Adjusting to {cur_date}."
                )
            target_range_end = cur_date
        self.target_range_start = target_range_start
        self.target_range_end = target_range_end

        if self.verbose:
            print(
                f"Initialized to search CVEs from {self.target_range_start} until {self.target_range_end}."
            )

    def pull_target_data(self) -> list[nvd_classes.CVE]:
        """
        Call the nvdlib.searchCVE API wrapper with the set nvd_updater class parameters.
        The nvdlib API call reaches out to 'https://services.nvd.nist.gov/rest/json/cves/2.0?'.
        SSL verification is enabled by default.
        :return: list of CVE objects
        """
        cve_search = []
        if self.target_range_end - self.target_range_start > timedelta(days=120):
            # scroll
            if self.verbose:
                print(
                    f"Target range {self.target_range_start} through {self.target_range_end} is larger than 120 days."
                    f" Setting scrolling window..."
                )
            temp_range_start = self.target_range_start
            temp_range_end = self.target_range_start + timedelta(days=120)
            while True:
                if self.verbose:
                    print(
                        f"Calling from ({temp_range_start}) through ({temp_range_end})."
                    )
                temp_cve_search = nvdlib.searchCVE(
                    key=self.api_key,
                    lastModStartDate=temp_range_start,
                    lastModEndDate=temp_range_end,
                )
                cve_search.extend(temp_cve_search)
                if not temp_range_end < self.target_range_end:
                    break
                temp_range_start = temp_range_end
                temp_range_end = min(
                    temp_range_start + timedelta(days=120), self.target_range_end
                )
        else:
            cve_search = nvdlib.searchCVE(
                key=self.api_key,
                lastModStartDate=self.target_range_start,
                lastModEndDate=self.target_range_end,
            )

        return cve_search


if __name__ == "__main__":
    # Initialize to defaults and get updated data
    source_updater = NvdUpdater()
    raw_cve_data = source_updater.pull_target_data()
