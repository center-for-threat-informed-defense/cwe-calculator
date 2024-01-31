"""
Environmental CWE CVSS Calculator (ec3)
Calculate the average CVSS score for a specified CWE identifier, provided optional environmental modifiers.
Utilizes data from NVD via the 2.0 API.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import argparse
import collections
import io
import pickle

# import statistics
# import re
from datetime import datetime, timedelta

from nvdlib import classes as nvd_classes  # type: ignore
from requests.exceptions import SSLError

from ec3.updater import NvdUpdater

# Default path for storing returned API data.
data_default: str = "./data/nvd_loaded.pickle"

# Default value for how many prior days to acquire data. Maximum value allowed is 120
date_difference_default: int = 2


def parse_args() -> argparse.Namespace:
    """Create the argument parser and parse the arguments

    Available arguments:
    (Required) cwe - An integer for the desired CWE to be calculated.
    (optional) loadfile - A string pointing to a pickle file that contains NVD JSON 2.0 data.
    (optional) update - A flag to signal a request to pull new data from NVD. Utilizes optional api_key,
    time_range_start, and time_range_end values if available.
    (optional) target_range_start - A date formatted string (MM-DD-YYYY). Date must be 1-1-2020 or after.
    (optional) target_range_end - A date formatted string (MM-DD-YYYY). Date must be the current date or earlier.
    (optional) verbose - A flag to enable more detailed messages in the console.

    Mutually exclusive:
    (optional) key - A string value corresponding to the user's NVD API key. Usage improves API rate limits.
    (optional) keyfile - A string identifying a file that contains the NVD API key string.
    ...

    """
    parser = argparse.ArgumentParser(description="Environmental CWE CVSS Calculator")
    parser.add_argument(
        "cwe",
        help="CWE numerical identifier (e.g. 20 for CWE-20)",
        action="store",
        type=int,
    )
    parser.add_argument(
        "--loadfile", "-j", help="Path to the pickle file to parse", type=str
    )
    parser.add_argument(
        "--update",
        "-u",
        help="Flag to utilize the NVD API to refresh source data",
        action="store_true",
    )
    parser.add_argument(
        "--target_range_start",
        help="Date of earliest NVD data desired. Date must be 1-1-2020 or after. Expected format is MM-DD-YYYY.",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--target_range_end",
        help="Date of most recent NVD data desired. Expected format is MM-DD-YYYY.",
        action="store",
        type=str,
    )
    parser.add_argument("--verbose", "-v", help="Verbose output", action="store_true")
    # Allow for a key or a keyfile
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument(
        "--key", action="store", default=None, type=str, help="NVD api_key string."
    )
    key_group.add_argument(
        "--keyfile",
        action="store",
        default=None,
        help="Filename containing NVD api_key string",
        type=str,
    )
    return parser.parse_args()


class RestrictedUnpickler(pickle.Unpickler):
    """Helper class to restrict the unpickler to just nvdlib.classes.CVE objects"""

    def find_class(self, module, name):
        """Overrides the default unpickler find_class method."""
        if module == "nvdlib.classes" and name in {"CVE"}:
            return nvd_classes.CVE
        # Forbid everything else.
        raise pickle.UnpicklingError(f"Found an illegal class: ({module}).({name})")


def restricted_load(file_str):
    """Helper function to restrict the loaded class type"""
    return RestrictedUnpickler(io.FileIO(file_str)).load()


def load_nvd_data(pickle_file_str: str) -> list | None:
    """Load the pickle file containing the NVD data into a nvdlib.classes.CVE list that we can handle
    params
    :param pickle_file_str: A path to the pickle file containing the NVD data to load
    :return list: a list of nvdlib.classes.CVE objects
    """
    try:
        return restricted_load(pickle_file_str)
    except FileNotFoundError:
        print(f"Input file not found.")
        return None
    except pickle.UnpicklingError as e:
        print(f"Input file was not in correct pickle format. {e}")
        return None


def save_nvd_data(pickle_file_str: str, cve_data: list) -> None:
    """Save JSON data returned from the NVD API into a pickle file that we can re-load without calling the API again.
    :param pickle_file_str: A filename to write the saved NVD JSON data in pickle format, preserving the NVD object.
    :param cve_data: Raw CVE data returned from NVD API. Schema 2.0.
    :return None
    """
    try:
        with open(pickle_file_str, "wb") as pickle_fh:
            pickle.dump(cve_data, pickle_fh, pickle.HIGHEST_PROTOCOL)
    except FileNotFoundError:
        print(f"Output file not found.")
        return None


def get_cvss(cve: nvd_classes.CVE) -> str | None:
    """Returns the CVSS score (as a vector) from a single CVE.

    :param cve: A dictionary from the list of CVEs loaded from the NVD data
    """

    # CVEs rejected by NVD
    if cve.vulnStatus == "Rejected" or not cve.metrics:
        return None
    try:
        return cve.v31vector
    except AttributeError:
        return None


def get_cwes(cve: nvd_classes.CVE) -> list[int]:
    """Get all valid CWEs associated with the CVE dictionary

    :param cve: A single CVE record from the list of CVEs loaded from the NVD data
    :return A list containing the numerical ids of valid CWEs parsed from this CVE.
    """
    cwes: list[int] = []
    try:
        if cve.vulnStatus == "Rejected" or not cve.cwe:
            return cwes
    except AttributeError:
        # cve.cwe will not exist if no CWE is found.
        return cwes
    for cwe in cve.cwe:
        if cwe.value in [
            "NVD-CWE-noinfo",
            "NVD-CWE-Other",
            "NVD-CWE-Insufficient-Info",
            "UNSURE",
            "Unsure",
            "CWE-GAP",
            "CWE-Gap",
        ]:
            continue
        try:
            # CWEs might have multiple mappings
            # NOTE: The calls to `strip` are in case someone put a space before or after when
            # doing a CWE mapping, because there were a few instances of those
            if " " in cwe.value:
                for x in cwe.value.split(" "):
                    # Ensure that we're not trying to parse the empty string
                    if not x:
                        continue
                    # Split on the '-' in 'CWE-###' and add the number to the list
                    cwes.append(int(x.strip().split("-")[1]))
            else:
                cwes.append(int(cwe.value.split("-")[1].strip()))
        except (IndexError, ValueError):
            continue
    return cwes


def run():
    """
    Entry point for calculator.
    """
    # Parse CLI arguments
    args = parse_args()
    if args.verbose:
        print(args)
    api_key = args.key
    if args.keyfile:
        with open(args.keyfile) as f:
            api_key = f.read().rstrip("\n")

    # Expected format is MM - DD - YYYY.
    if args.target_range_end:
        target_range_end = datetime.strptime(args.target_range_end, "%m-%d-%Y")
    else:
        target_range_end = datetime.now()

    if args.target_range_start:
        target_range_start = datetime.strptime(args.target_range_start, "%m-%d-%Y")
    else:
        # Configure the number of days to obtain from the NVD API
        target_range_start = datetime.now() - timedelta(days=date_difference_default)

    raw_cve_data = []
    if not args.update and args.loadfile is None:
        if args.verbose:
            print(
                f"No loadfile provided, and no update flag set. Loading default data from {data_default}"
            )
        args.loadfile = data_default
    # If refresh flag passed in, pull new data
    if args.update:
        if args.verbose:
            print("Updating from NVD API...")
        source_updater = NvdUpdater(
            api_key=api_key,
            target_range_start=target_range_start,
            target_range_end=target_range_end,
            verbose=args.verbose,
        )
        try:
            raw_cve_data = source_updater.pull_target_data()
            if args.verbose:
                print(f"Saving data from API call to default file {data_default}...")
            save_nvd_data(cve_data=raw_cve_data, pickle_file_str=data_default)
        except SSLError as e:
            print(f"Caught SSLError. Unable to reach NVD. TEMP_MESSAGE:__{e}__")
            # print(f"Caught SSLError. Issue with NVD API connection.")
            return
        except PermissionError:
            print(
                "Caught PermissionError. Unable to write to pickle file. Continuing with data in memory."
            )
        except Exception as e:
            # Figure out error when unable to save_nvd_data. file currently read-only
            print(f"type:{type(e)}, __{e}__")
            return
    # Load the pre-saved CVE data from the pickle file
    else:
        if args.verbose:
            print("Loading input file ...")
        raw_cve_data = load_nvd_data(args.loadfile)

    # Dictionary that maps CWE ID to list of CVSS vectors
    cwe_data: dict[int, list[str]] = collections.defaultdict(list)

    # Keep track of the number of CVEs processed (as a sanity check)
    cve_count = 0

    # Populate the CWE dictionary and log any failures
    if raw_cve_data:
        for cve in raw_cve_data:
            # Update the cve count
            cve_count += 1
            cvss_score = get_cvss(cve)
            if cvss_score is not None:
                cwes_for_cve = get_cwes(cve)
                for cwe in cwes_for_cve:
                    cwe_data[cwe].append(cvss_score)

    # Sanity check on the number of CVEs processed
    if args.verbose:
        if args.update:
            print(f"Processed {cve_count} CVEs from API response.")
        else:
            print(f"Processed {cve_count} CVEs from input file.")

    # Get the input CWE
    cwe_id = args.cwe
    # Create an output format with all required information
    if cwe_data[cwe_id]:
        ec3_results: dict = {
            "CWE": cwe_id,
            "Count": len(cwe_data[cwe_id]),
            # "Average CVSS": statistics.mean(cwe_data[cwe_id]),
            "CVSS Vectors": cwe_data[cwe_id],
        }
    else:
        ec3_results = {"CWE": cwe_id, "Count": 0, "Average CVSS": "N/A"}

    print(ec3_results)


if __name__ == "__main__":
    run()
