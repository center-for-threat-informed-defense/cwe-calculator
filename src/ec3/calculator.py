"""
Environmental CWE CVSS Calculator (ec3)
Calculate the average CVSS score for a specified CWE identifier, provided optional environmental modifiers.
Utilizes data from NVD via the 2.0 API.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import argparse
import collections
import csv
import io
import pickle
from datetime import datetime, timedelta

from nvdlib import classes as nvd_classes  # type: ignore
from requests.exceptions import SSLError

from ec3.updater import NvdUpdater

# Default path for storing returned API data.
data_default: str = "./data/nvd_loaded.pickle"

# Default integer value for how many prior days to acquire data. Maximum value allowed is [ec3.updater.max_date_range]
date_difference_default: int = 1


class RestrictedUnpickler(pickle.Unpickler):
    """Helper class to restrict the unpickler to just nvdlib.classes.CVE objects"""

    def find_class(self, module, name) -> nvd_classes.CVE:
        """Overrides the default unpickler find_class method."""

        # Permit nvdlib.classes.CVE to be loaded and forbid everything else.
        if module == "nvdlib.classes" and name in {"CVE"}:
            return nvd_classes.CVE
        raise pickle.UnpicklingError(f"Found an illegal class: ({module}).({name})")


def parse_args() -> argparse.Namespace:
    """Create the argument parser and parse the arguments

    Available arguments:
    (Required) cwe - An integer for the desired CWE to be calculated.
    (optional) load_file - A string pointing to a pickle file that contains NVD JSON 2.0 data.
    (optional) normalize_file - A string pointing to a two column CSV file that contains the normalization data.
    (optional) update - A flag to signal a request to pull new data from NVD. Utilizes optional api_key,
    time_range_start, and time_range_end values if available.
    (optional) target_range_start - A date formatted string (MM-DD-YYYY). Date must be 1-1-2020 or after.
    (optional) target_range_end - A date formatted string (MM-DD-YYYY). Date must be the current date or earlier.
    (optional) verbose - A flag to enable more detailed messages in the console.

    Mutually exclusive:
    (optional) key - A string value corresponding to the user's NVD API key. Usage improves API rate limits.
    (optional) keyfile - A string identifying a file that contains the NVD API key string.

    """

    parser = argparse.ArgumentParser(description="Environmental CWE CVSS Calculator")
    parser.add_argument(
        "cwe",
        help="CWE numerical identifier (e.g. 20 for CWE-20)",
        action="store",
        type=int,
    )
    parser.add_argument(
        "--load_file", "-l", help="Path to the pickle file to parse", type=str
    )
    parser.add_argument(
        "--normalize_file",
        "-n",
        help="Path to the normalization CSV file to parse",
        type=str,
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

    # Allow for a key or a keyfile but not both.
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


def restricted_load(file_str) -> list[nvd_classes.CVE]:
    """Helper function to restrict the loaded class type"""

    return RestrictedUnpickler(io.FileIO(file_str)).load()


def load_nvd_data(pickle_file_str: str) -> list[nvd_classes.CVE]:
    """Load the pickle file containing the NVD data into a nvdlib.classes.CVE list that we can handle
    params
    :param pickle_file_str: A path to the pickle file containing the NVD data to load
    :return list: A list of nvdlib.classes.CVE objects (or an empty list if an error is encountered)
    """

    # If unable to load data from a file or file permissions are encountered, returns None.
    # Otherwise, return the list of nvdlib's CVE objects previously saved.
    try:
        return restricted_load(pickle_file_str)
    except FileNotFoundError:
        print(f"Caught FileNotFoundError. Input file not found.")
        return []
    except pickle.UnpicklingError as e:
        print(
            f"Caught UnpicklingError. Input file was not in correct pickle format. {e}"
        )
        return []


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
        print(f"Caught FileNotFoundError. Output file not found.")
    return None


def load_normalization_data(normalization_file_str: str, orig_id: int) -> int | None:
    """Load the normalization data CSV file and returns the first corresponding normalization CWE identifier.
    The normalization file should only have one suggestion per CWE ID in the left column.
    The file may map an identifier to itself or "Other". Both of these cases should return None (no new normalization).

    :param normalization_file_str: A path to the CSV file containing the normalization data to load
    :param orig_id: An integer for the originally requested CWE identifier, which will be used in a lookup of the data.
    :return int: An integer of the found CWE identifier to map to, or None if no new valid normalization value is found.
    """

    # If unable to load data from a file, file permissions are encountered, or no lookup value is found, returns None.
    # Otherwise, return the integer lookup value for the orig_id to normalize to.
    try:
        with open(normalization_file_str, mode="r") as normalization_fh:
            normalization_file = csv.reader(normalization_fh)
            for lines in normalization_file:
                if lines[0] == orig_id.__str__():
                    if lines[1] == "Other" or lines[1] == orig_id.__str__():
                        return None
                    try:
                        return int(lines[1])
                    except:
                        return None
            return None
    except FileNotFoundError:
        print(f"Caught FileNotFoundError. Input normalization file not found.")
        return None
    except PermissionError:
        print("Caught PermissionError. Unable to open normalization file.")
        return None


def get_cvss(cve: nvd_classes.CVE) -> str | None:
    """Returns the CVSS score (as a vector) from a single CVE.

    :param cve: A dictionary from the list of CVEs loaded from the NVD data
    :return CVSS 3.1 vector string if found, otherwise None
    """

    # Our CVE data must not be Rejected, and must contain a CVSS 3.1 vector.
    if cve.vulnStatus == "Rejected" or not cve.metrics:
        return None
    try:
        return cve.v31vector
    except AttributeError:
        return None


def get_cwes(cve: nvd_classes.CVE) -> list[int]:
    """Get all valid CWEs associated with the single nvdlib CVE object

    :param cve: A single CVE record from the list of CVEs loaded from the NVD data
    :return A list containing the numerical ids of valid CWEs parsed from this CVE.
    """

    cwes: list[int] = []

    # Our CVE data must not be Rejected, and contain a CWE identifier. "cve.cwe" will not exist if no CWE is found.
    try:
        if cve.vulnStatus == "Rejected" or not cve.cwe:
            return cwes
    except AttributeError:
        return cwes

    # CVEs might have multiple CWE mappings and each mapping might contain space delimited CWEs.
    for cwe in cve.cwe:

        # Ignore valid mappings that are not found within CWE.
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

        # Call "strip" in case someone put a space before or after when doing a CWE mapping.
        # Split on the '-' in 'CWE-###' and add the number to the list
        try:
            if " " in cwe.value:
                for x in cwe.value.split(" "):

                    # Ensure that we're not trying to parse the empty string
                    if not x:
                        continue
                    cwes.append(int(x.strip().split("-")[1]))
            else:
                cwes.append(int(cwe.value.split("-")[1].strip()))
        except (IndexError, ValueError):
            continue

    return cwes


def run() -> None:
    """
    Entry point for calculator.
    """

    # Parse CLI arguments
    args = parse_args()

    if args.verbose:
        print(args)

    api_key = args.key
    if args.keyfile:
        try:
            with open(args.keyfile) as f:
                api_key = f.read().rstrip("\n")
        except PermissionError:
            print("Caught PermissionError. Unable to open keyfile.")
            return None

    # Expected target_range_end format is MM - DD - YYYY.
    # If not present, default to current date and time.
    if args.target_range_end:
        target_range_end = datetime.strptime(args.target_range_end, "%m-%d-%Y")
    else:
        target_range_end = datetime.now()

    # Expected target_range_start format is MM - DD - YYYY.
    # If not present, set value to current date and time minus the date_difference_default global variable.
    if args.target_range_start:
        target_range_start = datetime.strptime(args.target_range_start, "%m-%d-%Y")
    else:
        target_range_start = datetime.now() - timedelta(days=date_difference_default)

    raw_cve_data: list[nvd_classes.CVE] = []
    if not args.update and args.load_file is None:
        if args.verbose:
            print(
                f"No load_file provided, and no update flag set. Loading default data from {data_default}"
            )
        args.load_file = data_default

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
            print(f"Caught SSLError. Error connecting to NVD.")
            return None
        except PermissionError:
            print(
                "Caught PermissionError. Unable to write to pickle file. Continuing with data in memory."
            )
    # Load the pre-saved CVE data from the pickle file
    else:
        if args.verbose:
            print("Loading input file ...")
        raw_cve_data = load_nvd_data(args.load_file)

    # Dictionary that maps CWE ID to list of CVSS vectors
    cwe_data: dict[int, list[str]] = collections.defaultdict(list)

    # Populate the CWE dictionary and cve count
    cve_count = 0
    if raw_cve_data:
        for cve in raw_cve_data:
            cve_count += 1
            cvss_score = get_cvss(cve)
            if cvss_score is not None:
                cwes_for_cve = get_cwes(cve)
                for cwe in cwes_for_cve:
                    cwe_data[cwe].append(cvss_score)

    # Display the number of CVE entries in the raw_cve_data
    if args.verbose:
        print(f"Processed {cve_count} CVEs.")

    # Get the input CWE. Make sure the ID is not negative.
    if args.cwe < 0:
        if args.verbose:
            print(
                f"Input CWE was negative ({args.cwe}). Using the absolute value ({abs(args.cwe)}) instead."
            )
        cwe_id = abs(args.cwe)
    else:
        cwe_id = args.cwe

    # Include normalized results if present.
    if args.normalize_file:
        normalization_id: int | None = load_normalization_data(
            args.normalize_file, cwe_id
        )

        # If a valid integer mapping was found within the file, include the normalized results if available
        # Otherwise, report no mapping present.
        if normalization_id is not None and normalization_id > 0:
            if cwe_data[normalization_id]:
                normalized_ec3_results: dict = {
                    "CWE": normalization_id,
                    "Count": len(cwe_data[normalization_id]),
                    "CVSS Vectors": cwe_data[normalization_id],
                }
                if args.verbose:
                    print(f"CWE data found for normalized ID {normalization_id}!")
            else:
                normalized_ec3_results = {
                    "CWE": normalization_id,
                    "Count": 0,
                    "CVSS Vectors": "N/A",
                }
                if args.verbose:
                    print(f"No normalized CWE data found for ID {normalization_id}!")
            print(normalized_ec3_results)
        else:
            if args.verbose:
                print(f"No normalized CWE ID found for ID {cwe_id}!")

    # Create an output format with all required information
    if cwe_data[cwe_id]:
        ec3_results: dict = {
            "CWE": cwe_id,
            "Count": len(cwe_data[cwe_id]),
            "CVSS Vectors": cwe_data[cwe_id],
        }
        if args.verbose:
            print(f"CWE data found for requested ID {cwe_id}!")
    else:
        if args.verbose:
            print(f"No CWE data found for ID {cwe_id}!")
        # list entry will not exist if no CWE's found with that ID.
        ec3_results = {"CWE": cwe_id, "Count": 0, "CVSS Vectors": "N/A"}

    print(ec3_results)
    return None


if __name__ == "__main__":
    run()