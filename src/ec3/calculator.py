"""
The Environmental CWE CVSS Calculator (ec3) is used to calculate a potential CVSS score for a provided CWE
Identifier. Data from the National Vulnerability Database(NVD) is pulled via the 2.0 API and stored for later re-use.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import argparse
import collections
import csv
import io
import pickle
import statistics
from datetime import datetime, timedelta

from nvdlib import classes as nvd_classes  # type: ignore
from requests.exceptions import SSLError

from ec3.cvss import Cvss31
from ec3.collector import NvdCollector

# Default path for storing returned API data.
data_default_file: str = "./data/nvd_loaded.pickle"

# Default integer value for how many prior days to acquire data. Maximum value allowed is [ec3.collector.max_date_range]
date_difference_default: int = 1


class RestrictedUnpickler(pickle.Unpickler):
    """
    Helper class to restrict the unpickler to just nvdlib.classes.CVE objects
    """

    def find_class(self, module, name) -> nvd_classes.CVE:
        """
        Overrides the default unpickler find_class method.
        Only permit nvdlib.classes.CVE to be loaded by the unpickler. For any other type raise an exception to stop
        a potentially malicious module.
        """

        if module == "nvdlib.classes" and name in {"CVE"}:
            return nvd_classes.CVE
        raise pickle.UnpicklingError(f"Found an illegal class: ({module}).({name})")


def parse_args() -> argparse.Namespace:
    """
    Create the argument parser and parse the arguments

    Available arguments:
    (Required) cwe - An integer for the desired CWE to be calculated.
    (optional) data_file - A string pointing to a pickle file that contains NVD JSON 2.0 data.
    (optional) normalize_file - A string pointing to a two column CSV file that contains the normalization data.
    (optional) update - A flag to signal a request to pull new data from NVD. Utilizes optional api_key,
    time_range_start, and time_range_end values if available.
    (optional) target_range_start - A date formatted string (MM-DD-YYYY). Date must be 1-1-2020 or after.
    (optional) target_range_end - A date formatted string (MM-DD-YYYY). Date must be the current date or earlier.
    (optional) verbose - A flag to enable more detailed messages in the console.

    Mutually exclusive:
    (optional) key - A string value corresponding to the user's NVD API key. Usage improves API rate limits.
    (optional) keyfile - A string identifying a file that contains the NVD API key string.

    Temporal modification metrics:
    (optional) exploit_code_maturity - A string representing the exploit code maturity (E) metric.
    (optional) remediation_level - A string representing the remediation level (RL) metric.
    (optional) report_confidence - A string representing the report confidence (RC) metric.

    Environmental modification metrics:
    (optional) modified_confidentiality - A string representing the modified confidentiality (MC) metric.
    (optional) modified_integrity - A string representing the modified integrity (MI) metric.
    (optional) modified_availability - A string representing the modified availability (MA) metric.
    """

    parser = argparse.ArgumentParser(description="Environmental CWE CVSS Calculator")
    parser.add_argument(
        "cwe",
        help="CWE numerical identifier (e.g., 787 for CWE-787)",
        action="store",
        type=int,
    )
    parser.add_argument(
        "--data_file",
        "-d",
        help="Path to the CVE data pickle file to parse",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--normalize_file",
        "-n",
        help="Path to the normalization CSV file to parse",
        action="store",
        type=str,
    )
    update_group = parser.add_argument_group(title="Related NVD API parameters")
    update_group.add_argument(
        "--update",
        "-u",
        help="Flag to utilize the NVD API to refresh source data",
        action="store_true",
    )
    update_group.add_argument(
        "--target_range_start",
        help="Date of earliest NVD data desired. Date must be 1-1-2020 or after. Expected format is MM-DD-YYYY.",
        action="store",
        type=str,
    )
    update_group.add_argument(
        "--target_range_end",
        help="Date of most recent NVD data desired. Expected format is MM-DD-YYYY.",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--verbose",
        "-v",
        help="Flag to enable verbose output.",
        action="store_true",
    )

    # Allow for a key or a keyfile but not both.
    key_group = update_group.add_mutually_exclusive_group()
    key_group.add_argument(
        "--key",
        help="NVD api_key string.",
        action="store",
        type=str,
    )
    key_group.add_argument(
        "--keyfile",
        help="Filename containing NVD api_key string",
        action="store",
        type=str,
    )

    # Allow for individual temporal CVSS metrics to be passed in.
    temporal_group = parser.add_argument_group(title="Temporal Metrics")
    temporal_group.add_argument(
        "--exploit-code-maturity",
        "-e",
        help="Temporal exploit code maturity (E) metric. (Expected values: X, H, F, P, U)",
        type=str,
    )
    temporal_group.add_argument(
        "--remediation-level",
        "-rl",
        help="Temporal remediation level (RL) metric. (Expected values: X, U, W, T, O)",
        type=str,
    )
    temporal_group.add_argument(
        "--report-confidence",
        "-rc",
        help="Temporal report confidence (RC) metric. (Expected values: X, C, R, U)",
        type=str,
    )

    # Allow for individual environmental modified impact CVSS metrics to be passed in.
    environmental_group = parser.add_argument_group(title="Environmental Metrics")
    environmental_group.add_argument(
        "--modified-confidentiality",
        "-mc",
        help="Environmental modified confidentiality (MC) metric. (Expected values:  X, N, L, H)",
        type=str,
    )
    environmental_group.add_argument(
        "--modified-integrity",
        "-mi",
        help="Environmental modified integrity (MI) metric. (Expected values: X, N, L, H)",
        type=str,
    )
    environmental_group.add_argument(
        "--modified-availability",
        "-ma",
        help="Environmental modified availability (MA) metric. (Expected values: X, N, L, H)",
        type=str,
    )

    return parser.parse_args()


def restricted_load(file_str) -> list[nvd_classes.CVE]:
    """
    Helper function to restrict the loaded class type
    """

    return RestrictedUnpickler(io.FileIO(file_str)).load()


def load_nvd_data(pickle_file_str: str) -> list[nvd_classes.CVE]:
    """
    Load the pickle file containing the NVD data into a nvdlib.classes.CVE list that we can handle.
    If unable to load data from a file or file permissions are encountered, returns an empty list.
    Otherwise, return the list of nvdlib's CVE objects previously saved.

    :param pickle_file_str: A path to the pickle file containing the NVD data to load
    :return list: A list of nvdlib.classes.CVE objects (or an empty list if an error is encountered)
    """

    try:
        return restricted_load(pickle_file_str)
    except FileNotFoundError:
        print(f"Caught FileNotFoundError. Input file not found.")
        return []
    except PermissionError:
        print(f"Caught FileNotFoundError. Unable to read data file.")
        return []
    except pickle.UnpicklingError:
        print(f"Caught UnpicklingError. Input file was not in correct pickle format.")
        return []


def save_nvd_data(pickle_file_str: str, cve_data: list) -> None:
    """
    Save JSON data returned from the NVD API into a pickle file that we can re-load without calling the API again.

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
    """
    Load the normalization data CSV file and returns the first corresponding normalization CWE identifier.
    The normalization file should only have one suggestion per CWE ID in the left column.
    The file may map an identifier to itself or "Other". Both of these cases should return None (no new normalization).

    If unable to load data from a file, file permissions are encountered, or no lookup value is found, returns None.
    Otherwise, return the integer lookup value for the orig_id to normalize to.

    :param normalization_file_str: A path to the CSV file containing the normalization data to load
    :param orig_id: An integer for the originally requested CWE identifier, which will be used in a lookup of the data.
    :return int: An integer of the found CWE identifier to map to, or None if no new valid normalization value is found.
    """

    try:
        with open(normalization_file_str, mode="r") as normalization_fh:
            normalization_file = csv.reader(normalization_fh)
            for lines in normalization_file:
                if lines[0] == orig_id.__str__():
                    if lines[1] == "Other" or lines[1] == orig_id.__str__():
                        return None

                    # Try to cast the normalized value column as an integer, return None if unable
                    try:
                        return int(lines[1])
                    except ValueError:
                        return None
            return None
    except FileNotFoundError:
        print(f"Caught FileNotFoundError. Input normalization file not found.")
        return None
    except PermissionError:
        print("Caught PermissionError. Unable to open normalization file.")
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

    # If args.data_file was not provided, then set it to data_default_file.
    if args.data_file is None:
        if args.verbose:
            print(
                f"No data_file provided. Setting default data_file to {data_default_file}"
            )
        args.data_file = data_default_file

    raw_cve_data: list[nvd_classes.CVE] = []

    # If the args.update flag was passed in, then pull the most recently modified data for the date range provided.
    # Save the pulled source data to the specified or default [data_file] location
    if args.update:
        if args.verbose:
            print("Updating from NVD API...")
        source_collector = NvdCollector(
            api_key=api_key,
            target_range_start=target_range_start,
            target_range_end=target_range_end,
            verbose=args.verbose,
        )
        try:
            raw_cve_data = source_collector.pull_target_data()
            if args.verbose:
                print(f"Saving data from API call to data file...")
            save_nvd_data(cve_data=raw_cve_data, pickle_file_str=args.data_file)
        except SSLError:
            print(f"Caught SSLError. Error connecting to NVD.")
            return None
        except PermissionError:
            print(
                "Caught PermissionError. Unable to write to pickle file. Continuing with data in memory."
            )

    # We need to load some source of data from NVD into the raw_cve_data object. If we just performed an update, then
    # this object already exists, so only perform the following load if we haven't done the update.
    else:
        raw_cve_data = load_nvd_data(args.data_file)
        if args.verbose:
            print("Update not requested, loaded existing data file.")

    # Dictionary that maps CWE ID to list of CVSS vectors
    cwe_data: dict[int, list[Cvss31]] = collections.defaultdict(list)

    # Populate the CWE dictionary and cve count
    cve_count = 0
    if raw_cve_data:
        for cve in raw_cve_data:
            cve_count += 1
            try:
                if hasattr(cve, "v31vector"):
                    base_cvss = Cvss31.from_cve(cve=cve)

                    # Set optional temporal modifiers
                    if args.exploit_code_maturity:
                        base_cvss.set_e(args.exploit_code_maturity)
                    if args.remediation_level:
                        base_cvss.set_rl(args.remediation_level)
                    if args.report_confidence:
                        base_cvss.set_rc(args.report_confidence)

                    # Set optional environmental modifiers
                    if args.modified_confidentiality:
                        base_cvss.set_mc(args.modified_confidentiality)
                    if args.modified_integrity:
                        base_cvss.set_mi(args.modified_integrity)
                    if args.modified_availability:
                        base_cvss.set_ma(args.modified_availability)
                    # if args.exploit_code_maturity:
                    #     print(f"found exploit code maturity value:{args.e}")

                    cwes_for_cve = get_cwes(cve)
                    for cwe in cwes_for_cve:
                        cwe_data[cwe].append(base_cvss)
            except ValueError:
                print("Caught ValueError.")
                raise

    # Display the number of CVE entries in the raw_cve_data
    if args.verbose:
        print(f"Processed {cve_count} vulnerabilities.")

    # Get the input CWE. Make sure the ID is not negative.
    if args.cwe < 0:
        cwe_id = abs(args.cwe)
        if args.verbose:
            print(
                f"Input CWE was negative ({args.cwe}). Used the absolute value ({abs(args.cwe)}) instead."
            )
    else:
        cwe_id = args.cwe

    # Include normalized results if present.
    if args.normalize_file:
        normalization_id: int | None = load_normalization_data(
            args.normalize_file, cwe_id
        )

        # If a valid integer mapping was found within the file, include the normalized results if available
        if normalization_id is not None and normalization_id > 0:
            if cwe_data[normalization_id]:
                normalized_score_values: list[list[float]] = []
                for x in cwe_data[normalization_id]:
                    scores = [x.get_base_score(), x.get_environmental_score()]
                    normalized_score_values.append(scores)

                normalized_ec3_results: dict = {
                    "Projected CVSS:": statistics.mean(
                        [item[1] for item in normalized_score_values]
                    )
                } | (
                    {
                        "CWE": normalization_id,
                        "Count": len(cwe_data[normalization_id]),
                        "Min CVSS Base Score:": min(
                            [item[0] for item in normalized_score_values]
                        ),
                        "Max CVSS Base Score:": max(
                            [item[0] for item in normalized_score_values]
                        ),
                        "Average CVSS Base Score:": statistics.mean(
                            [item[0] for item in normalized_score_values]
                        ),
                    }
                    if args.verbose
                    else {}
                )

                if args.verbose:
                    print(
                        f"Vulnerability data found for normalized CWE ID {normalization_id}!"
                    )
            else:
                normalized_ec3_results = {"Projected CVSS:": 0} | (
                    {
                        "CWE": normalization_id,
                        "Count": 0,
                        "Min CVSS Base Score:": 0,
                        "Max CVSS Base Score:": 0,
                        "Average CVSS Base Score:": 0,
                    }
                    if args.verbose
                    else {}
                )
                if args.verbose:
                    print(
                        f"No vulnerability data found for normalized CWE ID {normalization_id}!"
                    )

            print(normalized_ec3_results)

    # Create an output format with all required information
    # score_values holds [base, environmental] calculated scores
    # cwe_data is a dict that holds a list of Cvss31 objects indexed by the CWE ID
    if cwe_data[cwe_id]:
        score_values: list[list[float]] = []
        for x in cwe_data[cwe_id]:
            scores = [x.get_base_score(), x.get_environmental_score()]
            score_values.append(scores)

        ec3_results: dict = {
            "Projected CVSS:": statistics.mean([item[1] for item in score_values])
        } | (
            {
                "CWE": cwe_id,
                "Count": len(cwe_data[cwe_id]),
                "Min CVSS Base Score:": min([item[0] for item in score_values]),
                "Max CVSS Base Score:": max([item[0] for item in score_values]),
                "Average CVSS Base Score:": statistics.mean(
                    [item[0] for item in score_values]
                ),
            }
            if args.verbose
            else {}
        )

        if args.verbose:
            print(f"Vulnerability data found for requested CWE ID {cwe_id}.")
    else:
        if args.verbose:
            print(f"No vulnerability data found for requested CWE ID {cwe_id}!")
        # list entry will not exist if no CWEs found with that ID.
        ec3_results = {"Projected CVSS:": 0} | (
            {
                "CWE": cwe_id,
                "Count": 0,
                "Min CVSS Base Score:": 0,
                "Max CVSS Base Score:": 0,
                "Average CVSS Base Score:": 0,
            }
            if args.verbose
            else {}
        )

    print(ec3_results)
    return None


if __name__ == "__main__":
    run()
