import argparse
from datetime import datetime, timedelta

from nvdlib import classes as nvd_classes  # type: ignore
from requests.exceptions import SSLError

from ec3.calculator import Cvss31Calculator, data_default_file
from ec3.collector import NvdCollector, date_difference_default


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


def main() -> None:
    """
    This function orchestrates the collection and evaluation of NVD vulnerability data using ec3 classes.

    :return: None
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
    # If not present, set value to current date and time minus the ec3.collector.date_difference_default global
    # variable.
    if args.target_range_start:
        target_range_start = datetime.strptime(args.target_range_start, "%m-%d-%Y")
    else:
        target_range_start = datetime.now() - timedelta(days=date_difference_default)

    # If args.data_file was not provided, then set it to data_default_file.
    if args.data_file is None:
        args.data_file = data_default_file
        if args.verbose:
            print(
                f"No data_file provided. Set default data_file to {data_default_file}"
            )

    # Initialize the calculator and parse data.
    ec3_calculator = Cvss31Calculator(cwe_id=args.cwe, verbose=args.verbose)

    # If a temporal or environmental metric flag was not passed in, it would default to None. Instead, change this to
    # be "Not Defined" ("X") when setting modifiers.
    ec3_calculator.set_score_modifiers(
        exploit_code_maturity=args.exploit_code_maturity
        if args.exploit_code_maturity
        else "X",
        remediation_level=args.remediation_level if args.remediation_level else "X",
        report_confidence=args.report_confidence if args.report_confidence else "X",
        modified_confidentiality=args.modified_confidentiality
        if args.modified_confidentiality
        else "X",
        modified_integrity=args.modified_integrity if args.modified_integrity else "X",
        modified_availability=args.modified_availability
        if args.modified_availability
        else "X",
    )

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
            ec3_calculator.set_vulnerability_data(source_collector.pull_target_data())
            if args.verbose:
                print("Saving data from API call to data file...")
            ec3_calculator.save_data_file(data_file_str=args.data_file)
        except SSLError:
            print("Caught SSLError. Error connecting to NVD.")
            return None
        except PermissionError:
            print(
                "Caught PermissionError. Unable to write to pickle file. Continuing with data in memory."
            )
        except FileNotFoundError:
            print("Caught FileNotFoundError. Output file not found.")

    # We need to load some source of data from NVD into the raw_cve_data object. If we just performed an update, then
    # this object already exists, so only perform the following load if we haven't done the update.
    else:
        ec3_calculator.load_data_file(args.data_file)
        if args.verbose:
            print("Update not requested, loaded existing data file.")

    # Include normalized results if present.
    if args.normalize_file:
        ec3_calculator.load_normalization_data(args.normalize_file)

    # Results will be calculated for a normalized CWE ID if present. Otherwise, the default initialized CWE ID.
    # Non-normalized results can be obtained by calling ec3_calculator.get_results(args.cwe)
    ec3_results: dict = ec3_calculator.get_results()
    print(ec3_results)

    return None


if __name__ == "__main__":
    """
    This is the ec3.calculator entry point when run as a standalone application. The __main__ section logic check is in
    place for when ec3 will be executed directly as a script."
    """
    main()
