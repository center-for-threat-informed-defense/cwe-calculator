"""
The Environmental CWE CVSS Calculator (ec3) is used to calculate a potential CVSS score for a provided CWE
Identifier. Data from the National Vulnerability Database(NVD) is pulled via the 2.0 API and stored for later re-use.

This is the command line interface entry point for ec3. When called, it obtains the arguments from the command line and
initializes the collector and calculator classes. When completed it prints any results found.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import argparse
import pathlib
from datetime import datetime, timedelta

from nvdlib import classes as nvd_classes  # type: ignore
from requests.exceptions import SSLError

from ec3.calculator import Cvss31Calculator
from ec3.collector import NvdCollector, date_difference_default


def parse_args(arg_list: list[str] | None) -> argparse.Namespace:
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
    (optional) confidentiality_requirement - A string representing the confidentiality requirement (CR) metric.
    (optional) integrity_requirement - A string representing the integrity requirement (IR) metric.
    (optional) availability_requirement - A string representing the availability requirement (AR) metric.
    (optional) modified_attack_vector - A string representing the modified attack vector (MAV) metric.
    (optional) modified_attack_complexity - A string representing the modified attack complexity (MAC) metric.
    (optional) modified_privileges_required - A string representing the modified privileges required (MPR) metric.
    (optional) modified_user_interaction - A string representing the modified user interaction (MUI) metric.
    (optional) modified_scope - A string representing the modified scope (MS) metric.
    (optional) modified_confidentiality - A string representing the modified confidentiality (MC) metric.
    (optional) modified_integrity - A string representing the modified integrity (MI) metric.
    (optional) modified_availability - A string representing the modified availability (MA) metric.

    :param arg_list: Optional input argument list.
    :return argparse.Namespace object holding all attributes provided.
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
        type=pathlib.Path,
    )
    parser.add_argument(
        "--normalize_file",
        "-n",
        help="Path to the normalization CSV file to parse",
        action="store",
        type=pathlib.Path,
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
        type=pathlib.Path,
    )

    # Allow for individual temporal CVSS metrics to be passed in.
    temporal_group = parser.add_argument_group(title="Temporal Metrics")
    temporal_group.add_argument(
        "--exploit_code_maturity",
        "-e",
        help="Temporal exploit code maturity (E) metric. (Expected values: X, H, F, P, U)",
        type=str,
        choices=["X", "H", "F", "P", "U"],
    )
    temporal_group.add_argument(
        "--remediation_level",
        "-rl",
        help="Temporal remediation level (RL) metric. (Expected values: X, U, W, T, O)",
        type=str,
        choices=["X", "U", "W", "T", "O"],
    )
    temporal_group.add_argument(
        "--report_confidence",
        "-rc",
        help="Temporal report confidence (RC) metric. (Expected values: X, C, R, U)",
        type=str,
        choices=["X", "C", "R", "U"],
    )

    # Allow for individual environmental modified impact CVSS metrics to be passed in.
    environmental_group = parser.add_argument_group(title="Environmental Metrics")
    environmental_group.add_argument(
        "--confidentiality_requirement",
        "-cr",
        help="Environmental confidentiality requirement (CR) metric. (Expected values:  X, H, M, L)",
        type=str,
        choices=["X", "H", "M", "L"],
    )
    environmental_group.add_argument(
        "--integrity_requirement",
        "-ir",
        help="Environmental integrity requirement (IR) metric. (Expected values:  X, H, M, L)",
        type=str,
        choices=["X", "H", "M", "L"],
    )
    environmental_group.add_argument(
        "--availability_requirement",
        "-ar",
        help="Environmental availability requirement (AR) metric. (Expected values:  X, H, M, L)",
        type=str,
        choices=["X", "H", "M", "L"],
    )
    environmental_group.add_argument(
        "--modified_attack_vector",
        "-mav",
        help="Environmental modified attack complexity (MAC) metric. (Expected values:  X, N, A, L, P)",
        type=str,
        choices=["X", "N", "A", "L", "P"],
    )
    environmental_group.add_argument(
        "--modified_attack_complexity",
        "-mac",
        help="Environmental modified attack complexity (MAC) metric. (Expected values:  X, L, H)",
        type=str,
        choices=["X", "L", "H"],
    )
    environmental_group.add_argument(
        "--modified_privileges_required",
        "-mpr",
        help="Environmental modified privileges required (MPR) metric. (Expected values:  X, N, L, H)",
        type=str,
        choices=["X", "N", "L", "H"],
    )
    environmental_group.add_argument(
        "--modified_user_interaction",
        "-mui",
        help="Environmental modified user interaction (MUI) metric. (Expected values:  X, N, R)",
        type=str,
        choices=["X", "N", "R"],
    )
    environmental_group.add_argument(
        "--modified_scope",
        "-ms",
        help="Environmental modified scope (MS) metric. (Expected values:  X, U, C)",
        type=str,
        choices=["X", "U", "C"],
    )
    environmental_group.add_argument(
        "--modified_confidentiality",
        "-mc",
        help="Environmental modified confidentiality (MC) metric. (Expected values:  X, N, L, H)",
        type=str,
        choices=["X", "N", "L", "H"],
    )
    environmental_group.add_argument(
        "--modified_integrity",
        "-mi",
        help="Environmental modified integrity (MI) metric. (Expected values: X, N, L, H)",
        type=str,
        choices=["X", "N", "L", "H"],
    )
    environmental_group.add_argument(
        "--modified_availability",
        "-ma",
        help="Environmental modified availability (MA) metric. (Expected values: X, N, L, H)",
        type=str,
        choices=["X", "N", "L", "H"],
    )

    # The argparse class' parse_args function will interpret a list of strings as the provided parameters.
    # If this list of inputs is not explicitly provided, then the default behavior is to use sys.argv (the list
    # of arguments passed to the called python script) as this list of string inputs.
    return parser.parse_args(arg_list)


def main(arg_list: list[str] | None = None) -> None:
    """
    This function orchestrates the collection and evaluation of NVD vulnerability data using ec3 classes.

    :param arg_list: Optional input argument list to pass to parse_args.
    :return: None
    """

    # Parse CLI arguments
    args = parse_args(arg_list)
    if args.verbose:
        print("*** Environmental CWE CVSS Calculator (ec3) ***")
        print()  # print blank line
        print(f"Input arguments: {args}")
        print()  # print blank line

    # Attempt to set the api_key value from the key argument directly, or load from a specified file. The api_key is
    # used to increase the rate limits of the NVD API during collection. Setting this value without the update flag
    # would have no effect.
    api_key = args.key
    if args.keyfile:
        try:
            with open(args.keyfile) as f:
                api_key = f.read().rstrip("\n")
        except PermissionError:
            print("Caught PermissionError. Unable to open keyfile. Exiting.")
            return None

    # Parse values for target_range_start and target_range_end. These values set the bounds for the NVD API data
    # acquisition by passing them to their respective lastModStartDate and lastModEndDate API parameters. The collector
    # automatically handles ranges larger than the ec3.collector.max_date_range global variable. Expected date
    # format is MM - DD - YYYY.

    # If the target_range_start is not provided then set it to the current date minus the
    # [ec3.collector.date_difference_default] global variable. If the target_range_end is not provided then set it to
    # the current date.

    if args.target_range_start:
        target_range_start = datetime.strptime(args.target_range_start, "%m-%d-%Y")
    else:
        target_range_start = datetime.now() - timedelta(days=date_difference_default)
    if args.target_range_end:
        target_range_end = datetime.strptime(args.target_range_end, "%m-%d-%Y")
    else:
        target_range_end = datetime.now()

    # If an update is requested and fails to save the data, we can load it from memory later
    load_data_from_memory: bool = False
    api_data: list[nvd_classes.CVE] = []

    # If the args.update flag was passed in, then pull the most recently modified data for the date range provided.
    # Save the pulled source data to the specified or default [data_file] location.
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
            api_data = source_collector.pull_target_data()
            if args.verbose:
                print("Saving data from API call to data file...")
            source_collector.save_data_to_file(api_data, data_file_str=args.data_file)
        except SSLError:
            print("Caught SSLError. Error connecting to NVD. Exiting.")
            return None
        except PermissionError:
            print(
                "Caught PermissionError. "
                "Unable to save NVD data to a file. Continuing with data temporarily stored in memory."
            )
            load_data_from_memory = True
        except FileNotFoundError:
            print(
                "Caught FileNotFoundError. Desired data file path is not writeable. Unable to save data. "
                "Continuing with data temporarily stored in memory."
            )
            load_data_from_memory = True
        except Exception:
            print("Caught unknown error while collecting and saving NVD data. Exiting.")
            return None

    # Initialize the calculator class instance. This calculator is used to load/save vulnerability data, modify
    # temporal and environmental metrics, and obtain results for desired CWE IDs.
    ec3_calculator = Cvss31Calculator(
        data_file_str=args.data_file,
        normalization_file_str=args.normalize_file,
        verbose=args.verbose,
    )

    # If a temporal or environmental metric flag was not passed in through the CLI args, it would default to None.
    # For each metric modifier: either use the passed in value, or "X" if not set.
    ec3_calculator.set_cvss_modifiers(
        e=args.exploit_code_maturity if args.exploit_code_maturity else "X",
        rl=args.remediation_level if args.remediation_level else "X",
        rc=args.report_confidence if args.report_confidence else "X",
        cr=args.confidentiality_requirement
        if args.confidentiality_requirement
        else "X",
        ir=args.integrity_requirement if args.integrity_requirement else "X",
        ar=args.availability_requirement if args.availability_requirement else "X",
        mav=args.modified_attack_vector if args.modified_attack_vector else "X",
        mac=args.modified_attack_complexity if args.modified_attack_complexity else "X",
        mpr=args.modified_privileges_required
        if args.modified_privileges_required
        else "X",
        mui=args.modified_user_interaction if args.modified_user_interaction else "X",
        ms=args.modified_scope if args.modified_scope else "X",
        mc=args.modified_confidentiality if args.modified_confidentiality else "X",
        mi=args.modified_integrity if args.modified_integrity else "X",
        ma=args.modified_availability if args.modified_availability else "X",
    )

    if load_data_from_memory:
        ec3_calculator.set_vulnerability_data(new_data=api_data)

    # If a normalization file was provided, assume CWE ID normalization is desired.
    normalize_ids: bool = False
    if args.normalize_file:
        normalize_ids = True

    # Results will be calculated for a normalized CWE ID if present. Otherwise, the default initialized CWE ID.
    # Non-normalized results can be obtained by calling ec3_calculator.calculate_results(args.cwe)
    # or ec3_calculator.calculate_results(args.cwe, False)
    ec3_results: dict = ec3_calculator.calculate_results(
        cwe_id=args.cwe, normalize=normalize_ids
    )
    ec3_calculator.output_results(ec3_results, 4)

    return None


if __name__ == "__main__":  # pragma: no cover
    """
    This is the ec3.calculator entry point when run as a standalone application. The __main__ section logic check is in
    place for when ec3 will be executed directly as a script."
    """

    main()
