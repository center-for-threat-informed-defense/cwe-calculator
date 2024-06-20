"""
The CWE with Environmental CVSS Calculator is used to calculate an estimated severity
score for a provided CWE identifier. Data from the National Vulnerability Database(NVD)
is pulled via the 2.0 API and cached for re-use.

This is the command line interface entry point for ec3. When called, it obtains the
arguments from the command line and initializes the collector and calculator classes.
When completed, it prints any results found.
"""

import argparse
import logging
import pathlib
import sys
from datetime import datetime, timedelta

from nvdlib import classes as nvd_classes  # type: ignore
from requests.exceptions import SSLError

from ec3.calculator import Cvss31Calculator
from ec3.collector import NvdCollector, date_difference_default


def parse_args(arg_list: list[str] | None) -> argparse.Namespace:
    """Create the argument parser and parse the arguments

    Args:
        arg_list: An optional list of strings to represent input CLI arguments.

    Global arguments (calculator+collector):
        (optional) data-file: A string pointing to a pickle file that contains NVD
            JSON 2.0 data.
        (optional) verbose: A flag to enable more detailed messages in the log.

    ec3-cli calculate:
        (required) cwe: An integer for the desired CWE to be calculated.
        (optional) normalize-file: A string pointing to a two column CSV file that
            contains the normalization data.

        Temporal modification metrics:
            (optional) exploit-code-maturity: A string representing the exploit code
                maturity (E) metric.
            (optional) remediation-level: A string representing the remediation
                level (RL) metric.
            (optional) report-confidence: A string representing the report
                confidence (RC) metric.

        Environmental modification metrics:
            (optional) confidentiality-requirement: A string representing the
                confidentiality requirement (CR) metric.
            (optional) integrity-requirement: A string representing the integrity
                requirement (IR) metric.
            (optional) availability-requirement: A string representing the availability
                requirement (AR) metric.
            (optional) modified-attack-vector: A string representing the modified
                attack vector (MAV) metric.
            (optional) modified-attack-complexity: A string representing the modified
                attack complexity (MAC) metric.
            (optional) modified-privileges-required: A string representing the modified
                privileges required (MPR) metric.
            (optional) modified-user-interaction: A string representing the modified
                user interaction (MUI) metric.
            (optional) modified-scope: A string representing the modified scope (MS)
                metric.
            (optional) modified-confidentiality: A string representing the modified
                confidentiality (MC) metric.
            (optional) modified-integrity: A string representing the modified
                integrity (MI) metric.
            (optional) modified-availability: A string representing the modified
                availability (MA) metric.

    ec3-cli update:
        (optional) update: A flag to signal a request to pull new data from NVD.
            Utilizes optional api-key, start-date, and end-date values if available.
        (optional) start-date: A date formatted string (YYYY-MM-DD). Date must be
            2020-1-1 or after.
        (optional) end-date: A date formatted string (YYYY-MM-DD). Date must be the
            current date or earlier.


        API key options (mutually exclusive):
            (optional) key - A string value corresponding to the user's NVD API key.
                Usage improves API rate limits.
            (optional) keyfile - A string identifying a file that contains the NVD API
                key string.

    Returns:
        An argparse.Namespace object holding all attributes provided.
    """

    parser = argparse.ArgumentParser(
        description="CWE with Environmental CVSS Calculator"
    )
    globals_parser = argparse.ArgumentParser(description="Global ec3 parameters")

    subparsers = parser.add_subparsers(
        title="sub-commands",
        help="Use 'calculate' or 'update' mode of ec3-cli. "
        "Run 'ec3-cli {sub-command} --help' for more information.",
        dest="command",
        required=True,
    )

    globals_parser.add_argument(
        "--data-file",
        "-d",
        help="Path to the CVE data pickle file to parse and save",
        action="store",
        type=pathlib.Path,
    )
    globals_parser.add_argument(
        "--verbose", "-v", help="Flag to enable verbose logging.", action="store_true"
    )
    parser_calculate = subparsers.add_parser(
        name="calculate", parents=[globals_parser], add_help=False
    )
    parser_update = subparsers.add_parser(
        name="update", parents=[globals_parser], add_help=False
    )

    parser_calculate.add_argument(
        "cwe",
        help="CWE numerical identifier (e.g., 787 for CWE-787)",
        action="store",
        type=int,
    )
    parser_calculate.add_argument(
        "--normalize-file",
        "-n",
        help="Path to the normalization CSV file to parse",
        action="store",
        type=pathlib.Path,
    )
    update_group = parser_update.add_argument_group(title="Related NVD API parameters")
    update_group.add_argument(
        "--start-date",
        help="Date of earliest NVD data desired. Date must be 2020-1-1 or after. "
        "Expected format is YYYY-MM-DD.",
        action="store",
        type=str,
    )
    update_group.add_argument(
        "--end-date",
        help="Date of most recent NVD data desired. Expected format is YYYY-MM-DD.",
        action="store",
        type=str,
    )

    # Allow for a key or a keyfile but not both.
    key_group = update_group.add_mutually_exclusive_group()
    key_group.add_argument(
        "--key",
        help="NVD api-key string.",
        action="store",
        type=str,
    )
    key_group.add_argument(
        "--keyfile",
        help="Filename containing NVD api-key string",
        action="store",
        type=pathlib.Path,
    )

    # Allow for individual temporal CVSS metrics to be passed in.
    temporal_group = parser_calculate.add_argument_group(title="Temporal Metrics")
    temporal_group.add_argument(
        "--exploit-code-maturity",
        "-e",
        help="Temporal exploit code maturity (E) metric.",
        type=str,
        choices=["X", "H", "F", "P", "U"],
    )
    temporal_group.add_argument(
        "--remediation-level",
        "-rl",
        help="Temporal remediation level (RL) metric.",
        type=str,
        choices=["X", "U", "W", "T", "O"],
    )
    temporal_group.add_argument(
        "--report-confidence",
        "-rc",
        help="Temporal report confidence (RC) metric.",
        type=str,
        choices=["X", "C", "R", "U"],
    )

    # Allow for individual environmental modified impact CVSS metrics to be passed in.
    environmental_group = parser_calculate.add_argument_group(
        title="Environmental Metrics"
    )
    environmental_group.add_argument(
        "--confidentiality-requirement",
        "-cr",
        help="Environmental confidentiality requirement (CR) metric.",
        type=str,
        choices=["X", "H", "M", "L"],
    )
    environmental_group.add_argument(
        "--integrity-requirement",
        "-ir",
        help="Environmental integrity requirement (IR) metric.",
        type=str,
        choices=["X", "H", "M", "L"],
    )
    environmental_group.add_argument(
        "--availability-requirement",
        "-ar",
        help="Environmental availability requirement (AR) metric.",
        type=str,
        choices=["X", "H", "M", "L"],
    )
    environmental_group.add_argument(
        "--modified-attack-vector",
        "-mav",
        help="Environmental modified attack complexity (MAC) metric.",
        type=str,
        choices=["X", "N", "A", "L", "P"],
    )
    environmental_group.add_argument(
        "--modified-attack-complexity",
        "-mac",
        help="Environmental modified attack complexity (MAC) metric.",
        type=str,
        choices=["X", "L", "H"],
    )
    environmental_group.add_argument(
        "--modified-privileges-required",
        "-mpr",
        help="Environmental modified privileges required (MPR) metric.",
        type=str,
        choices=["X", "N", "L", "H"],
    )
    environmental_group.add_argument(
        "--modified-user-interaction",
        "-mui",
        help="Environmental modified user interaction (MUI) metric.",
        type=str,
        choices=["X", "N", "R"],
    )
    environmental_group.add_argument(
        "--modified-scope",
        "-ms",
        help="Environmental modified scope (MS) metric.",
        type=str,
        choices=["X", "U", "C"],
    )
    environmental_group.add_argument(
        "--modified-confidentiality",
        "-mc",
        help="Environmental modified confidentiality (MC) metric.",
        type=str,
        choices=["X", "N", "L", "H"],
    )
    environmental_group.add_argument(
        "--modified-integrity",
        "-mi",
        help="Environmental modified integrity (MI) metric.",
        type=str,
        choices=["X", "N", "L", "H"],
    )
    environmental_group.add_argument(
        "--modified-availability",
        "-ma",
        help="Environmental modified availability (MA) metric.",
        type=str,
        choices=["X", "N", "L", "H"],
    )

    # The argparse class' parse_args function will interpret a list of strings as the
    # provided parameters. If this list of inputs is not explicitly provided, then the
    # default behavior is to use sys.argv (the list of arguments passed to the called
    # python script) as this list of string inputs.
    return parser.parse_args(arg_list)


def _setup_logging(verbose: bool = False) -> None:
    """Configure logging.
    Args:
        verbose: Boolean value representing whether to use the more verbose
            logging.DEBUG over the default logging.INFO
    Returns:
        None
    """

    # Define log file and console logging parameters
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    log_date_format = "%Y-%m-%d %H:%M:%S"
    log_filename = "ec3.log"
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


def main(arg_list: list[str] | None = None) -> None:
    """Orchestrate the collection and evaluation of NVD vulnerability data using
        ec3 classes.

    Args:
        arg_list: Optional input argument list to pass to parse_args.

    Returns:
        None
    """

    # Parse CLI arguments
    args = parse_args(arg_list)

    _setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    print()  # Print blank line to stdout
    logger.info("*** CWE with Environmental CVSS Calculator ***")
    print()
    logger.debug(f"Input arguments: {args}")

    # Initialize variable to hold vulnerability data in memory. If an update is
    # requested and fails to save the data, load it directly into the Cvss31Calculator
    # class from memory.
    api_data: list[nvd_classes.CVE] = []
    load_data_from_memory: bool = False

    # If sub-command called was "update", then pull the most recently modified data
    # for the date range provided. Save the pulled source data to the specified or
    # default [data_file] location.
    if args.command in "update":
        # Attempt to set the api_key value from the key argument directly, or load from
        # a specified file. The api_key is used to increase the rate limits of the
        # NVD API during collection. Setting this value without the update flag would
        # have no effect.
        api_key: str = args.key
        if args.keyfile:
            try:
                with open(args.keyfile) as f:
                    api_key = f.read().rstrip("\n")
            except PermissionError:
                logger.error("Caught PermissionError. Unable to open keyfile. Exiting.")
                return None

        # Parse values for start_date and end_date. These values set the bounds for the
        # NVD API data acquisition by passing them to their respective pubStartDate and
        # pubEndDate API parameters. The collector automatically handles ranges larger
        # than the ec3.collector.max_date_range global variable. Expected date format
        # is 'YYYY-MM-DD'. If the start_date is not provided then set it to the current
        # date minus the [ec3.collector.date_difference_default] global variable. If the
        # end_date is not provided then set it to the current date.
        if args.start_date:
            start_date = datetime.strptime(args.start_date, "%Y-%m-%d")
        else:
            start_date = datetime.now() - timedelta(days=date_difference_default)
        if args.end_date:
            end_date = datetime.strptime(args.end_date, "%Y-%m-%d")
        else:
            end_date = datetime.now()

        logger.debug("Updating from NVD API...")
        source_collector = NvdCollector(
            api_key=api_key,
            start_date=start_date,
            end_date=end_date,
        )
        try:
            api_data = source_collector.pull_target_data()
            logger.debug("Saving data from API call to data file...")
            source_collector.save_data_to_file(api_data, data_file_str=args.data_file)
        except SSLError:
            logger.error("Caught SSLError. Error connecting to NVD. Exiting.")
            return None
        except PermissionError:
            logger.warning(
                "Caught PermissionError. "
                "Unable to save NVD data to a file. "
                "Continuing with data temporarily stored in memory."
            )
            load_data_from_memory = True
        except FileNotFoundError:
            logger.warning(
                "Caught FileNotFoundError. Desired data file path is not writeable. "
                "Unable to save data. "
                "Continuing with data temporarily stored in memory."
            )
            load_data_from_memory = True
        except Exception:
            logger.error(
                "Caught unknown error while collecting and saving NVD data. Exiting."
            )
            return None

    # If sub-command called was "calculate", then initialize the calculator class
    # instance. This calculator is used to load vulnerability data, modify temporal and
    # environmental metrics, and obtain results for desired CWE IDs.
    if args.command in "calculate":
        ec3_calculator = Cvss31Calculator(
            data_file_str=args.data_file,
            normalization_file_str=args.normalize_file,
        )

        # If temporal or environmental flags were provided by the user, then update the
        # calculator with them and rebuild the data table. Note that if an individual
        # metric flag is not provided by the user, then it would default to None and the
        # CVSS modifier flag should be set to "X".
        ec3_calculator.set_cvss_modifiers(
            e=args.exploit_code_maturity if args.exploit_code_maturity else "X",
            rl=args.remediation_level if args.remediation_level else "X",
            rc=args.report_confidence if args.report_confidence else "X",
            cr=(
                args.confidentiality_requirement
                if args.confidentiality_requirement
                else "X"
            ),
            ir=args.integrity_requirement if args.integrity_requirement else "X",
            ar=args.availability_requirement if args.availability_requirement else "X",
            mav=args.modified_attack_vector if args.modified_attack_vector else "X",
            mac=(
                args.modified_attack_complexity
                if args.modified_attack_complexity
                else "X"
            ),
            mpr=(
                args.modified_privileges_required
                if args.modified_privileges_required
                else "X"
            ),
            mui=(
                args.modified_user_interaction
                if args.modified_user_interaction
                else "X"
            ),
            ms=args.modified_scope if args.modified_scope else "X",
            mc=args.modified_confidentiality if args.modified_confidentiality else "X",
            mi=args.modified_integrity if args.modified_integrity else "X",
            ma=args.modified_availability if args.modified_availability else "X",
        )

        # If there was an error saving the data file during update then there is newer
        # data still stored in memory. Load this data into the calculator.
        if load_data_from_memory:
            ec3_calculator.set_vulnerability_data(new_data=api_data)

        # If a normalization file was provided, assume CWE ID normalization is desired.
        normalize_ids: bool = False
        if args.normalize_file:
            normalize_ids = True

        # Results will be calculated for a normalized CWE ID if present. Otherwise, the
        # default initialized CWE ID. Non-normalized results can be obtained by
        # calling ec3_calculator.calculate_results(args.cwe)
        # or ec3_calculator.calculate_results(args.cwe, False)
        ec3_results: dict = ec3_calculator.calculate_results(
            cwe_id=args.cwe, normalize=normalize_ids
        )
        ec3_calculator.output_results(ec3_results, 4)

    return None


if __name__ == "__main__":  # pragma: no cover
    """The ec3.calculator entry point when run as a standalone application.

    The __main__ section logic check is in place for when ec3 will be executed
    directly as a script.
    """

    main()
