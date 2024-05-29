"""
The Environmental CWE CVSS Calculator (ec3) Server is used to calculate potential CVSS
scores for provided CWE Identifiers.

This is the command line interface entry point for ec3.server. When called, it obtains
the arguments from the command line and initializes the server.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import argparse
import logging
import logging.config
import pathlib
import typing

import uvicorn
from fastapi import FastAPI
from fastapi.concurrency import asynccontextmanager

import ec3.server.schemas as schemas
from ec3.server.broker import Cvss31CalculatorBroker
from ec3.server.config import LOGGING_CONFIG, UVICORN_LOGGING_CONFIG


def parse_args(arg_list: list[str] | None) -> argparse.Namespace:
    """Create the argument parser and parse the arguments

    Args:
        arg_list: An optional list of strings to represent input CLI arguments.

    Global arguments (calculator+collector):
        (optional) data-file: A string pointing to a pickle file that contains NVD
            JSON 2.0 data.
        (optional) normalize-file: A string pointing to a two column CSV file that
            contains the normalization data.
        (optional) verbose: A flag to enable more detailed messages in the log.

    Returns:
        An argparse.Namespace object holding all attributes provided.
    """

    parser = argparse.ArgumentParser(
        description="Environmental CWE CVSS Calculator Server"
    )
    parser.add_argument(
        "--data-file",
        "-d",
        help="Path to the CVE data file to parse and monitor.",
        action="store",
        type=pathlib.Path,
    )
    parser.add_argument(
        "--normalize-file",
        "-n",
        help="Path to the normalization CSV file to parse and monitor.",
        action="store",
        type=pathlib.Path,
    )
    parser.add_argument(
        "--verbose", "-v", help="Flag to enable verbose logging.", action="store_true"
    )

    # The argparse class' parse_args function will interpret a list of strings as the
    # provided parameters. If this list of inputs is not explicitly provided, then the
    # default behavior is to use sys.argv (the list of arguments passed to the called
    # python script) as this list of string inputs.
    return parser.parse_args(arg_list)


def instantiate_ec3_service(data_file_str: str, normalize_file_str: str) -> FastAPI:
    """Instantiates and returns the EC3 API.

    Args:
        data_file_str: A string representing the default location to load
            vulnerability data from.
        normalization_file_str: A string representing the normalization CSV file
            location to use when calculating normalized results.
    Returns:
        A FastAPI application instance configured with the EC3 service.
    """

    # Initialize Calculator Broker
    calculator_broker = Cvss31CalculatorBroker()

    # This function defines FastAPI's lifespan. All logic before `yield` runs before
    # the server is started. All logic after `yield` runs before the server is shutdown.
    @asynccontextmanager
    async def lifespan(api: FastAPI):
        # Start calculator broker
        calculator_broker.start(data_file_str, normalize_file_str)
        yield
        # Stop calculator broker
        calculator_broker.stop()

    # Initialize FastAPI instance
    app = FastAPI(
        title="Environmental CWE CVSS Calculator (ec3) Server",
        summary="The Environmental CWE CVSS Calculator (ec3) is used to calculate a "
        "potential CVSS score for a provided CWE Identifier.",
        version="1.0.0",
        license_info={
            "name": "Apache 2.0",
            "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
        },
        lifespan=lifespan,
    )

    # Configure calculator endpoint
    @typing.no_type_check
    @app.get("/score/{cwe_id}", summary="Score a CWE", response_model=schemas.CweScore)
    def score_cwe(
        cwe_id: int,
        normalize: bool = False,
        exploit_code_maturity: schemas.ExploitCodeMaturity = None,
        remediation_level: schemas.RemediationLevel = None,
        report_confidence: schemas.ReportConfidence = None,
        confidentiality_requirement: schemas.ConfidentialityRequirement = None,
        integrity_requirement: schemas.IntegrityRequirement = None,
        availability_requirement: schemas.AvailabilityRequirement = None,
        modified_attack_vector: schemas.ModifiedAttackVector = None,
        modified_attack_complexity: schemas.ModifiedAttackComplexity = None,
        modified_privileges_required: schemas.ModifiedPrivilegesRequired = None,
        modified_user_interaction: schemas.ModifiedUserInteraction = None,
        modified_scope: schemas.ModifiedScope = None,
        modified_confidentiality: schemas.ModifiedConfidentiality = None,
        modified_integrity: schemas.ModifiedIntegrity = None,
        modified_availability: schemas.ModifiedAvailability = None,
    ):
        """
        Calculates a potential CVSS score for a provided CWE Identifier. Optional
        modification metrics include:

        Temporal modification metrics:
        * Exploit Code Maturity (exploit_code_maturity)
        * Remediation Level (remediation_level)
        * Report Confidence (report_confidence)

        Environmental modification metrics:
        * Confidentiality Requirement (confidentiality_requirement)
        * Integrity Requirement (integrity_requirement)
        * Availability Requirement (availability_requirement)
        * Modified Attack Vector (modified_attack_vector)
        * Modified Attack Complexity (modified_attack_complexity)
        * Modified Privileges Required (modified_privileges_required)
        * Modified User Interaction (modified_user_interaction)
        * Modified Scope (modified_scope)
        * Modified Confidentiality (modified_confidentiality)
        * Modified Integrity (modified_integrity)
        * Modified Availability (modified_availability)
        """

        # Initialize the calculator class instance.
        ec3_calculator = calculator_broker.request_calculator()

        # If temporal or environmental flags were provided by the user, then update the
        # calculator with them and rebuild the data table. Note that if an individual
        # metric flag is not provided by the user, then it would default to None and the
        # CVSS modifier flag should be set to "X".
        ec3_calculator.set_cvss_modifiers(
            e=exploit_code_maturity or "X",
            rl=remediation_level or "X",
            rc=report_confidence or "X",
            cr=confidentiality_requirement or "X",
            ir=integrity_requirement or "X",
            ar=availability_requirement or "X",
            mav=modified_attack_vector or "X",
            mac=modified_attack_complexity or "X",
            mpr=modified_privileges_required or "X",
            mui=modified_user_interaction or "X",
            ms=modified_scope or "X",
            mc=modified_confidentiality or "X",
            mi=modified_integrity or "X",
            ma=modified_availability or "X",
        )

        # Calculate and return results
        return ec3_calculator.calculate_results(cwe_id, normalize)

    return app


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

    logging.config.dictConfig(LOGGING_CONFIG)
    logging.getLogger().setLevel(logging.DEBUG if args.verbose else logging.INFO)
    logger = logging.getLogger(__name__)

    print()  # Print blank line to stdout
    logger.info("*** Environmental CWE CVSS Server (ec3) ***")
    print()
    logger.debug(f"Input arguments: {args}")

    # Start Uvicorn ASGI web server
    uvicorn.run(
        app=instantiate_ec3_service(args.data_file, args.normalize_file),
        log_config=UVICORN_LOGGING_CONFIG,
    )


if __name__ == "__main__":  # pragma: no cover
    """The ec3.server entry point when run as a standalone application.

    The __main__ section logic check is in place for when ec3 will be executed
    directly as a script.
    """
    main()
