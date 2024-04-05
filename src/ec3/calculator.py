"""Utility class to parse, modify, and analyze NVD vulnerability data.

NVD data is parsed to extract CWE/CVSS31 fields for later statistical analysis.
Temporal and environmental CVSS metrics may be specified to influence calculations.
Results may be obtained for any number of CWE identifiers using the same source data.

Typical usage example:
    ec3_calc = ec3.calculator.Cvss31Calculator()
    example_results = ec3_calc.calculate_results(125)
    ec3_calc.output_results(example_results)

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import collections
import csv
import io
import logging
import pickle
import statistics

from nvdlib import classes as nvd_classes  # type: ignore

from ec3 import data_default_file
from ec3.cvss import Cvss31

logger = logging.getLogger(__name__)


class Cvss31Calculator:
    """Calculate projected CVSS v3.1 scores based on loaded vulnerability data, for any
    given CWE ID."""

    def __init__(
        self,
        data_file_str: str = data_default_file,
        normalization_file_str: str = "",
    ) -> None:
        """Initialize a Cvss31Calculator class instance using the provided parameters.

        Args:
            data_file_str: A string representing the default location to load
                vulnerability data from.
            normalization_file_str: A string representing the normalization CSV file
                location to use when calculating normalized results.

        Returns:
            A Cvss31Calculator instance with the default/specified data file already
                loaded into memory. All CVSS metric modifiers are initialized to
                "Unknown"/"X". The internal CWE table has been constructed from the
                call to load_data_file.
        """

        # Hold a list of nvdlib.classes.CVE objects loaded from a collector or file.
        self.raw_cve_data: list[nvd_classes.CVE] = []

        # Save the path to the normalization file to use when calculate_results is
        # called with the 'normalize' flag.
        self.normalization_file_str = normalization_file_str

        # Dictionary that will map CWE ID to list of CVSS vectors
        self.cwe_data: dict[int, list[list]] = collections.defaultdict(list)

        # Set optional temporal modifiers
        self.exploit_code_maturity: str = "X"
        self.remediation_level: str = "X"
        self.report_confidence: str = "X"

        # Set optional environmental modifiers
        self.confidentiality_requirement: str = "X"
        self.integrity_requirement: str = "X"
        self.availability_requirement: str = "X"
        self.modified_attack_vector: str = "X"
        self.modified_attack_complexity: str = "X"
        self.modified_privileges_required: str = "X"
        self.modified_user_interaction: str = "X"
        self.modified_scope: str = "X"
        self.modified_confidentiality: str = "X"
        self.modified_integrity: str = "X"
        self.modified_availability: str = "X"

        # Load vulnerability data from either the provided or default data file.
        if data_file_str:
            self.load_data_file(data_file_str)
        else:
            self.load_data_file(data_default_file)

        logger.debug("Initialized Cvss31Calculator.")

    @staticmethod
    def __cwe_id_valid(cwe_id: int | str | None) -> bool:
        """Provide a quick sanity check for the provided CWE ID value.

        A CWE ID should be a positive integer greater than 0.
        Note: not all IDs are used by CWE.

        Args:
            cwe_id: CWE identifier to evaluate as a potentially valid ID. Value may be
                an integer, string, or None.

        Returns:
            True if cwe_id is representable as an integer and is greater than 0,
                False otherwise.
        """

        try:
            return cwe_id is not None and int(cwe_id) > 0
        except ValueError:
            logger.warning("Caught ValueError. CWE ID provided was not a usable ID.")

        return False

    @staticmethod
    def __get_cwe_from_cve(cve: nvd_classes.CVE) -> list[int]:
        """Get all valid CWEs associated with the single nvdlib CVE object

        Args:
            cve: A single CVE record from the list of CVEs loaded from the NVD data

        Returns:
            A list containing the numerical ids of valid CWEs parsed from this CVE.
        """

        cwes: list[int] = []

        # The CVE data must not be Rejected, and contain a CWE identifier.
        if cve.vulnStatus == "Rejected" or not hasattr(cve, "cwe"):
            return cwes

        # CVEs might have multiple CWE mappings and each mapping might contain space
        # delimited CWEs.
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

            # Call "strip" in case someone put a space before or after when doing a
            # CWE mapping. Split on the '-' in 'CWE-###' and add the number to the list.
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
                logger.warning(
                    "Encountered error while parsing CWE ID from vulnerability data. "
                    "Skipping this entry."
                )
                continue

        return cwes

    @staticmethod
    def __restricted_load(file_str: str | None) -> list[nvd_classes.CVE]:
        """Restrict the loaded class type.

        Attempts to load a list of nvd_classes.CVE. This should prevent unsafe modules
        from being arbitrarily loaded.

        Args:
            file_str: A string representing the data file path to load.

        Returns:
            A list of nvdlib.classes.CVE objects if the pickle file is available and
                accessible. Returns an empty list otherwise.
        """

        return (
            RestrictedUnpickler(io.FileIO(file_str)).load()
            if file_str is not None
            else []
        )

    def load_data_file(self, data_file_str: str | None = None) -> None:
        """Loads a previously saved pickle file containing NVD vulnerability data.

        Loads vulnerability data into a list containing nvdlib.classes.CVE objects. If
        unable to load data from the specified or default data file, assigns the
        internal list to be empty. Calling this function will potentially replace
        previously loaded data in memory.

        Args:
            data_file_str: String containing the path to a pickle file containing
                nvdlib.classes.CVE data.

        Returns:
            None
        """

        logger.debug("Loading vulnerability information from a saved data file.")

        if data_file_str is None:
            logger.debug(
                f"No data_file provided, "
                f"setting to default file: {data_default_file}"
            )
            data_file_str = data_default_file

        try:
            loaded_data: list[nvd_classes.CVE] = self.__restricted_load(
                file_str=data_file_str
            )
            self.set_vulnerability_data(new_data=loaded_data)
        except FileNotFoundError:
            logger.warning("Caught FileNotFoundError. Input file not found.")
        except PermissionError:
            logger.warning("Caught PermissionError. Unable to read data file.")
        except pickle.UnpicklingError:
            logger.warning(
                "Caught UnpicklingError. Input file not in correct pickle format."
            )

        return None

    def normalize_cwe(self, cwe_id: int = 0) -> int | None:
        """Load the normalization data CSV file and return the first valid corresponding
            normalization CWE identifier.

        The CSV file should only have one suggestion per CWE ID in the left column.
        The file may map an identifier to itself or "Other". Both of these cases are
        expected to set the normalization CWE ID to None. If unable to load data from
        a file, file permissions are encountered, or no lookup value is found, set the
        normalization CWE ID to None.

        Args:
            cwe_id: A CWE identifier used for the lookup in the left column of the
                normalization CSV file.

        Returns:
            A CWE identifier of the normalized value to use in place of cwe_id, or None
                if no new ID was found.
        """

        try:
            with open(self.normalization_file_str, mode="r") as normalization_fh:
                normalization_file = csv.reader(normalization_fh)

                # Check each line, return the first valid match. Otherwise, return None.
                for lines in normalization_file:
                    if lines[0] == cwe_id.__str__():
                        # Cast the normalized value column as an integer and return
                        try:
                            if lines[1] != "Other" and lines[1] != cwe_id.__str__():
                                normalized_id = int(lines[1])

                                logger.debug(
                                    f"CWE ID {cwe_id} matched normalization ID "
                                    f"{normalized_id}."
                                )

                                return normalized_id
                        except ValueError:
                            logger.warning(
                                "Caught ValueError. "
                                "CWE ID found, but normalized value is not a usable ID."
                            )

                # The whole file was searched without error. Notify the user that no
                # match was found.
                logger.debug(f"CWE ID {cwe_id} does not normalize to a new ID.")

        except FileNotFoundError:
            logger.warning(
                "Caught FileNotFoundError. Input normalization file not found."
            )
        except PermissionError:
            logger.warning("Caught PermissionError. Unable to open normalization file.")

        # If still here, then no value was found or an error was encountered.
        # Return nothing found
        return None

    def set_vulnerability_data(self, new_data: list[nvd_classes.CVE]) -> None:
        """Validate then assign a new source of vulnerability data from memory.

        Evaluate whether the input data is a list of nvdlib.classes.CVE objects. If so,
        load this new_data into the class instance. Otherwise, raise TypeError.
        Additionally, update the internal CWE table based on new data.

        Args:
            new_data: A list of new vulnerability records to load into this class
                instance.

        Returns:
            None

        Raises:
            TypeError: The new_data provided was not a list of CVE objects.
        """

        if not isinstance(new_data, list) or not any(
            isinstance(record, nvd_classes.CVE) for record in new_data
        ):
            raise TypeError(
                "Vulnerability data is not in the correct format. "
                "Expected list[nvdlib.classes.CVE]"
            )

        self.raw_cve_data = new_data

        # Update internal cwe table using new vulnerability data
        self.build_cwe_table()

        return None

    def set_cvss_modifiers(
        self,
        e: str = "X",
        rl: str = "X",
        rc: str = "X",
        cr: str = "X",
        ir: str = "X",
        ar: str = "X",
        mav: str = "X",
        mac: str = "X",
        mpr: str = "X",
        mui: str = "X",
        ms: str = "X",
        mc: str = "X",
        mi: str = "X",
        ma: str = "X",
    ) -> None:
        """Set the individual temporal and environmental re-scoring metrics.

        Validation occurs during the actual modification of the Cvss31 object.
        Additionally, update the internal CWE table based on new scoring modifiers.

        Args:
            e: Value of temporal Exploit Code Maturity (E) modification
            rl: Value of temporal Remediation Level (RL) modification
            rc: Value of temporal Report Confidence (RC) modification
            cr: Value of environmental Confidentiality Requirement (CR) modification
            ir: Value of environmental Integrity Requirement (IR) modification
            ar: Value of environmental Availability Requirement (AR) modification
            mav: Value of environmental Modified Attack Vector (MAV) modification
            mac: Value of environmental Modified Attack Complexity (MAC) modification
            mpr: Value of environmental Modified Privileges Required (MPR) modification
            mui: Value of environmental Modified User Interaction (MUI) modification
            ms: Value of environmental Modified Scope (MS) modification
            mc: Value of environmental Modified Confidentiality (MC) modification
            mi: Value of environmental Modified Integrity (MI) modification
            ma: Value of environmental Modified Availability (MA) modification

        Returns:
            None
        """

        self.exploit_code_maturity = e
        self.remediation_level = rl
        self.report_confidence = rc

        self.confidentiality_requirement = cr
        self.integrity_requirement = ir
        self.availability_requirement = ar
        self.modified_attack_vector = mav
        self.modified_attack_complexity = mac
        self.modified_privileges_required = mpr
        self.modified_user_interaction = mui
        self.modified_scope = ms
        self.modified_confidentiality = mc
        self.modified_integrity = mi
        self.modified_availability = ma

        # Update internal cwe table using new modifiers
        self.build_cwe_table()

        return None

    def build_cwe_table(self) -> None:
        """Parse through the loaded vulnerability data, and create a lookup dict for
            each CWE identifier encountered.

        This data is stored within the class for later use during final calculations.
        Saves the associated CVE/CVSS data (applying temporal/environmental
        modifications) within their respective CWE lookup bin.

        Returns:
            None

        Raises:
            ValueError: An invalid flag was attempted to be used.
        """

        # Reinitialize the cwe_data dict. Populate the CWE dictionary and cve count
        self.cwe_data = collections.defaultdict(list)
        cve_count = 0
        if self.raw_cve_data:
            for cve in self.raw_cve_data:
                cve_count += 1
                try:
                    if hasattr(cve, "v31vector"):
                        base_cvss = Cvss31.from_cve(cve=cve)

                        # Set optional temporal modifiers
                        if self.exploit_code_maturity != "X":
                            base_cvss.set_e(self.exploit_code_maturity)
                        if self.remediation_level != "X":
                            base_cvss.set_rl(self.remediation_level)
                        if self.report_confidence != "X":
                            base_cvss.set_rc(self.report_confidence)

                        # Set optional environmental modifiers
                        if self.confidentiality_requirement != "X":
                            base_cvss.set_cr(self.confidentiality_requirement)
                        if self.integrity_requirement != "X":
                            base_cvss.set_ir(self.integrity_requirement)
                        if self.availability_requirement != "X":
                            base_cvss.set_ar(self.availability_requirement)
                        if self.modified_attack_vector != "X":
                            base_cvss.set_mav(self.modified_attack_vector)
                        if self.modified_attack_complexity != "X":
                            base_cvss.set_mac(self.modified_attack_complexity)
                        if self.modified_privileges_required != "X":
                            base_cvss.set_mpr(self.modified_privileges_required)
                        if self.modified_user_interaction != "X":
                            base_cvss.set_mui(self.modified_user_interaction)
                        if self.modified_scope != "X":
                            base_cvss.set_ms(self.modified_scope)
                        if self.modified_confidentiality != "X":
                            base_cvss.set_mc(self.modified_confidentiality)
                        if self.modified_integrity != "X":
                            base_cvss.set_mi(self.modified_integrity)
                        if self.modified_availability != "X":
                            base_cvss.set_ma(self.modified_availability)

                        cwes_for_cve = self.__get_cwe_from_cve(cve)
                        for cwe in cwes_for_cve:
                            self.cwe_data[cwe].append([cve.id, base_cvss])
                except ValueError:
                    logger.error(
                        "Caught ValueError parsing CWE data from vulnerabilities."
                    )
                    raise

        # Display the number of CVE entries in the raw_cve_data
        logger.debug(f"Processed {cve_count} vulnerabilities.")

        return None

    def calculate_results(self, cwe_id: int = 0, normalize: bool = False) -> dict:
        """Conduct statistical analysis against source data.

        Can be called multiple times against different IDs and will use the same data
        until new data is loaded from a file or the ec3.collector.

        If normalization was requested, then we will attempt to find a replacement
        recommended CWE ID to use from the class' set normalization file string.
        Normalization is attempting to use a CWE ID higher in the relationship tree
        that might be more commonly used during mapping. Note that not all CWE IDs have
        a recommended normalization ID to use as a replacement.

        Args:
            cwe_id: A required integer value for the CWE ID to collect data on.
                normalize: A boolean value to determine whether a normalized CWE ID is
                used in lieu of the provided ID.
            normalize: A boolean flag to tell the calculator to search the set
                normalization file for a potential replacement CWE ID.

        Returns:
            The results dict includes the projected CVSS score (accounting for temporal
                and environmental modifications), the CWE ID used, min/max/mean base
                score CVSS values, count (of vulnerabilities mapped to the desired
                CWE ID), and the list of related CVE records.
        """

        # Attempt to load the normalization CSV file, and update the cwe_id param to
        # the normalized value if not None. The input cwe_id value should be a valid
        # CWE identifier.
        if normalize and self.__cwe_id_valid(cwe_id):
            normalization_result = self.normalize_cwe(cwe_id)
            if normalization_result:
                cwe_id = normalization_result

        if self.__cwe_id_valid(cwe_id):
            score_values: list[list[float]] = []
            cve_ids: list[str] = []
            if self.cwe_data[cwe_id]:
                for [cve_id, cvss_data] in self.cwe_data[cwe_id]:
                    scores = [
                        cvss_data.get_base_score(),
                        cvss_data.get_environmental_score(),
                    ]
                    score_values.append(scores)
                    cve_ids.append(cve_id)

                results_stdev: float = 0.0
                if len(score_values) > 1:
                    results_stdev = statistics.stdev([item[0] for item in score_values])

                # Create an output format with all required information
                # score_values holds [base, environmental] calculated scores
                # self.cwe_data is a dict that holds a list of [cve_id, Cvss31] list
                # entries indexed by the CWE ID
                calculator_results: dict = {
                    "Projected CVSS": statistics.mean(
                        [item[1] for item in score_values]
                    ),
                    "CWE": cwe_id,
                    "Count": len(self.cwe_data[cwe_id]),
                    "Min CVSS Base Score": min([item[0] for item in score_values]),
                    "Max CVSS Base Score": max([item[0] for item in score_values]),
                    "Average CVSS Base Score": statistics.mean(
                        [item[0] for item in score_values]
                    ),
                    "Standard Deviation CVSS Base Score": results_stdev,
                    "CVE Records": cve_ids,
                }

                return calculator_results

            else:
                logger.debug(f"No vulnerability data found for CWE ID {cwe_id}.")

        else:
            logger.warning("CWE ID provided was not a usable ID.")

        # If the CWE ID was invalid, or if no vulnerability data maps to the requested
        # or normalized CWE ID, then construct an empty results dictionary.
        empty_results: dict = {
            "Projected CVSS": 0.0,
            "CWE": cwe_id,
            "Count": 0,
            "Min CVSS Base Score": 0.0,
            "Max CVSS Base Score": 0.0,
            "Average CVSS Base Score": 0.0,
            "Standard Deviation CVSS Base Score": 0.0,
            "CVE Records": [],
        }

        return empty_results

    def output_results(self, ec3_results: dict = {}, cve_cols: int = 4) -> None:
        """Print a previously returned results dictionary.

        Validates the expected type for each field before rendering.

        Args:
            ec3_results: A required dictionary of values returned from
                Cvss31Calculator.calculate_results().
            cve_cols: An optional integer to set how many CVE records appear per line
                during output.

        Returns:
            None
        """

        if self.__results_valid(ec3_results) and self.__cwe_id_valid(
            ec3_results["CWE"]
        ):
            # If negative or bad value provided, revert the number of columns back to 4.
            if not isinstance(cve_cols, int) or cve_cols < 1:
                cve_cols = 4

            table_width: int = 40
            logger.info(f"Calculating CVSS for CWE ID {ec3_results['CWE']}:")
            logger.info(f"Projected CVSS: {ec3_results['Projected CVSS']:.2f}")
            print()  # Print blank line to stdout for readability.
            logger.info(f"{'-'*table_width}")  # Print a line of dashes for separation.
            print()
            logger.info("Additional Information")
            print()
            logger.info(f" Min: {ec3_results['Min CVSS Base Score']:.2f}")
            logger.info(f" Max: {ec3_results['Max CVSS Base Score']:.2f}")
            logger.info(f" Average: {ec3_results['Average CVSS Base Score']:.2f}")
            logger.info(
                f" Stdev: {ec3_results['Standard Deviation CVSS Base Score']:.2f}"
            )
            print()

            cve_str: str = ""
            for i in range(0, len(ec3_results["CVE Records"]), cve_cols):
                cve_str += "\n"
                cve_str += "\t".join(ec3_results["CVE Records"][i : i + cve_cols])

            cve_str += "\n"

            logger.info(
                f"Found {ec3_results['Count']} related CVE record"
                f"{'s' if ec3_results['Count'] > 1 else ''}:\n{cve_str}"
            )
            logger.info(f"{'-'*table_width}")
            print()
        else:
            if not self.__results_valid(ec3_results):
                logger.warning("No ec3 results dictionary provided.")
            else:
                logger.warning(
                    "Provided ec3 results dictionary contains an invalid CWE ID."
                )

    @staticmethod
    def __dict_key_matches_type(
        test_dict: dict | None, test_key: str, test_type: type
    ) -> bool:
        """Confirm that a dictionary passed in has the specified key present, and that
            key is of the expected Type.

        Args:
            test_dict: Provided dictionary to be queried
            test_key: The string key to look up within test_dict.
            test_type: The expected type of test_dict[test_key].

        Returns:
            True if test_dict[test_key] is an instance of test_type, False otherwise
        """

        # Ensure test_dict is not None/empty and contains the test_key
        if not test_dict:
            return False
        if test_key not in test_dict:
            return False

        return isinstance(test_dict[test_key], test_type)

    @staticmethod
    def __results_valid(ec3_results: dict | None) -> bool:
        """Confirm that a results object passed in has all expected fields and conforms
            to the expected data types.

        Args:
            ec3_results: Provided results dictionary to be evaluated for completeness
                and the correct structure

        Returns:
            True if ec3_results contains all fields in the expected data types,
                False otherwise.
        """
        results_invalid: bool = False
        if ec3_results:
            #
            if not Cvss31Calculator.__dict_key_matches_type(
                ec3_results, "Projected CVSS", float
            ):
                results_invalid = True
            if not Cvss31Calculator.__dict_key_matches_type(ec3_results, "CWE", int):
                results_invalid = True
            if not Cvss31Calculator.__dict_key_matches_type(ec3_results, "Count", int):
                results_invalid = True
            if not Cvss31Calculator.__dict_key_matches_type(
                ec3_results, "Min CVSS Base Score", float
            ):
                results_invalid = True
            if not Cvss31Calculator.__dict_key_matches_type(
                ec3_results, "Max CVSS Base Score", float
            ):
                results_invalid = True
            if not Cvss31Calculator.__dict_key_matches_type(
                ec3_results, "Average CVSS Base Score", float
            ):
                results_invalid = True
            if not Cvss31Calculator.__dict_key_matches_type(
                ec3_results, "Standard Deviation CVSS Base Score", float
            ):
                results_invalid = True
            if not Cvss31Calculator.__dict_key_matches_type(
                ec3_results, "CVE Records", list
            ):
                results_invalid = True
            else:
                # "CVE Records" was a valid key of type list within ec3_results
                for cve in ec3_results["CVE Records"]:
                    if not isinstance(cve, str):
                        results_invalid = True

            # Any missing field or type mismatch would invalidate the result dictionary.
            return not results_invalid
        else:
            return False


class RestrictedUnpickler(pickle.Unpickler):
    """Restrict the unpickler to just nvdlib.classes.CVE objects"""

    def find_class(self, module, name) -> nvd_classes.CVE:
        """Override the default unpickler find_class method.

        Only permit nvdlib.classes.CVE to be loaded by the unpickler. For any other
        type raise an exception to stop a potentially malicious module.

        Args:
            module: The expected module to load from the unpickler. Must be
                "nvdlib.classes" during this restricted loading operation.
            name: The expected class within the module from the unpickler. Must be
                "CVE" during this restricted  loading operation

        Returns:
            The nvdlib.classes.CVE class type

        Raises:
            pickle.UnpicklingError: An unexpected class was attempted to be loaded.
        """

        if module == "nvdlib.classes" and name in {"CVE"}:
            return nvd_classes.CVE
        raise pickle.UnpicklingError(
            "Found an illegal class while loading pickle file."
        )
