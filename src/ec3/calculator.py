"""
Utility class to parse, modify, and analyze NVD vulnerability data.
NVD vulnerability data is parsed to extract CWE/CVSS31 fields for later statistical analysis.
Temporal and environmental CVSS metrics may be specified to influence calculations.
Results may be obtained for any number of CWE identifiers using the same source data.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import collections
import csv
import io
import pickle
import statistics

from nvdlib import classes as nvd_classes  # type: ignore

from ec3 import data_default_file
from ec3.cvss import Cvss31


class Cvss31Calculator:
    """
    Wrapper class to obtain vulnerability data, and handle statistical calculations.
    """

    def __init__(
        self,
        data_file_str: str = data_default_file,
        normalization_file_str: str = "",
        verbose: bool = False,
    ) -> None:
        """
        Initialize a Cvss31Calculator class instance using the provided parameters.

        :param data_file_str: A string representing the default location to load vulnerability data from.
        :param normalization_file_str: A string representing the normalization CSV file location to use when
        calculating normalized results.
        :param verbose: A boolean flag to signal whether additional statements should be displayed.
        """

        self.verbose: bool = verbose

        # This will hold a list of nvdlib.classes.CVE objects loaded from a collector or file.
        self.raw_cve_data: list[nvd_classes.CVE] = []

        # Set self.raw_cve_data to default data file contents.
        if data_file_str:
            self.load_data_file(data_file_str)
        else:
            self.load_data_file(data_default_file)

        # Save the path to the normalization file to use when calculate_results is called with the normalize flag.
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

        if self.verbose:
            print(f"Initialized Cvss31Calculator.")
            print()  # print blank line

    @staticmethod
    def __cwe_id_valid(cwe_id: int | str | None) -> bool:
        """
        Utility function that provides a quick sanity check for the CWE ID value, whether it is an integer or string.

        :param cwe_id: CWE identifier to evaluate as a potentially valid ID. Value may be an integer, string, or None.
        :return: True if cwe_id is representable as an integer and is greater than 0, False otherwise.
        """

        try:
            return cwe_id is not None and int(cwe_id) > 0
        except ValueError:
            print("Caught ValueError. CWE ID provided was not a usable ID.")
            print()  # print blank line

        return False

    @staticmethod
    def __get_cwe_from_cve(cve: nvd_classes.CVE) -> list[int]:
        """
        Get all valid CWEs associated with the single nvdlib CVE object

        :param cve: A single CVE record from the list of CVEs loaded from the NVD data
        :return A list containing the numerical ids of valid CWEs parsed from this CVE.
        """

        cwes: list[int] = []

        # The CVE data must not be Rejected, and contain a CWE identifier.
        if cve.vulnStatus == "Rejected" or not hasattr(cve, "cwe"):
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
                print(
                    "Encountered error while parsing CWE ID from vulnerability data. Skipping this entry."
                )
                continue

        return cwes

    @staticmethod
    def __restricted_load(file_str: str | None) -> list[nvd_classes.CVE]:
        """
        Helper function to restrict the loaded class type. Attempts to load a list of nvd_classes.CVE. This should
        prevent unsafe modules from being arbitrarily loaded.

        :param file_str: A string representing the data file path to load.
        :return: A list of nvdlib.classes.CVE objects if the pickle file is available and accessible. Returns an
        empty list otherwise.
        """

        return (
            RestrictedUnpickler(io.FileIO(file_str)).load()
            if file_str is not None
            else []
        )

    def load_data_file(self, data_file_str: str | None = None) -> None:
        """
        Loads a previously saved pickle file containing NVD vulnerability data into a nvdlib.classes.CVE list that the
        code can handle. If unable to load data from the specified or default data file, returns an empty list.
        Calling this function will potentially replace previously loaded data in memory.

        :param data_file_str: String containing the path to a pickle file containing nvdlib.classes.CVE data.
        :return None
        """

        if self.verbose:
            print("Loading vulnerability information from a saved data file.")
            print()  # print blank line

        if data_file_str is None:
            if self.verbose:
                print(
                    f"No data_file provided, setting to default file: {data_default_file}"
                )
                print()  # print blank line
            data_file_str = data_default_file

        try:
            self.raw_cve_data = self.__restricted_load(file_str=data_file_str)
        except FileNotFoundError:
            print("Caught FileNotFoundError. Input file not found.")
        except PermissionError:
            print("Caught PermissionError. Unable to read data file.")
        except pickle.UnpicklingError:
            print("Caught UnpicklingError. Input file not in correct pickle format.")

        return None

    def normalize_cwe(self, cwe_id: int = 0) -> int | None:
        """
        Loads the normalization data CSV file and returns the first valid corresponding normalization CWE identifier.

        The normalization file should only have one suggestion per CWE ID in the left column.
        The file may map an identifier to itself or "Other". Both of these cases are expected to set the normalization
        CWE ID to None. If unable to load data from a file, file permissions are encountered, or no lookup value is
        found, set the normalization CWE ID to None.

        :param cwe_id: A CWE identifier used for the lookup in the left column of the normalization CSV file.
        :return A CWE identifier of the normalized value to use in place of the original cwe_id, or None if no new ID
        was found.
        """

        try:
            with open(self.normalization_file_str, mode="r") as normalization_fh:
                normalization_file = csv.reader(normalization_fh)

                # Check each line, return on the first valid match. Otherwise, return None.
                for lines in normalization_file:
                    if lines[0] == cwe_id.__str__():

                        # Try to cast the normalized value column as an integer and return
                        try:
                            if lines[1] != "Other" and lines[1] != cwe_id.__str__():
                                normalized_id = int(lines[1])
                                if self.verbose:
                                    print(
                                        f"CWE ID {cwe_id} matched normalization ID {normalized_id}."
                                    )
                                    print()  # print blank line
                                return normalized_id
                        except ValueError:
                            print(
                                "Caught ValueError. CWE ID found, but normalized value is not a usable ID."
                            )

                # The whole file was searched without error. Notify the user that no match was found.
                if self.verbose:
                    print(f"CWE ID {cwe_id} does not normalize to a new ID.")
                    print()  # print blank line

        except FileNotFoundError:
            print("Caught FileNotFoundError. Input normalization file not found.")
        except PermissionError:
            print("Caught PermissionError. Unable to open normalization file.")

        # If still here, then no value was found or an error was encountered. Return nothing found
        return None

    def set_vulnerability_data(self, new_data: list[nvd_classes.CVE]) -> None:
        """
        Utility function to  evaluate whether the input data is a list of nvdlib.classes.CVE objects. If so, load this
        new_data into the class instance. Otherwise, raise TypeError.

        :param new_data: A list of new vulnerability records to load into this class instance.
        :return: None
        """

        if not isinstance(new_data, list) or not any(
            isinstance(record, nvd_classes.CVE) for record in new_data
        ):
            raise TypeError(
                "Vulnerability data is not in the correct format. Expected list[nvdlib.classes.CVE]"
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
        """
        Utility function to set the individual temporal and environmental re-scoring metrics. Validation occurs during
        the actual modification of the Cvss31 object.

        :param e: Value representing temporal Exploit Code Maturity (E) modification
        :param rl: Value representing temporal Remediation Level (RL) modification
        :param rc: Value representing temporal Report Confidence (RC) modification
        :param cr: Value representing environmental Confidentiality Requirement (CR) modification
        :param ir: Value representing environmental Integrity Requirement (IR) modification
        :param ar: Value representing environmental Availability Requirement (AR) modification
        :param mav: Value representing environmental Modified Attack Vector (MAV) modification
        :param mac: Value representing environmental Modified Attack Complexity (MAC) modification
        :param mpr: Value representing environmental Modified Privileges Required (MPR) modification
        :param mui: Value representing environmental Modified User Interaction (MUI) modification
        :param ms: Value representing environmental Modified Scope (MS) modification
        :param mc: Value representing environmental Modified Confidentiality (MC) modification
        :param mi: Value representing environmental Modified Integrity (MI) modification
        :param ma: Value representing environmental Modified Availability (MA) modification
        :return: None
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
        """
        Utility function to parse through the loaded vulnerability data, and create a lookup dict for each CWE
        identifier encountered. This data is stored within the class for later use during final calculations. Saves the
        associated CVE/CVSS data (applying temporal/environmental modifications) within their respective CWE lookup bin.

        :return: None
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
                    print("Caught ValueError parsing CWE data from vulnerabilities.")
                    raise

        # Display the number of CVE entries in the raw_cve_data
        if self.verbose:
            print(f"Processed {cve_count} vulnerabilities.")
            print()  # print blank line

        return None

    def calculate_results(self, cwe_id: int = 0, normalize: bool = False) -> dict:
        """
        Utility function to conduct statistical analysis against source data. Can be called multiple times against
        different IDs and will use the same data until new data is loaded from a file or the ec3.collector.

        If normalization was requested, then we will attempt to find a replacement recommended CWE ID to use from
        the class' set normalization file string. Normalization is attempting to use a CWE ID higher in the relationship
        tree that might be more commonly used during mapping. Note that not all CWE IDs have a recommended
        normalization ID to use as a replacement.

        :param cwe_id: A required integer value for the CWE ID to collect data on.
        :param normalize: A boolean value to determine whether a normalized CWE ID is used in lieu of the provided ID.
        :return The results dict includes the projected CVSS score (accounting for temporal and environmental
        modifications), the CWE ID used, min/max/mean base score CVSS values, count (of vulnerabilities mapped to the
        desired CWE ID), and the list of related CVE records.
        """

        # Attempt to load the normalization CSV file, and update the cwe_id param to the normalized value if not None.
        # The input cwe_id value should be a valid CWE identifier.
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

                # Create an output format with all required information
                # score_values holds [base, environmental] calculated scores
                # self.cwe_data is a dict that holds a list of [cve_id, Cvss31] list entries indexed by the CWE ID
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
                    "CVE Records": cve_ids,
                }

                return calculator_results

            else:
                if self.verbose:
                    print(f"No vulnerability data found for CWE ID {cwe_id}.")
                    print()  # print blank line

        else:
            if self.verbose:
                print("CWE ID provided was not a usable ID.")
                print()  # print blank line

        # Use the same output format but report no data found.
        empty_results: dict = {
            "Projected CVSS": 0,
            "CWE": cwe_id,
            "Count": 0,
            "Min CVSS Base Score": 0,
            "Max CVSS Base Score": 0,
            "Average CVSS Base Score": 0,
            "CVE Records": [],
        }

        return empty_results

    def output_results(self, ec3_results: dict = {}, cve_cols: int = 4) -> None:
        """
        Utility function to print a previously returned results dictionary. If verbose, include additional fields beyond
        the "Projected CVSS". Validates the expected type for each field before rendering.

        :param ec3_results: A required dictionary of values returned from Cvss31Calculator.calculate_results().
        :param cve_cols: An optional integer to set how many CVE records appear per line during output.
        :return None
        """

        if self.__results_valid(ec3_results) and self.__cwe_id_valid(
            ec3_results["CWE"]
        ):
            if self.verbose:

                # If negative or bad value provided, set back to default of 4 columns per line.
                if not isinstance(cve_cols, int) or cve_cols < 1:
                    cve_cols = 4

                table_width: int = 40
                table_title = "Base CVSS Scores"
                print(f"Vulnerability data found for CWE ID {ec3_results['CWE']}:")
                print(f"Projected CVSS: {ec3_results['Projected CVSS']}")
                print()  # print blank line
                # Print a centered table head for a table of width [table_width]. 16 is the length of the title.
                print(
                    f"{'-'*table_width}\n{' '*((table_width - len(table_title))//2)}{table_title}\n{'-'*table_width}"
                )
                print(f" Min: {ec3_results['Min CVSS Base Score']}")
                print(f" Max: {ec3_results['Max CVSS Base Score']}")
                print(f" Average: {ec3_results['Average CVSS Base Score']}")
                print(f"{'-'*table_width}")
                print()  # print blank line
                print(
                    f"Found {ec3_results['Count']} related CVE record{'s' if ec3_results['Count'] > 1 else ''}:"
                )
                for i in range(0, len(ec3_results["CVE Records"]), cve_cols):
                    print("\t".join(ec3_results["CVE Records"][i : i + cve_cols]))
                print()  # print blank line

            else:
                print(
                    f"Vulnerability data found for CWE ID {ec3_results['CWE']}. Projected CVSS: "
                    f"{ec3_results['Projected CVSS']}"
                )
                print()  # print blank line

        else:
            if self.verbose:
                if not self.__results_valid(ec3_results):
                    print("No ec3 results dictionary provided.")
                    print()  # print blank line
                else:
                    print("Provided ec3 results dictionary contains an invalid CWE ID.")
                    print()  # print blank line

    @staticmethod
    def __dict_key_matches_type(
        test_dict: dict | None, test_key: str, test_type: type
    ) -> bool:
        """
        Utility function that confirms a dictionary passed in has the specified key present, and that key is of the
        expected Type.

        :param test_dict: Provided dictionary to be queried
        :param test_key: The string key to look up within test_dict.
        :param test_type: The expected type of test_dict[test_key].
        :return: True if test_dict[test_key] is an instance of test_type, False otherwise
        """

        # Ensure test_dict is not None/empty and contains the test_key
        if not test_dict:
            return False
        if test_key not in test_dict:
            return False

        return isinstance(test_dict[test_key], test_type)

    @staticmethod
    def __results_valid(ec3_results: dict | None) -> bool:
        """
        Utility function that confirms a results object passed in has all expected fields and conforms to the expected
         data types.

        :param ec3_results: Provided results dictionary to be evaluated for completeness and the correct structure
        :return: True if ec3_results contains all fields in the expected data types, False otherwise.
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
    """
    Helper class to restrict the unpickler to just nvdlib.classes.CVE objects
    """

    def find_class(self, module, name) -> nvd_classes.CVE:
        """
        Overrides the default unpickler find_class method.
        Only permit nvdlib.classes.CVE to be loaded by the unpickler. For any other type raise an exception to stop
        a potentially malicious module.

        :param module: The expected module to load from the unpickler. Must be "nvdlib.classes" during this
        restricted loading operation.
        :param name: The expected class within the module from the unpickler. Must be "CVE" during this restricted
        loading operation
        :return nvdlib.classes.CVE class type
        """

        if module == "nvdlib.classes" and name in {"CVE"}:
            return nvd_classes.CVE
        raise pickle.UnpicklingError(
            "Found an illegal class while loading pickle file."
        )
