"""
The Environmental CWE CVSS Calculator (ec3) is used to calculate a potential CVSS score for a provided CWE
Identifier. Data from the National Vulnerability Database(NVD) is pulled via the 2.0 API and stored for later re-use.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import collections
import csv
import io
import pickle
import statistics

from nvdlib import classes as nvd_classes  # type: ignore

from ec3.cvss import Cvss31

# Default path for storing returned API data.
data_default_file: str = "./data/nvd_loaded.pickle"


class Cvss31Calculator:
    """
    Wrapper class to obtain vulnerability data, and handle statistical calculations.
    """

    def __init__(
        self,
        cwe_id: int = 0,
        verbose: bool = False,
    ) -> None:
        """
        Initialize a Cvss31Calculator class instance using the provided parameters.

        :param cwe_id: an integer representing the CWE ID to query the NVD data against. Also used as the lookup value
        when normalizing using a remapping CSV file.
        :param verbose: Defaults to False. A boolean flag to signal whether additional statements should be displayed.
        """

        self.verbose: bool = verbose
        self.cwe_id: int = 0

        # Get the input CWE. Make sure the ID is greater than 0. Otherwise, warn the user of a bad cwe_id parameter.
        if self.__cwe_id_valid(cwe_id):
            self.cwe_id = cwe_id
        else:
            raise ValueError(
                "Can not initialize Cvss31Calculator with the provided CWE identifier."
            )

        # This value gets set if a normalization CSV file is loaded.
        self.normalized_id: int = 0

        # This will hold a list of nvdlib.classes.CVE objects loaded from a collector or file.
        self.raw_cve_data: list[nvd_classes.CVE] = []

        # Dictionary that will map CWE ID to list of CVSS vectors
        self.cwe_data: dict[int, list[Cvss31]] = collections.defaultdict(list)

        # Set optional temporal modifiers
        self.exploit_code_maturity: str = "X"
        self.remediation_level: str = "X"
        self.report_confidence: str = "X"

        # Set optional environmental modifiers
        self.modified_confidentiality: str = "X"
        self.modified_integrity: str = "X"
        self.modified_availability: str = "X"

        if self.verbose:
            print(
                f"Initialized Cvss31Calculator to search vulnerability data for CWE ID {self.cwe_id}."
            )

    @staticmethod
    def __cwe_id_valid(cwe_id: int | str | None) -> bool:
        """
        Utility function that provides a quick sanity check for the CWE ID value, whether it is an integer or string.

        :param cwe_id:
        :return: True if cwe_id is representable as an integer and is greater than 0, False otherwise.
        """
        try:
            return cwe_id is not None and int(cwe_id) > 0
        except ValueError:
            print("Caught ValueError. CWE ID provided was not a usable ID.")

        return False

    @staticmethod
    def __get_cwe_from_cve(cve: nvd_classes.CVE) -> list[int]:
        """
        Get all valid CWEs associated with the single nvdlib CVE object

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

    @staticmethod
    def __restricted_load(file_str: str | None) -> list[nvd_classes.CVE]:
        """
        Helper function to restrict the loaded class type.

        Attempts to load a list of nvd_classes.CVE

        :return: A list of nvdlib.classes.CVE objects if the pickle file is available and accessible. Returns an
        empty list otherwise.
        """

        return (
            RestrictedUnpickler(io.FileIO(file_str)).load()
            if file_str is not None
            else []
        )

    def has_normalized_id(self) -> bool:
        """
        Utility function to quickly determine if this calculator instance has a valid loaded normalized CWE ID.
        Useful in determining what default results to return.

        :return: True if normalized_id was initialized to a valid value, otherwise False
        """
        return self.__cwe_id_valid(self.normalized_id)

    def load_data_file(self, data_file_str: str | None = None) -> None:
        """
        Loads a previously saved pickle file containing NVD vulnerability data into a nvdlib.classes.CVE list that we
        can handle. If unable to load data from the specified or default data file, returns an empty list.
        Calling this function will potentially replace previously loaded data in memory.

        :param data_file_str: String containing the path to a pickle file containing nvdlib.classes.CVE data.
        :return None
        """

        # Attempt to load the data_default_file if just called with no parameters.
        if data_file_str is None:
            data_file_str = data_default_file

        try:
            self.raw_cve_data = self.__restricted_load(file_str=data_file_str)
            self.get_cwes()
        except FileNotFoundError:
            print("Caught FileNotFoundError. Input file not found.")
        except PermissionError:
            print("Caught FileNotFoundError. Unable to read data file.")
        except pickle.UnpicklingError as e:
            print(
                "Caught UnpicklingError. Input file was not in correct pickle format."
            )

        return None

    def save_data_file(self, data_file_str: str) -> None:
        """
        Save JSON data returned from the NVD API into a pickle file that we can re-load without calling the API again.

        :param data_file_str: A filename to write the saved NVD JSON data in pickle format, preserving the NVD object.
        :return None
        """

        try:
            with open(data_file_str, "wb") as pickle_fh:
                pickle.dump(self.raw_cve_data, pickle_fh, pickle.HIGHEST_PROTOCOL)
        except FileNotFoundError:
            raise

        return None

    def load_normalization_data(self, normalization_file_str: str) -> None:
        """
        Load the normalization data CSV file and finds the first valid corresponding normalization CWE identifier.
        Store this value within the class for later use during the final calculations.

        The normalization file should only have one suggestion per CWE ID in the left column.
        The file may map an identifier to itself or "Other". Both of these cases are expected to set the normalization
        CWE ID to None. If unable to load data from a file, file permissions are encountered, or no lookup value is
        found, set the normalization CWE ID to None.

        :param normalization_file_str: A path to the CSV file containing the normalization data to load
        :return int: An integer of the found CWE identifier to map to, or None if no new valid normalization value
        is fou.
        """

        try:
            with open(normalization_file_str, mode="r") as normalization_fh:
                normalization_file = csv.reader(normalization_fh)

                # Check each line, return on the first valid match. Otherwise, return None.
                for lines in normalization_file:
                    if lines[0] == self.cwe_id.__str__():

                        # Try to cast the normalized value column as an integer and return
                        try:
                            if (
                                lines[1] != "Other"
                                and lines[1] != self.cwe_id.__str__()
                            ):
                                self.normalized_id = int(lines[1])
                                return None
                        except ValueError:
                            print(
                                "Caught ValueError. CWE ID found, but normalized value is not a usable ID."
                            )

                # The whole file was searched without error. Notify the user that no match was found.
                if self.verbose:
                    print(f"CWE ID {self.cwe_id} does not normalize to a new ID.")

        except FileNotFoundError:
            print("Caught FileNotFoundError. Input normalization file not found.")
        except PermissionError:
            print("Caught PermissionError. Unable to open normalization file.")

        # If still here, then no value was found or an error was encountered. Leave normalized CWE ID as previously
        # initialized and return.
        return None

    def set_vulnerability_data(self, new_data: list[nvd_classes.CVE]) -> None:
        """
        Utility function to  evaluate whether the input data is a list of nvdlib.classes.CVE objects. If so, load this
        new_data into the class instance. Otherwise, raise TypeError.

        :param new_data: A list of new vulnerability records to load into this class instance.
        :return: None
        """

        if not isinstance(new_data, list) and not (
            isinstance(record, nvd_classes.CVE) for record in new_data
        ):
            raise TypeError(
                "Vulnerability data is not in the correct format. Expected list[nvdlib.classes.CVE]"
            )

        self.raw_cve_data = new_data
        self.get_cwes()

        return None

    def set_score_modifiers(
        self,
        exploit_code_maturity: str = "X",
        remediation_level: str = "X",
        report_confidence: str = "X",
        modified_confidentiality: str = "X",
        modified_integrity: str = "X",
        modified_availability: str = "X",
    ) -> None:
        """
        Utility function to set the individual temporal and environmental re-scoring metrics. Validation occurs during
        the actual modification of the Cvss31 object.

        :param exploit_code_maturity: Value representing temporal Exploit Code Maturity (E) modification
        :param remediation_level: Value representing temporal Remediation Level (RL) modification
        :param report_confidence: Value representing temporal Report Confidence (RC) modification
        :param modified_confidentiality: Value representing environmental Modified Confidentiality (MC) modification
        :param modified_integrity: Value representing environmental Modified Integrity (MI) modification
        :param modified_availability: Value representing environmental Modified Availability (MA) modification
        :return: None
        """
        self.exploit_code_maturity = exploit_code_maturity
        self.remediation_level = remediation_level
        self.report_confidence = report_confidence
        self.modified_confidentiality = modified_confidentiality
        self.modified_integrity = modified_integrity
        self.modified_availability = modified_availability
        return None

    def get_cwes(self) -> None:
        """
        Utility function to parse through the loaded vulnerability data, and create a lookup dict for each CWE
        identifier encountered. This data is stored within the class for later use during final calculations. Saves the
        associated CVSS data (applying temporal/environmental modifications) within their respective CWE lookup bin.

        :return: None
        """
        # Populate the CWE dictionary and cve count
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
                        if self.modified_confidentiality != "X":
                            base_cvss.set_mc(self.modified_confidentiality)
                        if self.modified_integrity != "X":
                            base_cvss.set_mi(self.modified_integrity)
                        if self.modified_availability != "X":
                            base_cvss.set_ma(self.modified_availability)

                        cwes_for_cve = self.__get_cwe_from_cve(cve)
                        for cwe in cwes_for_cve:
                            self.cwe_data[cwe].append(base_cvss)
                except ValueError:
                    print("Caught ValueError.")
                    raise

        # Display the number of CVE entries in the raw_cve_data
        if self.verbose:
            print(f"Processed {cve_count} vulnerabilities.")

        return None

    def get_results(self, cwe_id: int = 0) -> dict:
        """
        Utility function to conduct statistical analysis against source data. If verbose, include additional fields in
        the result dictionary. Can be called multiple times against different IDs and will use the same data until new
        data is loaded from file or NVD API.

        :param cwe_id: An optional integer value for the CWE ID to collect data on.
        :return The default results dict includes the projected CVSS score, accounting for temporal and environmental
        modifications. Verbose output includes min/max/mean base score CVSS values, count (of vulnerabilities mapped to
        the desired CWE ID), and the CWE ID used.
        """

        # If called without an ID, default to using a normalized ID (if present), otherwise the default CWE ID.
        if cwe_id == 0:
            cwe_id = self.normalized_id if self.has_normalized_id() else self.cwe_id

        if self.__cwe_id_valid(cwe_id):
            score_values: list[list[float]] = []
            if self.cwe_data[cwe_id]:
                if self.verbose:
                    print(f"Vulnerability data found for CWE ID {cwe_id}.")

                for x in self.cwe_data[cwe_id]:
                    scores = [x.get_base_score(), x.get_environmental_score()]
                    score_values.append(scores)

                # Create an output format with all required information
                # score_values holds [base, environmental] calculated scores
                # self.cwe_data is a dict that holds a list of Cvss31 objects indexed by the CWE ID
                calculator_results: dict = {
                    "Projected CVSS:": statistics.mean(
                        [item[1] for item in score_values]
                    )
                } | (
                    {
                        "CWE": cwe_id,
                        "Count": len(self.cwe_data[cwe_id]),
                        "Min CVSS Base Score:": min([item[0] for item in score_values]),
                        "Max CVSS Base Score:": max([item[0] for item in score_values]),
                        "Average CVSS Base Score:": statistics.mean(
                            [item[0] for item in score_values]
                        ),
                    }
                    if self.verbose
                    else {}
                )

                return calculator_results

            else:
                if self.verbose:
                    print(f"No vulnerability data found for CWE ID {cwe_id}.")

        else:
            if self.verbose:
                print(f"CWE ID provided was not a usable ID.")

        # Use the same output format but report no data found.
        empty_results: dict = {"Projected CVSS:": 0} | (
            {
                "CWE": cwe_id,
                "Count": 0,
                "Min CVSS Base Score:": 0,
                "Max CVSS Base Score:": 0,
                "Average CVSS Base Score:": 0,
            }
            if self.verbose
            else {}
        )

        return empty_results


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
        raise pickle.UnpicklingError(
            "Found an illegal class while loading pickle file."
        )
