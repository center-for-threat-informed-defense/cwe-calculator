import builtins
import json
import os
import pickle

import pytest
from ec3.calculator import Cvss31Calculator
from ec3.server.broker import Cvss31CalculatorBroker, ModifiedCalculatorDataHandler
from mock import mock_open, patch
from nvdlib import classes as nvd_classes
from watchdog.events import FileSystemEvent

MOCK_VULN_PKLE = "/fake/vuln/file.pickle"
MOCK_VULN_JSON = "/fake/vuln/file.json"
MOCK_NORM_FILE = "/fake/norm/file.csv"
BUILTIN_OPEN = open
BUILTIN_SAMEFILE = os.path.samefile


@pytest.fixture
def example_broker() -> Cvss31CalculatorBroker:
    return Cvss31CalculatorBroker()


@pytest.fixture
def example_cve_data() -> list[nvd_classes.CVE]:
    return [
        nvd_classes.__convert(
            "cve",
            {
                "id": "CVE-2023-48724",
                "vulnStatus": "Awaiting Analysis",
                "cwe": [{"lang": "en", "value": "CWE-121"}],
                "v31vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "v31severity": "HIGH",
                "v31attackVector": "NETWORK",
                "v31attackComplexity": "LOW",
                "v31privilegesRequired": "NONE",
                "v31userInteraction": "NONE",
                "v31scope": "UNCHANGED",
                "v31confidentialityImpact": "NONE",
                "v31integrityImpact": "NONE",
                "v31availabilityImpact": "HIGH",
                "metrics": {},
            },
        ),
        nvd_classes.__convert(
            "cve",
            {
                "id": "CVE-2023-49906",
                "vulnStatus": "Awaiting Analysis",
                "cwe": [{"lang": "en", "value": "CWE-121"}],
                "v31vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                "v31severity": "HIGH",
                "v31attackVector": "NETWORK",
                "v31attackComplexity": "LOW",
                "v31privilegesRequired": "HIGH",
                "v31userInteraction": "NONE",
                "v31scope": "UNCHANGED",
                "v31confidentialityImpact": "HIGH",
                "v31integrityImpact": "HIGH",
                "v31availabilityImpact": "HIGH",
                "metrics": {},
            },
        ),
        nvd_classes.__convert(
            "cve",
            {
                "id": "CVE-2023-49907",
                "vulnStatus": "Awaiting Analysis",
                "cwe": [{"lang": "en", "value": "CWE-121"}],
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-49907",
                "v31vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                "v31severity": "HIGH",
                "v31attackVector": "NETWORK",
                "v31attackComplexity": "LOW",
                "v31privilegesRequired": "HIGH",
                "v31userInteraction": "NONE",
                "v31scope": "UNCHANGED",
                "v31confidentialityImpact": "HIGH",
                "v31integrityImpact": "HIGH",
                "v31availabilityImpact": "HIGH",
                "metrics": {},
            },
        ),
    ]


@pytest.fixture
def setup_mock_files(monkeypatch, example_cve_data):

    def mock_open_files(*args, **kwargs):
        if args[0] == MOCK_NORM_FILE:
            return mock_open(read_data="121,300")(*args, **kwargs)
        if args[0] == MOCK_VULN_JSON:
            return mock_open(read_data="{}")(*args, **kwargs)
        return BUILTIN_OPEN(*args, **kwargs)

    def mock_samefile(*args, **kwargs):
        if args[0] == args[1] == MOCK_VULN_PKLE:
            return True
        if args[0] == args[1] == MOCK_VULN_JSON:
            return True
        if args[0] == args[1] == MOCK_NORM_FILE:
            return True
        return BUILTIN_SAMEFILE(*args, **kwargs)

    def mock_restricted_load(*args, **kwargs):
        return example_cve_data

    monkeypatch.setattr(builtins, "open", mock_open_files)
    monkeypatch.setattr(os.path, "samefile", mock_samefile)
    monkeypatch.setattr(Cvss31Calculator, "restricted_load", mock_restricted_load)


@pytest.fixture
def example_modified_data_handler(setup_mock_files) -> ModifiedCalculatorDataHandler:
    broker = Cvss31CalculatorBroker(MOCK_VULN_PKLE, MOCK_NORM_FILE)
    return ModifiedCalculatorDataHandler(broker)


def test_broker_is_running(example_broker: Cvss31CalculatorBroker):
    example_broker.start()
    assert example_broker.is_running
    example_broker.stop()
    assert not example_broker.is_running


def test_broker_start_with_files_in_same_directory(
    setup_mock_files,
    example_broker: Cvss31CalculatorBroker,
):
    example_broker.start(MOCK_VULN_PKLE, MOCK_NORM_FILE)
    calc = example_broker.request_calculator()
    resp = calc.calculate_results(121, True)
    assert resp["projected_cvss"] == 0
    assert resp["cwe"] == 300
    assert resp["count"] == 0
    assert resp["min_cvss_base_score"] == 0
    assert resp["max_cvss_base_score"] == 0
    assert resp["avg_cvss_base_score"] == 0
    assert resp["std_dev_cvss_base_score"] == 0
    assert len(resp["cve_records"]) == 0


def test_broker_start_with_files_in_separate_directories(
    setup_mock_files, example_broker: Cvss31CalculatorBroker
):
    example_broker.start(MOCK_VULN_PKLE)
    calc = example_broker.request_calculator()
    resp = calc.calculate_results(121)
    records = set(resp["cve_records"])
    assert resp["projected_cvss"] == 7.3
    assert resp["cwe"] == 121
    assert resp["count"] == 3
    assert resp["min_cvss_base_score"] == 7.2
    assert resp["max_cvss_base_score"] == 7.5
    assert resp["avg_cvss_base_score"] == 7.3
    assert resp["std_dev_cvss_base_score"] == 0.17320508075688762
    assert len(resp["cve_records"]) == 3
    assert "CVE-2023-48724" in records
    assert "CVE-2023-49906" in records
    assert "CVE-2023-49907" in records


@patch.object(Cvss31Calculator, "restricted_load")
def test_broker_start_with_vuln_file_not_found_error(
    mock_restricted_load, example_broker, caplog
):
    mock_restricted_load.side_effect = FileNotFoundError
    example_broker.start()
    assert (
        "Failed to update vulnerability data. Data file was not found."
    ) in caplog.text
    example_broker.stop()


@patch.object(Cvss31Calculator, "restricted_load")
def test_broker_start_with_vuln_permissions_error(
    mock_restricted_load, example_broker, caplog
):
    mock_restricted_load.side_effect = PermissionError
    example_broker.start()
    assert (
        "Failed to update vulnerability data. "
        "Insufficient permissions to access data file."
    ) in caplog.text
    example_broker.stop()


@patch.object(Cvss31Calculator, "restricted_load")
def test_broker_start_with_vuln_unpickling_error(
    mock_restricted_load, example_broker, caplog
):
    mock_restricted_load.side_effect = pickle.UnpicklingError
    example_broker.start()
    assert (
        "Failed to update vulnerability data. Data file uses an invalid pickle format."
    ) in caplog.text
    example_broker.stop()


@patch.object(Cvss31Calculator, "load_json")
def test_broker_start_with_vuln_lookup_error(mock_decode, example_broker, caplog):
    mock_decode.side_effect = LookupError
    example_broker.start(MOCK_VULN_JSON)
    assert (
        "Failed to update vulnerability data. Data file lists no vulnerabilities."
    ) in caplog.text
    example_broker.stop()


@patch.object(Cvss31Calculator, "load_json")
def test_broker_start_with_vuln_decode_error(mock_decode, example_broker, caplog):
    mock_decode.side_effect = json.JSONDecodeError("Bad JSON.", "", 0)
    example_broker.start(MOCK_VULN_JSON)
    assert ("Failed to update vulnerability data. Invalid JSON:") in caplog.text
    example_broker.stop()


@patch.object(Cvss31Calculator, "parse_normalization_file")
def test_broker_start_with_norm_file_not_found_error(
    mock_parse_file, example_broker, caplog
):
    mock_parse_file.side_effect = FileNotFoundError
    example_broker.start()
    assert (
        "Failed to update normalization data. Normalization file was not found."
    ) in caplog.text
    example_broker.stop()


@patch.object(Cvss31Calculator, "parse_normalization_file")
def test_broker_start_with_norm_permissions_error(
    mock_parse_file, example_broker, caplog
):
    mock_parse_file.side_effect = PermissionError
    example_broker.start()
    assert (
        "Failed to update normalization data. "
        "Insufficient permissions to access normalization file"
    ) in caplog.text
    example_broker.stop()


@patch.object(Cvss31Calculator, "parse_normalization_file")
def test_broker_start_with_norm_type_error(mock_parse_file, example_broker, caplog):
    mock_parse_file.side_effect = TypeError
    example_broker.start()
    assert (
        "Failed to update normalization data. "
        "Normalization file is not in the correct format."
    ) in caplog.text
    example_broker.stop()


def test_modified_vuln_file_handler(setup_mock_files, example_modified_data_handler):
    assert example_modified_data_handler.on_modified(FileSystemEvent(MOCK_VULN_PKLE))


def test_modified_norm_file_handler(setup_mock_files, example_modified_data_handler):
    assert example_modified_data_handler.on_modified(FileSystemEvent(MOCK_NORM_FILE))


def test_modified_rand_file_handler(setup_mock_files, example_modified_data_handler):
    assert not example_modified_data_handler.on_modified(
        FileSystemEvent(MOCK_VULN_JSON)
    )
