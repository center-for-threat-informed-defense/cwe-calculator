import json
import os
import pickle
from tempfile import NamedTemporaryFile
from typing import Any, Generator

import pytest
from ec3.calculator import Cvss31Calculator
from ec3.server.broker import Cvss31CalculatorBroker, ModifiedCalculatorDataHandler
from mock import patch
from nvdlib import classes as nvd_classes
from watchdog.events import FileSystemEvent


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
def example_vulnerability_file(example_cve_data) -> Generator[str, Any, None]:
    data_file = NamedTemporaryFile(dir="./tests", delete=False)
    # Create temporary data file
    pickle.dump(example_cve_data, data_file, pickle.HIGHEST_PROTOCOL)
    data_file.flush()
    data_file.close()
    # Return temporary data file
    yield data_file.name
    # Destroy temporary data file
    os.remove(data_file.name)


@pytest.fixture
def example_normalization_file() -> Generator[str, Any, None]:
    norm_file = NamedTemporaryFile(dir="./tests", delete=False)
    # Create temporary data file
    norm_file.write(b"121,300")
    norm_file.close()
    # Return temporary data file
    yield norm_file.name
    # Destroy temporary data file
    os.remove(norm_file.name)


@pytest.fixture
def example_modified_data_handler(
    example_vulnerability_file: str, example_normalization_file: str
) -> ModifiedCalculatorDataHandler:
    broker = Cvss31CalculatorBroker(
        example_vulnerability_file, example_normalization_file
    )
    return ModifiedCalculatorDataHandler(broker)


def test_broker_is_running(example_broker: Cvss31CalculatorBroker):
    example_broker.start()
    assert example_broker.is_running
    example_broker.stop()
    assert not example_broker.is_running


def test_broker_start_with_files_in_same_directory(
    example_broker: Cvss31CalculatorBroker,
    example_vulnerability_file: str,
    example_normalization_file: str,
):
    example_broker.start(example_vulnerability_file, example_normalization_file)
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
    example_broker: Cvss31CalculatorBroker, example_vulnerability_file: str
):
    example_broker.start(example_vulnerability_file)
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
    example_broker.start("/fake/file.json")
    assert (
        "Failed to update vulnerability data. Data file lists no vulnerabilities."
    ) in caplog.text
    example_broker.stop()


@patch.object(Cvss31Calculator, "load_json")
def test_broker_start_with_vuln_decode_error(mock_decode, example_broker, caplog):
    mock_decode.side_effect = json.JSONDecodeError("Bad JSON.", "", 0)
    example_broker.start("/fake/file.json")
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


def test_modified_vuln_file_handler(
    example_modified_data_handler, example_vulnerability_file, caplog
):
    assert example_modified_data_handler.on_modified(
        FileSystemEvent(example_vulnerability_file)
    )


def test_modified_norm_file_handler(
    example_modified_data_handler, example_normalization_file, caplog
):
    assert example_modified_data_handler.on_modified(
        FileSystemEvent(example_normalization_file)
    )
