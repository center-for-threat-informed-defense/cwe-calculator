import os
import pickle
from tempfile import NamedTemporaryFile
from typing import Any, Generator

import ec3
import ec3.server
import ec3.server.cli
import pytest
from fastapi.testclient import TestClient
from nvdlib import classes as nvd_classes


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
def example_args(
    example_vulnerability_file: str, example_normalization_file: str
) -> list[str]:
    return [
        "--data-file",
        example_vulnerability_file,
        "--normalize-file",
        example_normalization_file,
    ]


@pytest.fixture
def test_client(example_vulnerability_file: str, example_normalization_file: str):
    app = ec3.server.cli.instantiate_ec3_service(
        example_vulnerability_file, example_normalization_file
    )
    # Create test client
    with TestClient(app) as client:
        # Return test client
        yield client
        # Destroy test client


def test_args_simple(
    example_args: list[str],
    example_vulnerability_file: str,
    example_normalization_file: str,
):
    args = ec3.server.cli.parse_args(example_args)
    assert os.path.samefile(args.data_file, example_vulnerability_file)
    assert os.path.samefile(args.normalize_file, example_normalization_file)


def test_server_score_not_normalized(test_client: TestClient):
    response = test_client.get("/score/121?normalize=false")
    json = response.json()
    records = set(json["cve_records"])
    assert response.status_code == 200
    assert json["projected_cvss"] == 7.3
    assert json["cwe"] == 121
    assert json["count"] == 3
    assert json["min_cvss_base_score"] == 7.2
    assert json["max_cvss_base_score"] == 7.5
    assert json["avg_cvss_base_score"] == 7.3
    assert json["std_dev_cvss_base_score"] == 0.17320508075688762
    assert len(json["cve_records"]) == 3
    assert "CVE-2023-48724" in records
    assert "CVE-2023-49906" in records
    assert "CVE-2023-49907" in records


def test_server_score_normalized(test_client: TestClient):
    response = test_client.get("/score/121?normalize=true")
    json = response.json()
    assert response.status_code == 200
    assert json["projected_cvss"] == 0
    assert json["cwe"] == 300
    assert json["count"] == 0
    assert json["min_cvss_base_score"] == 0
    assert json["max_cvss_base_score"] == 0
    assert json["avg_cvss_base_score"] == 0
    assert json["std_dev_cvss_base_score"] == 0
    assert len(json["cve_records"]) == 0
