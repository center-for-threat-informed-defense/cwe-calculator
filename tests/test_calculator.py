import builtins
import io
import logging

import pickle
import pytest
from mock import patch, mock_open
from nvdlib import classes as nvd_classes

import ec3.calculator


@pytest.fixture
def example_cve_data() -> nvd_classes.CVE:

    # Using API return of Heartbleed CVE as an example, some unrelated fields have been selectively removed.
    test_data_reduced = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "sourceIdentifier": "secalert@redhat.com",
            "published": "2014-04-07T22:55:03.893",
            "lastModified": "2023-11-07T02:18:10.590",
            "vulnStatus": "Modified",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Test",
                },
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "availabilityImpact": "NONE",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 3.6,
                    }
                ],
            },
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-125"}],
                }
            ],
            "cwe": [{"lang": "en", "value": "CWE-125"}],
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "v31score": 7.5,
            "v31vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "v31severity": "HIGH",
            "v31attackVector": "NETWORK",
            "v31attackComplexity": "LOW",
            "v31privilegesRequired": "NONE",
            "v31userInteraction": "NONE",
            "v31scope": "UNCHANGED",
            "v31confidentialityImpact": "HIGH",
            "v31integrityImpact": "NONE",
            "v31availabilityImpact": "NONE",
            "v31exploitability": 3.9,
            "v31impactScore": 3.6,
            "score": ["V31", 7.5, "HIGH"],
        },
    )

    return test_data_reduced


@pytest.fixture
def example_cve_data_to_normalize() -> nvd_classes.CVE:

    # Using API return of Heartbleed CVE as an example, some unrelated fields have been selectively removed.
    test_data_reduced = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "sourceIdentifier": "secalert@redhat.com",
            "published": "2014-04-07T22:55:03.893",
            "lastModified": "2023-11-07T02:18:10.590",
            "vulnStatus": "Modified",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Test",
                },
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "availabilityImpact": "NONE",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 3.6,
                    }
                ],
            },
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-126"}],
                }
            ],
            "cwe": [{"lang": "en", "value": "CWE-126"}],
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "v31score": 7.5,
            "v31vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "v31severity": "HIGH",
            "v31attackVector": "NETWORK",
            "v31attackComplexity": "LOW",
            "v31privilegesRequired": "NONE",
            "v31userInteraction": "NONE",
            "v31scope": "UNCHANGED",
            "v31confidentialityImpact": "HIGH",
            "v31integrityImpact": "NONE",
            "v31availabilityImpact": "NONE",
            "v31exploitability": 3.9,
            "v31impactScore": 3.6,
            "score": ["V31", 7.5, "HIGH"],
        },
    )

    return test_data_reduced


@pytest.fixture
def mock_normalization(monkeypatch):
    normalized_file_patch = mock_open(read_data="126,125\n130,Other")
    monkeypatch.setattr(builtins, "open", normalized_file_patch)


@pytest.fixture
def mock_normalization_type_error(monkeypatch):
    normalized_file_patch = mock_open(read_data="126,125\n130,Bad")
    monkeypatch.setattr(builtins, "open", normalized_file_patch)


@pytest.fixture
def mock_normalization_file_not_found_error(monkeypatch):
    normalized_file_patch = mock_open(read_data="126,125\n130,Bad")
    normalized_file_patch.side_effect = FileNotFoundError
    monkeypatch.setattr(builtins, "open", normalized_file_patch)


@pytest.fixture
def mock_normalization_permission_error(monkeypatch):
    normalized_file_patch = mock_open(read_data="126,125\n130,Bad")
    normalized_file_patch.side_effect = PermissionError
    monkeypatch.setattr(builtins, "open", normalized_file_patch)


@pytest.fixture
def example_cve_data_rejected() -> nvd_classes.CVE:

    # Using API return of CVE-2021-29633 for rejected example with metrics added
    test_data_rejected = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2021-29633",
            "sourceIdentifier": "secteam@freebsd.org",
            "published": "2024-02-15T06:15:44.667",
            "lastModified": "2024-02-15T06:15:44.667",
            "vulnStatus": "Rejected",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Rejected reason: This candidate was in a CNA pool that was not assigned to any issues during 2021.",
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "availabilityImpact": "NONE",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 3.6,
                    }
                ],
            },
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-125"}],
                }
            ],
            "cwe": [{"lang": "en", "value": "CWE-125"}],
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "v31score": 7.5,
            "v31vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "v31severity": "HIGH",
            "v31attackVector": "NETWORK",
            "v31attackComplexity": "LOW",
            "v31privilegesRequired": "NONE",
            "v31userInteraction": "NONE",
            "v31scope": "UNCHANGED",
            "v31confidentialityImpact": "HIGH",
            "v31integrityImpact": "NONE",
            "v31availabilityImpact": "NONE",
            "v31exploitability": 3.9,
            "v31impactScore": 3.6,
            "score": ["V31", 7.5, "HIGH"],
        },
    )

    return test_data_rejected


@pytest.fixture
def example_cve_data_cwe_unsure() -> nvd_classes.CVE:
    # Using API return of Heartbleed CVE as an example, some unrelated fields have been selectively removed.
    test_data_unsure = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "sourceIdentifier": "secalert@redhat.com",
            "published": "2014-04-07T22:55:03.893",
            "lastModified": "2023-11-07T02:18:10.590",
            "vulnStatus": "Modified",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Test",
                },
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "availabilityImpact": "NONE",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 3.6,
                    }
                ],
            },
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "UNSURE"}],
                }
            ],
            "cwe": [{"lang": "en", "value": "UNSURE"}],
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "v31score": 7.5,
            "v31vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "v31severity": "HIGH",
            "v31attackVector": "NETWORK",
            "v31attackComplexity": "LOW",
            "v31privilegesRequired": "NONE",
            "v31userInteraction": "NONE",
            "v31scope": "UNCHANGED",
            "v31confidentialityImpact": "HIGH",
            "v31integrityImpact": "NONE",
            "v31availabilityImpact": "NONE",
            "v31exploitability": 3.9,
            "v31impactScore": 3.6,
            "score": ["V31", 7.5, "HIGH"],
        },
    )

    return test_data_unsure


@pytest.fixture
def example_cve_data_multi_cwe() -> nvd_classes.CVE:
    # Using API return of Heartbleed CVE as an example, some unrelated fields have been selectively removed.
    test_data_multi_cwe = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "sourceIdentifier": "secalert@redhat.com",
            "published": "2014-04-07T22:55:03.893",
            "lastModified": "2023-11-07T02:18:10.590",
            "vulnStatus": "Modified",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Test",
                },
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "availabilityImpact": "NONE",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 3.6,
                    }
                ],
            },
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-125 CWE-126"}],
                }
            ],
            "cwe": [{"lang": "en", "value": "CWE-125 CWE-126"}],
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "v31score": 7.5,
            "v31vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "v31severity": "HIGH",
            "v31attackVector": "NETWORK",
            "v31attackComplexity": "LOW",
            "v31privilegesRequired": "NONE",
            "v31userInteraction": "NONE",
            "v31scope": "UNCHANGED",
            "v31confidentialityImpact": "HIGH",
            "v31integrityImpact": "NONE",
            "v31availabilityImpact": "NONE",
            "v31exploitability": 3.9,
            "v31impactScore": 3.6,
            "score": ["V31", 7.5, "HIGH"],
        },
    )

    return test_data_multi_cwe


@pytest.fixture
def example_cve_data_bad_cwe() -> nvd_classes.CVE:

    # Using API return of Heartbleed CVE as an example, some unrelated fields have been selectively removed.
    test_data_bad = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "sourceIdentifier": "secalert@redhat.com",
            "published": "2014-04-07T22:55:03.893",
            "lastModified": "2023-11-07T02:18:10.590",
            "vulnStatus": "Modified",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Test",
                },
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "availabilityImpact": "NONE",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 3.6,
                    }
                ],
            },
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-TEST"}],
                }
            ],
            "cwe": [{"lang": "en", "value": "CWE-TEST"}],
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "v31score": 7.5,
            "v31vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "v31severity": "HIGH",
            "v31attackVector": "NETWORK",
            "v31attackComplexity": "LOW",
            "v31privilegesRequired": "NONE",
            "v31userInteraction": "NONE",
            "v31scope": "UNCHANGED",
            "v31confidentialityImpact": "HIGH",
            "v31integrityImpact": "NONE",
            "v31availabilityImpact": "NONE",
            "v31exploitability": 3.9,
            "v31impactScore": 3.6,
            "score": ["V31", 7.5, "HIGH"],
        },
    )

    return test_data_bad


@pytest.fixture
def example_cve_data_empty_cwe() -> nvd_classes.CVE:

    # Using API return of Heartbleed CVE as an example, some unrelated fields have been selectively removed.
    test_data_empty = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "sourceIdentifier": "secalert@redhat.com",
            "published": "2014-04-07T22:55:03.893",
            "lastModified": "2023-11-07T02:18:10.590",
            "vulnStatus": "Modified",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Test",
                },
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "availabilityImpact": "NONE",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 3.6,
                    }
                ],
            },
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": " "}],
                }
            ],
            "cwe": [{"lang": "en", "value": " "}],
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "v31score": 7.5,
            "v31vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "v31severity": "HIGH",
            "v31attackVector": "NETWORK",
            "v31attackComplexity": "LOW",
            "v31privilegesRequired": "NONE",
            "v31userInteraction": "NONE",
            "v31scope": "UNCHANGED",
            "v31confidentialityImpact": "HIGH",
            "v31integrityImpact": "NONE",
            "v31availabilityImpact": "NONE",
            "v31exploitability": 3.9,
            "v31impactScore": 3.6,
            "score": ["V31", 7.5, "HIGH"],
        },
    )

    return test_data_empty


@pytest.fixture
def example_calculator(example_cve_data) -> ec3.calculator.Cvss31Calculator:

    # Initialize a Cvss31Calculator using example data
    test_calculator = ec3.calculator.Cvss31Calculator()
    test_calculator.set_vulnerability_data([example_cve_data])

    return test_calculator


@pytest.fixture
def example_normalized_calculator(
    mock_normalization, example_cve_data_to_normalize
) -> ec3.calculator.Cvss31Calculator:

    # Initialize a Cvss31Calculator using example data
    test_normalized_calculator = ec3.calculator.Cvss31Calculator(
        normalization_file_str="/fake/file.csv"
    )
    test_normalized_calculator.set_vulnerability_data([example_cve_data_to_normalize])

    return test_normalized_calculator


@pytest.fixture
def example_calculator_mock_normalized(
    mock_normalization, example_cve_data
) -> ec3.calculator.Cvss31Calculator:

    # Initialize a Cvss31Calculator using example data
    test_calculator = ec3.calculator.Cvss31Calculator()
    test_calculator.set_vulnerability_data([example_cve_data])

    return test_calculator


@pytest.fixture
def example_results(example_cve_data) -> dict:

    # Initialize a Cvss31Calculator using example data
    test_calculator = ec3.calculator.Cvss31Calculator()
    test_calculator.set_vulnerability_data([example_cve_data])
    ec3_results = test_calculator.calculate_results(125)

    return ec3_results


@pytest.fixture
def example_results_normalized(
    example_normalized_calculator,
    example_cve_data,
) -> dict:
    example_normalized_calculator.set_vulnerability_data([example_cve_data])
    ec3_results = example_normalized_calculator.calculate_results(126, normalize=True)
    return ec3_results


def test_init_support_defaults_false():
    test_calculator = ec3.calculator.Cvss31Calculator(support_defaults=False)
    assert not test_calculator.cwe_data


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_init_bad_support_defaults(mock_unpickle, example_cve_data):
    mock_unpickle.return_value = [example_cve_data]
    test_calculator = ec3.calculator.Cvss31Calculator(support_defaults="bad")

    # Changes back to default value of True
    assert test_calculator.cwe_data[125]


def test_build_cwe_table(example_calculator):
    assert example_calculator.cwe_data[125]


def test_build_cwe_table_rejected(example_calculator, example_cve_data_rejected):
    example_calculator.set_vulnerability_data([example_cve_data_rejected])
    assert not example_calculator.cwe_data


def test_build_cwe_table_unsure(example_calculator, example_cve_data_cwe_unsure):
    example_calculator.set_vulnerability_data([example_cve_data_cwe_unsure])
    assert not example_calculator.cwe_data


def test_build_cwe_table_multi_cwe(example_calculator, example_cve_data_multi_cwe):
    example_calculator.set_vulnerability_data([example_cve_data_multi_cwe])
    assert example_calculator.cwe_data[125] and example_calculator.cwe_data[126]


def test_build_cwe_table_empty(example_calculator):
    assert not example_calculator.cwe_data[126]


def test_build_cwe_table_cwe_empty_value(
    example_calculator, example_cve_data_empty_cwe
):
    example_calculator.set_vulnerability_data([example_cve_data_empty_cwe])
    assert not example_calculator.cwe_data


def test_build_cwe_table_bad_value(
    caplog, example_calculator, example_cve_data_bad_cwe
):
    example_calculator.set_vulnerability_data([example_cve_data_bad_cwe])
    assert (
        "Encountered error while parsing CWE ID from vulnerability data. Skipping this entry."
        in caplog.text
    )


def test_calculate_results(example_calculator):

    # Get default results dictionary.
    assert example_calculator.calculate_results(125).get("Projected CVSS") == 7.5


def test_calculate_results_verbose(example_calculator):

    # Set calculator verbose mode to get wider results.
    assert example_calculator.calculate_results(125) == {
        "Projected CVSS": 7.5,
        "CWE": 125,
        "Count": 1,
        "Min CVSS Base Score": 7.5,
        "Max CVSS Base Score": 7.5,
        "Average CVSS Base Score": 7.5,
        "Standard Deviation CVSS Base Score": 0.0,
        "CVE Records": ["CVE-2014-0160"],
    }


def test_calculate_results_empty_verbose(caplog, example_calculator):
    caplog.set_level(logging.DEBUG)
    example_calculator.calculate_results(1000)
    assert "No vulnerability data found for CWE ID 1000." in caplog.text


def test_calculate_results_negative_id_verbose(caplog, example_calculator):
    caplog.set_level(logging.DEBUG)
    example_calculator.calculate_results(-1)
    assert "CWE ID provided was not a usable ID." in caplog.text


def test_calculate_results_invalid_cwe_id_verbose(caplog, example_calculator):
    caplog.set_level(logging.DEBUG)
    example_calculator.calculate_results("bad")
    assert "Caught ValueError. CWE ID provided was not a usable ID." in caplog.text


def test_output_results(caplog, example_calculator, example_results):
    caplog.set_level(logging.DEBUG)
    example_calculator.output_results(example_results)
    print(caplog.text)
    assert "Calculating CVSS for CWE ID 125:" in caplog.text
    assert "Projected CVSS: 7.5" in caplog.text


def test_output_results_verbose(caplog, example_calculator, example_results):
    caplog.set_level(logging.DEBUG)
    example_calculator.output_results(example_results)
    assert "Projected CVSS: 7.5" in caplog.text
    assert " Min: 7.5" in caplog.text
    assert " Max: 7.5" in caplog.text
    assert " Average: 7.5" in caplog.text
    assert "Found 1 related CVE record:" in caplog.text
    assert "CVE-2014-0160" in caplog.text


def test_set_cvss_modifiers(example_calculator):

    # Default vector for calculation: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/
    assert example_calculator.calculate_results(125).get("Projected CVSS") == 7.5
    example_calculator.set_cvss_modifiers(mav="P", cr="H")

    # Modified vector for calculation: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/CR:H/MAV:P
    assert example_calculator.calculate_results(125).get("Projected CVSS") == 6.4


def test_set_cvss_modifiers_all(example_calculator):

    # Override all metric values.
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/
    #   E:F/RL:U/RC:R/
    #   CR:H/IR:M/AR:M/MAV:P/MAC:L/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:L
    example_calculator.set_cvss_modifiers(
        e="F",
        rl="U",
        rc="R",
        cr="H",
        ir="M",
        ar="M",
        mav="P",
        mac="L",
        mpr="L",
        mui="R",
        ms="U",
        mc="L",
        mi="L",
        ma="L",
    )
    assert example_calculator.calculate_results(125).get("Projected CVSS") == 4.1


def test_build_cwe_table_value_error(example_calculator):

    # Cause a ValueError exception
    with pytest.raises(ValueError):
        example_calculator.set_cvss_modifiers(mav="?")


def test_set_vulnerability_data_type_error(example_calculator):

    # Cause a TypeError exception
    with pytest.raises(TypeError):
        example_calculator.set_vulnerability_data(["abc", "def"])


def test_set_normalization_data_type_error(example_calculator):
    with pytest.raises(TypeError):
        example_calculator.set_normalization_data([[125, "Bad"]])


def test_normalize_cwe_id(caplog, example_normalized_calculator):
    caplog.set_level(logging.DEBUG)
    example_normalized_calculator.normalize_cwe(126)
    assert "CWE ID 126 matched normalization ID 125." in caplog.text


def test_output_results_normalized(
    caplog, example_normalized_calculator, example_results_normalized
):
    # example_results_normalized called with normalization against CWE-126(->125)
    caplog.set_level(logging.DEBUG)
    example_normalized_calculator.output_results(example_results_normalized)
    print(caplog.text)
    assert "Calculating CVSS for CWE ID 125:" in caplog.text
    assert "Projected CVSS: 7.5" in caplog.text


def test_load_normalize_file_none(caplog, example_calculator_mock_normalized):
    caplog.set_level(logging.DEBUG)

    # Initialization sets file to default value.
    # Call directly with no parameters to send None
    example_calculator_mock_normalized.load_normalization_file()
    assert (
        "No normalization file provided, setting to default file: ./data/normalized.csv"
        in caplog.text
    )


def test_load_normalize_file_type_error(caplog, mock_normalization_type_error):
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator(
        normalization_file_str="/fake/file"
    )
    assert (
        "Caught TypeError. Input normalization file not in the correct format."
        in caplog.text
    )


def test_normalize_cwe_value_error(caplog, example_cve_data):
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator()
    test_calculator.set_vulnerability_data([example_cve_data])
    test_calculator.raw_normalization_data = [[125, "Bad"]]
    test_calculator.calculate_results(125, True)
    assert (
        "Caught ValueError. CWE ID found, but normalized value is not a usable ID."
        in caplog.text
    )


def test_load_normalize_file_not_found_error(
    caplog, mock_normalization_file_not_found_error
):
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator(
        normalization_file_str="/fake/file"
    )
    assert (
        "Caught FileNotFoundError. Input normalization file not found." in caplog.text
    )


def test_load_normalize_permission_error(caplog, mock_normalization_permission_error):
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator(
        normalization_file_str="/fake/file"
    )
    assert "Caught PermissionError. Unable to read normalization file." in caplog.text


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_normalization_file_blank(
    mock_unpickle, mock_normalization, caplog, example_cve_data
):
    mock_unpickle.return_value = [example_cve_data]
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator(normalization_file_str="")

    assert [126, "125"] in test_calculator.raw_normalization_data


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_unpickler(mock_unpickle, caplog, example_cve_data):
    mock_unpickle.return_value = [example_cve_data]
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator("/fake/file")

    assert test_calculator.cwe_data[125]


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_unpickler_data_file_None(mock_unpickle, caplog, example_cve_data):
    mock_unpickle.return_value = [example_cve_data]
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator()

    # Initialization sets file to default value.
    # Call directly with no parameters to send None
    test_calculator.load_data_file()

    assert (
        "No data file provided, setting to default file: ./data/nvd_loaded.pickle"
        in caplog.text
    )


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_load_data_file_not_found_error(
    mock_unpickle, caplog, example_cve_data
):
    mock_unpickle.side_effect = FileNotFoundError
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator()

    assert "Caught FileNotFoundError. Input file not found." in caplog.text


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_load_data_permission_error(mock_unpickle, caplog, example_cve_data):
    mock_unpickle.side_effect = PermissionError
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator()

    assert "Caught PermissionError. Unable to read data file." in caplog.text


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_load_data_permission_error(mock_unpickle, caplog, example_cve_data):
    mock_unpickle.side_effect = PermissionError
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator()

    assert "Caught PermissionError. Unable to read data file." in caplog.text


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_load_data_unpickling_error(mock_unpickle, caplog, example_cve_data):
    mock_unpickle.side_effect = pickle.UnpicklingError
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator()

    assert (
        "Caught UnpicklingError. Input file not in correct pickle format."
        in caplog.text
    )


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_unpickler_data_file_blank(mock_unpickle, caplog, example_cve_data):
    mock_unpickle.return_value = [example_cve_data]
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator("")

    assert test_calculator.cwe_data[125]


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_unpickler_type_error(mock_unpickle, caplog, example_cve_data):
    mock_unpickle.return_value = [example_cve_data]
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator("")

    assert test_calculator.cwe_data[125]
