import pytest
from nvdlib import classes as nvd_classes


@pytest.fixture
def example_cve_data() -> nvd_classes.CVE:

    # Using API return of Heartbleed CVE as an example,
    # some unrelated fields have been selectively removed.
    test_data_reduced = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "vulnStatus": "Modified",
            "metrics": {},
            "cwe": [{"lang": "en", "value": "CWE-125"}],
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

    # Using API return of Heartbleed CVE as an example,
    # some unrelated fields have been selectively removed.
    test_data_reduced = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "vulnStatus": "Modified",
            "metrics": {},
            "cwe": [{"lang": "en", "value": "CWE-126"}],
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
def example_cve_data_rejected() -> nvd_classes.CVE:

    # Using API return of CVE-2021-29633 for rejected example with metrics added
    test_data_rejected = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2021-29633",
            "vulnStatus": "Rejected",
            "metrics": {},
            "cwe": [{"lang": "en", "value": "CWE-125"}],
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
    # Using API return of Heartbleed CVE as an example,
    # some unrelated fields have been selectively removed.
    test_data_unsure = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "vulnStatus": "Modified",
            "metrics": {},
            "cwe": [{"lang": "en", "value": "UNSURE"}],
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
    # Using API return of Heartbleed CVE as an example,
    # some unrelated fields have been selectively removed.
    test_data_multi_cwe = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "vulnStatus": "Modified",
            "metrics": {},
            "cwe": [{"lang": "en", "value": "CWE-125 CWE-126"}],
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

    # Using API return of Heartbleed CVE as an example,
    # some unrelated fields have been selectively removed.
    test_data_bad = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "vulnStatus": "Modified",
            "metrics": {},
            "cwe": [{"lang": "en", "value": "CWE-TEST"}],
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

    # Using API return of Heartbleed CVE as an example,
    # some unrelated fields have been selectively removed.
    test_data_empty = nvd_classes.__convert(
        product="cve",
        CVEID={
            "id": "CVE-2014-0160",
            "vulnStatus": "Modified",
            "metrics": {},
            "cwe": [{"lang": "en", "value": " "}],
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
def example_cve_data_as_json() -> dict:
    return {
        "vulnerabilities": [
            # Has metrics
            {
                "cve": {
                    "id": "CVE-2014-0160",
                    "vulnStatus": "Modified",
                    "metrics": {},
                    "cwe": [{"lang": "en", "value": "CWE-125"}],
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
                }
            },
            # Has no metrics
            {
                "cve": {
                    "id": "CVE-2014-0160",
                    "vulnStatus": "Modified",
                    "cwe": [{"lang": "en", "value": "CWE-126"}],
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
                }
            },
        ]
    }
