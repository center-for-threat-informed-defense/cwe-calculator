import pytest

import ec3.cli
import ec3.collector
import ec3.calculator
from mock import patch
from datetime import datetime, timedelta
from nvdlib import classes as nvd_classes


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
            "evaluatorImpact": "CVSS V2 scoring evaluates the impact of the vulnerability on the host where the "
            "vulnerability is located. When evaluating the impact of this vulnerability to your "
            "organization, take into account the nature of the data that is being protected and act "
            "according to your organization’s risk acceptance. While CVE-2014-0160 does not allow "
            "unrestricted access to memory on the targeted host, a successful exploit does leak "
            "information from memory locations which have the potential to contain particularly "
            "sensitive information, e.g., cryptographic keys and passwords.  Theft of this "
            "information could enable other attacks on the information system, the impact of which "
            "would depend on the sensitivity of the data and functions of that system.",
            "cisaExploitAdd": "2022-05-04",
            "cisaActionDue": "2022-05-25",
            "cisaRequiredAction": "Apply updates per vendor instructions.",
            "cisaVulnerabilityName": "OpenSSL Information Disclosure Vulnerability",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly "
                    "handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive "
                    "information from process memory via crafted packets that trigger a buffer over-read, as "
                    "demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the "
                    "Heartbleed bug.",
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
            "v2score": 5.0,
            "v2vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "v2severity": "MEDIUM",
            "v2accessVector": "NETWORK",
            "v2accessComplexity": "LOW",
            "v2authentication": "NONE",
            "v2confidentialityImpact": "PARTIAL",
            "v2integrityImpact": "NONE",
            "v2availabilityImpact": "NONE",
            "v2exploitability": 10.0,
            "v2impactScore": 2.9,
            "score": ["V31", 7.5, "HIGH"],
        },
    )

    return test_data_reduced


@pytest.fixture
def example_simple_args() -> list[str]:

    # default non-verbose call to calculator.
    simple_args = ["125"]

    return simple_args


@pytest.fixture
def example_normalized_modified_args() -> list[str]:
    normalized_modified_args = [
        "121",
        "--data_file",
        ".\\data\\nvd_loaded.pickle",
        "--normalize_file",
        ".\\data\\normalized.csv",
        "-v",
        "-e",
        "H",
        "-mi",
        "L",
    ]

    return normalized_modified_args


@pytest.fixture
def example_collector_args() -> list[str]:
    collector_args = [
        "125",
        "--update",
        "--key",
        "test_api_key",
        "--target_range_start",
        "01-01-2024",
        "--target_range_end",
        "02-01-2024",
        "-v",
    ]

    return collector_args


def test_args_simple(example_simple_args):
    args = ec3.cli.parse_args(example_simple_args)
    assert args.cwe == 125


def test_args_normalized_modified(example_normalized_modified_args):
    args = ec3.cli.parse_args(example_normalized_modified_args)
    assert args.cwe == 121
    assert args.normalize_file is not None
    assert args.data_file is not None
    assert args.verbose
    assert args.exploit_code_maturity == "H"
    assert args.modified_integrity == "L"


@patch.object(ec3.collector.NvdCollector, "pull_target_data")
def test_main_collector(
    mock_pulled_data, capsys, example_collector_args, example_cve_data
):
    mock_pulled_data.return_value = [example_cve_data]
    ec3.cli.main(example_collector_args)
    captured = capsys.readouterr()
    assert str(captured.out).__contains__(
        "Initialized NvdCollector to search CVEs from 2024-01-01 00:00:00 until 2024-02-01 00:00:00."
    )
    assert str(captured.out).__contains__("Projected CVSS = 7.5")
