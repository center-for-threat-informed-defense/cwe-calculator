from datetime import datetime, timedelta

import nvdlib
import pytest
from mock import patch
from nvdlib import classes as nvd_classes

import ec3.collector


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
            "score": ["V31", 7.5, "HIGH"],
        },
    )

    return test_data_reduced


@pytest.fixture
def example_collector() -> ec3.collector.NvdCollector:

    # Initialize an NvdCollector with no parameters.
    test_collector = ec3.collector.NvdCollector()
    return test_collector


@patch.object(nvdlib, "searchCVE")
def test_search_cve(mock_search_cve, example_cve_data):
    mock_search_cve.return_value = [example_cve_data]
    test_collector = ec3.collector.NvdCollector()
    assert test_collector.pull_target_data() == [example_cve_data]


@patch.object(nvdlib, "searchCVE")
def test_search_cve_scrolling(mock_search_cve, example_cve_data):
    mock_search_cve.return_value = [example_cve_data]
    test_collector = ec3.collector.NvdCollector(
        start_date=datetime.now() - timedelta(days=ec3.collector.max_date_range + 1),
        end_date=datetime.now(),
    )

    # Results will contain two instances of example_cve_data since the scrolling window
    # was set to one day past the max_date_range
    assert test_collector.pull_target_data() == [example_cve_data, example_cve_data]


def test_adjust_valid_dates_bounds():

    # Test adjust_valid_dates with bounds beyond the expected range.
    test_collector = ec3.collector.NvdCollector(
        start_date=datetime(1995, 10, 10, 0, 0, 0),
        end_date=datetime(2200, 11, 11, 0, 0, 0),
    )
    assert test_collector.start_date == datetime(2020, 1, 1, 0, 0, 0)
    assert test_collector.end_date <= datetime.now()


def test_adjust_valid_dates_swap():

    # Test adjust_valid_dates with bounds swapped and beyond expected ranges.
    test_collector = ec3.collector.NvdCollector(
        start_date=datetime(2200, 11, 11, 0, 0, 0),
        end_date=datetime(1995, 10, 10, 0, 0, 0),
    )
    assert test_collector.start_date <= datetime.now()
    assert test_collector.end_date <= datetime.now()


def test_save_data_to_file_error(example_collector, example_cve_data):
    with pytest.raises(FileNotFoundError):
        example_collector.save_data_to_file(
            new_data=[example_cve_data], data_file_str="./bad_path/bad_file_str"
        )
