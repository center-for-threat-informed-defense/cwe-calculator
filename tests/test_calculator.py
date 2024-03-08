import pytest
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

    # Initialize a non-verbose Cvss31Calculator using example data
    test_calculator = ec3.calculator.Cvss31Calculator(125)
    test_calculator.set_vulnerability_data([example_cve_data])
    test_calculator.build_cwe_table()

    return test_calculator


@pytest.fixture
def example_results(example_cve_data) -> dict:

    # Initialize a non-verbose Cvss31Calculator using example data
    test_calculator = ec3.calculator.Cvss31Calculator(125)
    test_calculator.set_vulnerability_data([example_cve_data])
    test_calculator.build_cwe_table()
    ec3_results = test_calculator.calculate_results(125)

    return ec3_results


def test_init_verbose():
    # Initialize a verbose Cvss31Calculator
    test_calculator = ec3.calculator.Cvss31Calculator(125, True)
    assert test_calculator.verbose == True


def test_init_value_error():

    # Cause a ValueError exception
    with pytest.raises(ValueError):
        # Initialize a non-verbose Cvss31Calculator with a bad numerical CWE ID value
        test_calculator = ec3.calculator.Cvss31Calculator(-1)


def test_cwe_id_valid_value_error(example_calculator):

    # Cause a ValueError exception
    with pytest.raises(ValueError):
        # Pass a non-valid ID to the Cvss31Calculator constructor
        test_calculator = ec3.calculator.Cvss31Calculator("BAD")


def test_build_cwe_table(example_calculator):
    example_calculator.build_cwe_table()
    assert example_calculator.cwe_data[125]


def test_build_cwe_table_rejected(example_calculator, example_cve_data_rejected):
    example_calculator.set_vulnerability_data([example_cve_data_rejected])
    example_calculator.build_cwe_table()
    assert not example_calculator.cwe_data


def test_build_cwe_table_unsure(example_calculator, example_cve_data_cwe_unsure):
    example_calculator.set_vulnerability_data([example_cve_data_cwe_unsure])
    example_calculator.build_cwe_table()
    assert not example_calculator.cwe_data


def test_build_cwe_table_multi_cwe(example_calculator, example_cve_data_multi_cwe):
    example_calculator.set_vulnerability_data([example_cve_data_multi_cwe])
    example_calculator.build_cwe_table()
    assert example_calculator.cwe_data[125] and example_calculator.cwe_data[126]


def test_build_cwe_table_empty(example_calculator):
    assert not example_calculator.cwe_data[126]


def test_build_cwe_table_cwe_empty_value(
    example_calculator, example_cve_data_empty_cwe
):
    example_calculator.set_vulnerability_data([example_cve_data_empty_cwe])
    example_calculator.build_cwe_table()
    assert not example_calculator.cwe_data


def test_build_cwe_table_bad_value(
    capsys, example_calculator, example_cve_data_bad_cwe
):
    example_calculator.set_vulnerability_data([example_cve_data_bad_cwe])
    example_calculator.build_cwe_table()
    captured = capsys.readouterr()
    assert str(captured.out).__contains__(
        "Encountered error while parsing CWE ID from vulnerability data. Skipping this entry."
    )


def test_calculate_results(example_calculator):

    # Get default results dictionary.
    assert example_calculator.calculate_results(125).get("Projected CVSS") == 7.5


def test_calculate_results_verbose(example_calculator):

    # Set calculator verbose mode to get wider results.
    example_calculator.verbose = True
    assert example_calculator.calculate_results(125) == {
        "Projected CVSS": 7.5,
        "CWE": 125,
        "Count": 1,
        "Min CVSS Base Score": 7.5,
        "Max CVSS Base Score": 7.5,
        "Average CVSS Base Score": 7.5,
        "CVE Records": ["CVE-2014-0160"],
    }


def test_calculate_results_empty_verbose(capsys, example_calculator):

    # Set calculator verbose mode to capture more edge case output.
    example_calculator.verbose = True
    example_calculator.calculate_results(1000)
    captured = capsys.readouterr()
    assert str(captured.out).__contains__(
        "No vulnerability data found for CWE ID 1000."
    )


def test_calculate_results_bad_id_verbose(capsys, example_calculator):

    # Set calculator verbose mode to capture more error output.
    example_calculator.verbose = True
    example_calculator.calculate_results(-1)
    captured = capsys.readouterr()
    assert str(captured.out).__contains__("CWE ID provided was not a usable ID.")


def test_output_results(capsys, example_calculator, example_results):

    example_calculator.output_results(example_results)
    captured = capsys.readouterr()
    assert str(captured.out).__contains__(
        "Vulnerability data found for CWE ID 125. Projected CVSS: 7.5"
    )


def test_output_results_verbose(capsys, example_calculator, example_results):
    example_calculator.verbose = True
    example_calculator.output_results(example_results)
    captured = capsys.readouterr()
    assert str(captured.out).__contains__(
        "Vulnerability data found for CWE ID 125:\nProjected CVSS: 7.5"
    )
    assert str(captured.out).__contains__(" Min: 7.5\n Max: 7.5\n Average: 7.5")
    assert str(captured.out).__contains__("Found 1 related CVE record:\nCVE-2014-0160")


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
        example_calculator.build_cwe_table()


def test_set_vulnerability_data_type_error(example_calculator):

    # Cause a TypeError exception
    with pytest.raises(TypeError):
        example_calculator.set_vulnerability_data(["abc", "def"])
