import pytest
from nvdlib import classes as nvd_classes

import ec3.cvss


@pytest.fixture
def example_cve_data() -> nvd_classes.CVE:

    # Using API return of Heartbleed CVE as an example, some unrelated fields have been selectively removed.
    test_data = nvd_classes.__convert(
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
            "score": ["V31", 7.5, "HIGH"],
        },
    )

    return test_data


@pytest.fixture
def example_bad_cve_data() -> nvd_classes.CVE:

    # Using API return of Heartbleed CVE as an example, some unrelated fields have been selectively removed.
    bad_test_data = nvd_classes.__convert(
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
                            "attackVector": "TEST",
                            "attackComplexity": "TEST",
                            "privilegesRequired": "TEST",
                            "userInteraction": "TEST",
                            "scope": "TEST",
                            "confidentialityImpact": "TEST",
                            "integrityImpact": "TEST",
                            "availabilityImpact": "TEST",
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
            "v31attackVector": "TEST",
            "v31attackComplexity": "TEST",
            "v31privilegesRequired": "TEST",
            "v31userInteraction": "TEST",
            "v31scope": "TEST",
            "v31confidentialityImpact": "TEST",
            "v31integrityImpact": "TEST",
            "v31availabilityImpact": "TEST",
            "v31exploitability": 3.9,
            "v31impactScore": 3.6,
            "score": ["V31", 7.5, "HIGH"],
        },
    )

    return bad_test_data


@pytest.fixture
def example_base_cvss() -> ec3.cvss.Cvss31:

    base_cvss = ec3.cvss.Cvss31(
        av="N",
        ac="L",
        pr="N",
        ui="N",
        s="U",
        c="H",
        i="N",
        a="N",
        verbose=True,
    )

    return base_cvss


@pytest.fixture
def example_full_cvss() -> ec3.cvss.Cvss31:

    # Initialize all metric values.
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/
    #   E:F/RL:U/RC:R/
    #   CR:H/IR:M/AR:M/MAV:P/MAC:L/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:L
    full_cvss = ec3.cvss.Cvss31(
        av="N",
        ac="L",
        pr="N",
        ui="N",
        s="U",
        c="H",
        i="N",
        a="N",
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
        verbose=True,
    )

    return full_cvss


def test_cvss_init(example_full_cvss):
    assert example_full_cvss.get_environmental_score() == 4.1


def test_display_cvss(capsys, example_base_cvss):
    print(example_base_cvss)
    captured = capsys.readouterr()
    assert str(captured.out) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N\n"
    print(repr(example_base_cvss))
    captured = capsys.readouterr()
    assert str(captured.out) == "'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'\n"


def test_display_full_cvss(capsys, example_full_cvss):
    print(example_full_cvss)
    captured = capsys.readouterr()
    assert str(captured.out) == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/"
        "E:F/RL:U/RC:R/"
        "CR:H/IR:M/AR:M/MAV:P/MAC:L/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:L\n"
    )
    print(repr(example_full_cvss))
    captured = capsys.readouterr()
    assert str(captured.out) == (
        "'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/"
        "E:F/RL:U/RC:R/"
        "CR:H/IR:M/AR:M/MAV:P/MAC:L/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:L'\n"
    )


def test_from_cve(example_cve_data):

    # Test default base CVSS example
    test_cvss = ec3.cvss.Cvss31.from_cve(example_cve_data)
    assert test_cvss.get_base_score() == 7.5


def test_from_cve_value_error(example_bad_cve_data):

    # Test that values such as "TEST" raise a ValueError during conversion
    with pytest.raises(ValueError):
        test_cvss = ec3.cvss.Cvss31.from_cve(example_bad_cve_data)


def test_get_temporal_score(example_full_cvss):
    assert example_full_cvss.get_temporal_score() == 7.0
