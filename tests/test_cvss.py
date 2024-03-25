import pytest
from nvdlib import classes as nvd_classes

import ec3.cvss


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
def example_non_cvss_cve_data() -> nvd_classes.CVE:

    # Using API return of Heartbleed CVE as an example, some unrelated fields have been selectively removed.
    no_cvss_test_data = nvd_classes.__convert(
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
            "metrics": {},
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-125"}],
                }
            ],
            "cwe": [{"lang": "en", "value": "CWE-125"}],
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
        },
    )

    return no_cvss_test_data


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
        ec3.cvss.Cvss31.from_cve(example_bad_cve_data)


def test_from_cve_no_cvss(example_non_cvss_cve_data):

    # Test that values such as "TEST" raise a ValueError during conversion
    with pytest.raises(ValueError):
        ec3.cvss.Cvss31.from_cve(example_non_cvss_cve_data)


def test_get_temporal_score(example_full_cvss):
    assert example_full_cvss.get_temporal_score() == 7.0


def test_base_invalid(example_base_cvss):
    example_base_cvss.av = None
    assert not example_base_cvss.base_valid()


def test_get_base_score_invalid(example_base_cvss):
    example_base_cvss.av = None
    with pytest.raises(ValueError):
        example_base_cvss.get_base_score()


def test_get_temporal_score_invalid(example_base_cvss):
    example_base_cvss.av = None
    with pytest.raises(ValueError):
        example_base_cvss.get_temporal_score()


def test_get_environmental_score_invalid(example_base_cvss):
    example_base_cvss.av = None
    with pytest.raises(ValueError):
        example_base_cvss.get_environmental_score()


def test_set_av_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_av(None)
    with pytest.raises(ValueError):
        example_base_cvss.set_av("?")


def test_set_ac_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_ac(None)
    with pytest.raises(ValueError):
        example_base_cvss.set_ac("?")


def test_set_pr_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_pr(None)
    with pytest.raises(ValueError):
        example_base_cvss.set_pr("?")


def test_set_ui_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_ui(None)
    with pytest.raises(ValueError):
        example_base_cvss.set_ui("?")


def test_set_s_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_s(None)
    with pytest.raises(ValueError):
        example_base_cvss.set_s("?")


def test_set_c_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_c(None)
    with pytest.raises(ValueError):
        example_base_cvss.set_c("?")


def test_set_i_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_i(None)
    with pytest.raises(ValueError):
        example_base_cvss.set_i("?")


def test_set_a_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_a(None)
    with pytest.raises(ValueError):
        example_base_cvss.set_a("?")


def test_set_e_values(example_base_cvss):
    example_base_cvss.set_e("HIGH")
    assert example_base_cvss.e == "H"
    example_base_cvss.set_e("NOT_DEFINED")
    assert example_base_cvss.e == "X"
    example_base_cvss.set_e(None)
    assert example_base_cvss.e == "X"


def test_set_e_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_e("?")


def test_set_rl_values(example_base_cvss):
    example_base_cvss.set_rl("WORKAROUND")
    assert example_base_cvss.rl == "W"
    example_base_cvss.set_rl("NOT_DEFINED")
    assert example_base_cvss.rl == "X"
    example_base_cvss.set_rl(None)
    assert example_base_cvss.rl == "X"


def test_set_rl_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_rl("?")


def test_set_rc_values(example_base_cvss):
    example_base_cvss.set_rc("CONFIRMED")
    assert example_base_cvss.rc == "C"
    example_base_cvss.set_rc("NOT_DEFINED")
    assert example_base_cvss.rc == "X"
    example_base_cvss.set_rc(None)
    assert example_base_cvss.rc == "X"


def test_set_rc_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_rc("?")


def test_set_cr_values(example_base_cvss):
    example_base_cvss.set_cr("HIGH")
    assert example_base_cvss.cr == "H"
    example_base_cvss.set_cr("NOT_DEFINED")
    assert example_base_cvss.cr == "X"
    example_base_cvss.set_cr(None)
    assert example_base_cvss.cr == "X"


def test_set_cr_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_cr("?")


def test_set_ir_values(example_base_cvss):
    example_base_cvss.set_ir("HIGH")
    assert example_base_cvss.ir == "H"
    example_base_cvss.set_ir("NOT_DEFINED")
    assert example_base_cvss.ir == "X"
    example_base_cvss.set_ir(None)
    assert example_base_cvss.ir == "X"


def test_set_ir_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_ir("?")


def test_set_ar_values(example_base_cvss):
    example_base_cvss.set_ar("HIGH")
    assert example_base_cvss.ar == "H"
    example_base_cvss.set_ar("NOT_DEFINED")
    assert example_base_cvss.ar == "X"
    example_base_cvss.set_ar(None)
    assert example_base_cvss.ar == "X"


def test_set_ar_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_ar("?")


def test_set_mav_values(example_base_cvss):
    example_base_cvss.set_mav("PHYSICAL")
    assert example_base_cvss.mav == "P"
    example_base_cvss.set_mav("NOT_DEFINED")
    assert example_base_cvss.mav == "X"
    example_base_cvss.set_mav(None)
    assert example_base_cvss.mav == "X"


def test_set_mav_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_mav("?")


def test_set_mac_values(example_base_cvss):
    example_base_cvss.set_mac("HIGH")
    assert example_base_cvss.mac == "H"
    example_base_cvss.set_mac("NOT_DEFINED")
    assert example_base_cvss.mac == "X"
    example_base_cvss.set_mac(None)
    assert example_base_cvss.mac == "X"


def test_set_mac_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_mac("?")


def test_set_mpr_values(example_base_cvss):
    example_base_cvss.set_mpr("HIGH")
    assert example_base_cvss.mpr == "H"
    example_base_cvss.set_mpr("NOT_DEFINED")
    assert example_base_cvss.mpr == "X"
    example_base_cvss.set_mpr(None)
    assert example_base_cvss.mpr == "X"


def test_set_mpr_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_mpr("?")


def test_set_mui_values(example_base_cvss):
    example_base_cvss.set_mui("REQUIRED")
    assert example_base_cvss.mui == "R"
    example_base_cvss.set_mui("NOT_DEFINED")
    assert example_base_cvss.mui == "X"
    example_base_cvss.set_mui(None)
    assert example_base_cvss.mui == "X"


def test_set_mui_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_mui("?")


def test_set_ms_values(example_base_cvss):
    example_base_cvss.set_ms("CHANGED")
    assert example_base_cvss.ms == "C"
    example_base_cvss.set_ms("NOT_DEFINED")
    assert example_base_cvss.ms == "X"
    example_base_cvss.set_ms(None)
    assert example_base_cvss.ms == "X"


def test_set_ms_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_ms("?")


def test_set_mc_values(example_base_cvss):
    example_base_cvss.set_mc("HIGH")
    assert example_base_cvss.mc == "H"
    example_base_cvss.set_mc("NOT_DEFINED")
    assert example_base_cvss.mc == "X"
    example_base_cvss.set_mc(None)
    assert example_base_cvss.mc == "X"


def test_set_mc_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_mc("?")


def test_set_mi_values(example_base_cvss):
    example_base_cvss.set_mi("HIGH")
    assert example_base_cvss.mi == "H"
    example_base_cvss.set_mi("NOT_DEFINED")
    assert example_base_cvss.mi == "X"
    example_base_cvss.set_mi(None)
    assert example_base_cvss.mi == "X"


def test_set_mi_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_mi("?")


def test_set_ma_values(example_base_cvss):
    example_base_cvss.set_ma("HIGH")
    assert example_base_cvss.ma == "H"
    example_base_cvss.set_ma("NOT_DEFINED")
    assert example_base_cvss.ma == "X"
    example_base_cvss.set_ma(None)
    assert example_base_cvss.ma == "X"


def test_set_ma_bad_values(example_base_cvss):
    with pytest.raises(ValueError):
        example_base_cvss.set_ma("?")
