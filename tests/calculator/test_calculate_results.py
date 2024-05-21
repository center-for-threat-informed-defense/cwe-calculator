import logging


def test_calculate_results(example_calculator):

    # Get default results dictionary.
    assert example_calculator.calculate_results(125).get("projected_cvss") == 7.5


def test_calculate_results_verbose(example_calculator):

    # Set calculator verbose mode to get wider results.
    assert example_calculator.calculate_results(125) == {
        "projected_cvss": 7.5,
        "cwe": 125,
        "count": 1,
        "min_cvss_base_score": 7.5,
        "max_cvss_base_score": 7.5,
        "avg_cvss_base_score": 7.5,
        "std_dev_cvss_base_score": 0.0,
        "cve_records": ["CVE-2014-0160"],
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
