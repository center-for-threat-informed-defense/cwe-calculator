import logging


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
