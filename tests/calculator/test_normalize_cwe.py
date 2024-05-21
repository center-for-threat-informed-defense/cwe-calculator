import logging

import ec3.calculator


def test_normalize_cwe_id(caplog, example_normalized_calculator):
    caplog.set_level(logging.DEBUG)
    example_normalized_calculator.normalize_cwe(126)
    assert "CWE ID 126 matched normalization ID 125." in caplog.text


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
