import logging


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


def test_output_results_normalized(
    caplog, example_normalized_calculator, example_results_normalized
):
    # example_results_normalized called with normalization against CWE-126(->125)
    caplog.set_level(logging.DEBUG)
    example_normalized_calculator.output_results(example_results_normalized)
    print(caplog.text)
    assert "Calculating CVSS for CWE ID 125:" in caplog.text
    assert "Projected CVSS: 7.5" in caplog.text
