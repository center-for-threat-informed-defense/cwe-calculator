import pytest


def test_build_cwe_table(example_calculator):
    assert example_calculator.cwe_data[125]


def test_build_cwe_table_empty(example_calculator):
    assert not example_calculator.cwe_data[126]


def test_build_cwe_table_rejected(example_calculator, example_cve_data_rejected):
    example_calculator.set_vulnerability_data([example_cve_data_rejected])
    assert not example_calculator.cwe_data


def test_build_cwe_table_unsure(example_calculator, example_cve_data_cwe_unsure):
    example_calculator.set_vulnerability_data([example_cve_data_cwe_unsure])
    assert not example_calculator.cwe_data


def test_build_cwe_table_multi_cwe(example_calculator, example_cve_data_multi_cwe):
    example_calculator.set_vulnerability_data([example_cve_data_multi_cwe])
    assert example_calculator.cwe_data[125] and example_calculator.cwe_data[126]


def test_build_cwe_table_cwe_empty_value(
    example_calculator, example_cve_data_empty_cwe
):
    example_calculator.set_vulnerability_data([example_cve_data_empty_cwe])
    assert not example_calculator.cwe_data


def test_build_cwe_table_bad_value(
    caplog, example_calculator, example_cve_data_bad_cwe
):
    example_calculator.set_vulnerability_data([example_cve_data_bad_cwe])
    assert (
        "Encountered error while parsing CWE ID from vulnerability data. "
        "Skipping this entry." in caplog.text
    )


def test_build_cwe_table_value_error(example_calculator):

    # Cause a ValueError exception
    with pytest.raises(ValueError):
        example_calculator.set_cvss_modifiers(mav="?")
