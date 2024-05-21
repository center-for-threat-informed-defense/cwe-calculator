import logging

import ec3.calculator
import pytest
from mock import patch


def test_load_normalize_file_none(caplog, example_calculator_mock_normalized):
    caplog.set_level(logging.DEBUG)

    # Initialization sets file to default value.
    # Call directly with no parameters to send None
    example_calculator_mock_normalized.load_normalization_file()
    assert (
        "No normalization file provided, setting to default file: ./data/normalized.csv"
        in caplog.text
    )


def test_load_normalize_file_type_error(caplog, setup_mock_normalization_type_error):
    caplog.set_level(logging.DEBUG)
    ec3.calculator.Cvss31Calculator(normalization_file_str="/fake/file")
    assert (
        "Caught TypeError. "
        "Input normalization file not in the correct format." in caplog.text
    )


def test_load_normalize_file_not_found_error(
    caplog, setup_mock_normalization_file_not_found_error
):
    caplog.set_level(logging.DEBUG)
    ec3.calculator.Cvss31Calculator(normalization_file_str="/fake/file")
    assert (
        "Caught FileNotFoundError. "
        "Input normalization file not found." in caplog.text
    )


def test_load_normalize_permission_error(
    caplog, setup_mock_normalization_permission_error
):
    caplog.set_level(logging.DEBUG)
    ec3.calculator.Cvss31Calculator(normalization_file_str="/fake/file")
    assert "Caught PermissionError. Unable to read normalization file." in caplog.text


def test_set_normalization_data_type_error(example_calculator):
    with pytest.raises(TypeError):
        example_calculator.set_normalization_data([[125, "Bad"]])


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_normalization_file_blank(
    mock_unpickle, setup_mock_normalization, caplog, example_cve_data
):
    mock_unpickle.return_value = [example_cve_data]
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator(normalization_file_str="")

    assert [126, "125"] in test_calculator.raw_normalization_data
