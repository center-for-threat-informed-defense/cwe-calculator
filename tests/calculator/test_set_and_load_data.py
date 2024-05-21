import json
import logging
import pickle

import ec3.calculator
import pytest
from mock import patch


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_load_data_file_not_found_error(mock_unpickle, caplog):
    mock_unpickle.side_effect = FileNotFoundError
    caplog.set_level(logging.DEBUG)
    ec3.calculator.Cvss31Calculator()

    assert "Caught FileNotFoundError. Input file not found." in caplog.text


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_load_data_permission_error(mock_unpickle, caplog):
    mock_unpickle.side_effect = PermissionError
    caplog.set_level(logging.DEBUG)
    ec3.calculator.Cvss31Calculator()

    assert "Caught PermissionError. Unable to read data file." in caplog.text


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_load_data_unpickling_error(mock_unpickle, caplog):
    mock_unpickle.side_effect = pickle.UnpicklingError
    caplog.set_level(logging.DEBUG)
    ec3.calculator.Cvss31Calculator()

    assert (
        "Caught UnpicklingError. Input file not in correct pickle format."
        in caplog.text
    )


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_unpickler_data_file(mock_unpickle, example_cve_data):
    mock_unpickle.return_value = [example_cve_data]
    test_calculator = ec3.calculator.Cvss31Calculator("/fake/file")

    assert test_calculator.cwe_data[125]


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_unpickler_data_file_blank(mock_unpickle, example_cve_data):
    mock_unpickle.return_value = [example_cve_data]
    test_calculator = ec3.calculator.Cvss31Calculator("")

    assert test_calculator.cwe_data[125]


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_calculator_unpickler_data_file_None(mock_unpickle, caplog, example_cve_data):
    mock_unpickle.return_value = [example_cve_data]
    caplog.set_level(logging.DEBUG)
    test_calculator = ec3.calculator.Cvss31Calculator()

    # Initialization sets file to default value.
    # Call directly with no parameters to send None
    test_calculator.load_data_file()

    assert (
        "No data file provided, setting to default file: ./data/nvd_loaded.pickle"
        in caplog.text
    )


def test_set_vulnerability_data_type_error(example_calculator):

    # Cause a TypeError exception
    with pytest.raises(TypeError):
        example_calculator.set_vulnerability_data(["abc", "def"])
