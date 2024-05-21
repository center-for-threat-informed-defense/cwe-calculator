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


@patch.object(ec3.calculator.Cvss31Calculator, "load_json")
def test_calculator_load_data_lookup_error(mock_decode, caplog):
    mock_decode.side_effect = LookupError
    caplog.set_level(logging.DEBUG)
    ec3.calculator.Cvss31Calculator("fake/file.json")

    assert "Caught LookupError. Input file lists no vulnerabilities." in caplog.text


@patch.object(ec3.calculator.Cvss31Calculator, "load_json")
def test_calculator_load_data_decode_error(mock_decode, caplog):
    mock_decode.side_effect = json.JSONDecodeError("Bad JSON", "", 0)
    caplog.set_level(logging.DEBUG)
    ec3.calculator.Cvss31Calculator("fake/file.json")

    assert "Caught JSONDecodeError. Input file not a valid JSON file." in caplog.text


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


def test_calculator_decode_data_file(setup_mock_json_file):
    test_calculator = ec3.calculator.Cvss31Calculator(support_defaults=False)
    test_calculator.load_data_file("/fake/file.json")

    assert test_calculator.cwe_data[125]


def test_calculator_decode_data_file_no_vulnerabilities(setup_mock_json_file_empty):
    test_calculator = ec3.calculator.Cvss31Calculator(support_defaults=False)

    # Cause a LookupError exception
    with pytest.raises(LookupError):
        test_calculator.load_json("/fake/file.json")


def test_calculator_decode_data_file_None(setup_mock_json_file):
    test_calculator = ec3.calculator.Cvss31Calculator(support_defaults=False)
    test_calculator.load_json(None)

    assert not test_calculator.cwe_data[125]


def test_set_vulnerability_data_type_error(example_calculator):

    # Cause a TypeError exception
    with pytest.raises(TypeError):
        example_calculator.set_vulnerability_data(["abc", "def"])
