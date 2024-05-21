import ec3.calculator
import pytest


@pytest.fixture
def example_calculator(example_cve_data) -> ec3.calculator.Cvss31Calculator:

    # Initialize a Cvss31Calculator using example data
    test_calculator = ec3.calculator.Cvss31Calculator()
    test_calculator.set_vulnerability_data([example_cve_data])

    return test_calculator


@pytest.fixture
def example_normalized_calculator(
    setup_mock_normalization, example_cve_data_to_normalize
) -> ec3.calculator.Cvss31Calculator:

    # Initialize a Cvss31Calculator using example data
    test_normalized_calculator = ec3.calculator.Cvss31Calculator(
        normalization_file_str="/fake/file.csv"
    )
    test_normalized_calculator.set_vulnerability_data([example_cve_data_to_normalize])

    return test_normalized_calculator


@pytest.fixture
def example_calculator_mock_normalized(
    setup_mock_normalization, example_cve_data
) -> ec3.calculator.Cvss31Calculator:

    # Initialize a Cvss31Calculator using example data
    test_calculator = ec3.calculator.Cvss31Calculator()
    test_calculator.set_vulnerability_data([example_cve_data])

    return test_calculator
