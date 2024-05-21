import pytest


@pytest.fixture
def example_results(example_calculator) -> dict:
    ec3_results = example_calculator.calculate_results(125)
    return ec3_results


@pytest.fixture
def example_results_normalized(example_normalized_calculator, example_cve_data) -> dict:
    example_normalized_calculator.set_vulnerability_data([example_cve_data])
    ec3_results = example_normalized_calculator.calculate_results(126, normalize=True)
    return ec3_results
