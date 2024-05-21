import ec3.calculator
from mock import patch


def test_init_support_defaults_false():
    test_calculator = ec3.calculator.Cvss31Calculator(support_defaults=False)
    assert not test_calculator.cwe_data


@patch.object(ec3.calculator.Cvss31Calculator, "restricted_load")
def test_init_bad_support_defaults(mock_unpickle, example_cve_data):
    mock_unpickle.return_value = [example_cve_data]
    test_calculator = ec3.calculator.Cvss31Calculator(support_defaults="bad")

    # Changes back to default value of True
    assert test_calculator.cwe_data[125]
