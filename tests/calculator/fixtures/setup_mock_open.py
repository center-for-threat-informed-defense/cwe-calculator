import builtins
import json

import pytest
from mock import mock_open


@pytest.fixture
def setup_mock_normalization(monkeypatch):
    normalized_file_patch = mock_open(read_data="126,125\n130,Other")
    monkeypatch.setattr(builtins, "open", normalized_file_patch)


@pytest.fixture
def setup_mock_normalization_type_error(monkeypatch):
    normalized_file_patch = mock_open(read_data="126,125\n130,Bad")
    monkeypatch.setattr(builtins, "open", normalized_file_patch)


@pytest.fixture
def setup_mock_normalization_file_not_found_error(monkeypatch):
    normalized_file_patch = mock_open(read_data="126,125\n130,Bad")
    normalized_file_patch.side_effect = FileNotFoundError
    monkeypatch.setattr(builtins, "open", normalized_file_patch)


@pytest.fixture
def setup_mock_normalization_permission_error(monkeypatch):
    normalized_file_patch = mock_open(read_data="126,125\n130,Bad")
    normalized_file_patch.side_effect = PermissionError
    monkeypatch.setattr(builtins, "open", normalized_file_patch)


@pytest.fixture
def setup_mock_json_file(monkeypatch, example_cve_data_as_json):
    json_data_file = mock_open(read_data=json.dumps(example_cve_data_as_json))
    monkeypatch.setattr(builtins, "open", json_data_file)


@pytest.fixture
def setup_mock_json_file_empty(monkeypatch):
    json_data_file = mock_open(read_data="{}")
    monkeypatch.setattr(builtins, "open", json_data_file)
