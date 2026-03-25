from tempfile import NamedTemporaryFile
from unittest.mock import Mock, patch

import pytest
from pydantic import ValidationError

from cd_dat_utils.core.config import BigFileConfig, Config


@pytest.fixture
def valid_config() -> Config:
    return Config.from_yaml("tests/test_data/test_config.yaml")


def test_config_from_yaml_succeeds():
    _ = Config.from_yaml("tests/test_data/test_config.yaml")


def test_config_from_yaml_fails():
    with pytest.raises(ValidationError):
        _ = Config.from_yaml("tests/test_data/test_config_invalid.yaml")


def test_bigfile_config_uses_packed_path():
    config = BigFileConfig(
        src_path="my_src_path",
        unpacked_path="my_unpacked_path",
        packed_path="my_packed_path",
        structure_path="my_structure",
    )

    assert config.packed_path == "my_packed_path"


def test_bigfile_config_overloads_packed_path():
    config = BigFileConfig(
        src_path="my_src_path",
        unpacked_path="my_unpacked_path",
        structure_path="my_structure",
    )

    assert config.packed_path == "my_src_path"


@patch("os.path.exists")
def test_file_map_path_raises_not_exists(mock_exists: Mock):
    mock_exists.return_value = False

    with pytest.raises(Exception, match=r"File list YAML .* does not exist!"):
        _ = BigFileConfig(
            src_path="my_src_path",
            unpacked_path="my_unpacked_path",
            structure_path="my_structure",
            file_map_path="invalid",
        )


def test_config_loads_file_map_if_present():
    config = BigFileConfig(
        src_path="my_src_path",
        unpacked_path="my_unpacked_path",
        structure_path="my_structure",
        file_map_path="tests/test_data/test_file_map.yaml",
    )

    assert len(config.file_map) == 3


@patch("builtins.open")
def test_config_write_yaml(mock_open: Mock, valid_config):
    mock_open.return_value = NamedTemporaryFile("w")
    valid_config.write_yaml("config.yaml")
    mock_open.assert_called_once_with("config.yaml", "w")
