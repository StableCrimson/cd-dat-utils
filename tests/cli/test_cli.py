from unittest.mock import Mock, call, patch

import pytest

from cd_dat_utils.cli.commands import (
    _from_path,
    command_compare,
    command_pack,
    command_undrm,
    command_unpack,
)
from cd_dat_utils.core.config import BigFileConfig, Config, OverlayConfig
from cd_dat_utils.core.dat import BigFile

DAT_PATH = "tests/test_data/hello_dat.DAT"
UNPACKED_PATH = "tests/test_data/unpacked"
STRUCTURE_PATH = "tests/test_data/test_structure.yaml"
FILE_MAP_PATH = "tests/test_data/test_file_map.yaml"


@pytest.fixture
def config_with_bigfile() -> Config:
    return Config(
        bigfile=BigFileConfig(
            src_path=DAT_PATH,
            unpacked_path=UNPACKED_PATH,
            structure_path=STRUCTURE_PATH,
            file_map_path=FILE_MAP_PATH,
            file_map={
                2037158304: "dir_1\\test_file1.drm",
                2037191072: "dir_1\\test_file2.drm",
                2579342152: "dir_2\\test_file3.bin",
            },
        )
    )


@pytest.fixture
def config_with_overlays() -> Config:
    return Config(
        overlays=[
            OverlayConfig(
                name="MyOverlay", src_path="myOverlay.drm", out_path="myOverlay.bin"
            )
        ]
    )


@patch("cd_dat_utils.cli.commands.Config.from_yaml")
def test_command_compare_fails_no_bigfile(mock_from_yaml: Mock):
    mock_from_yaml.return_value = Config()

    with pytest.raises(SystemExit):
        command_compare("some_path")


@patch("cd_dat_utils.cli.commands.compare")
@patch("cd_dat_utils.cli.commands._from_path")
@patch("cd_dat_utils.core.config.Config.from_yaml")
def test_command_compare_a_overrides(
    mock_from_yaml: Mock, mock_from_path: Mock, mock_compare: Mock, config_with_bigfile
):
    mock_from_yaml.return_value = config_with_bigfile
    mock_from_path.return_value = BigFile(size=1, folder_list=[])
    mock_compare.return_value = []

    command_compare("some_path", path_a="new_path_a")

    mock_from_path.assert_has_calls([call("new_path_a", config_with_bigfile.bigfile)])


@patch("cd_dat_utils.cli.commands.compare")
@patch("cd_dat_utils.cli.commands._from_path")
@patch("cd_dat_utils.core.config.Config.from_yaml")
def test_command_compare_b_overrides(
    mock_from_yaml: Mock, mock_from_path: Mock, mock_compare: Mock, config_with_bigfile
):
    mock_from_yaml.return_value = config_with_bigfile
    mock_from_path.return_value = BigFile(size=1, folder_list=[])
    mock_compare.return_value = []

    command_compare("some_path", path_b="new_path_b")

    mock_from_path.assert_has_calls([call("new_path_b", config_with_bigfile.bigfile)])


@patch("builtins.print")
@patch("cd_dat_utils.cli.commands.compare")
@patch("cd_dat_utils.cli.commands._from_path")
@patch("cd_dat_utils.core.config.Config.from_yaml")
def test_command_compare_reports_no_errors(
    mock_from_yaml: Mock,
    mock_from_path: Mock,
    mock_compare: Mock,
    mock_print: Mock,
    config_with_bigfile,
):
    mock_from_yaml.return_value = config_with_bigfile
    mock_from_path.return_value = BigFile(size=1, folder_list=[])
    mock_compare.return_value = []

    command_compare("some_path", path_a="path_a", path_b="path_b")

    mock_print.assert_called_once_with(
        "No differences found between 'path_a' and 'path_b'"
    )


@patch("builtins.print")
@patch("cd_dat_utils.cli.commands.compare")
@patch("cd_dat_utils.cli.commands._from_path")
@patch("cd_dat_utils.core.config.Config.from_yaml")
def test_command_compare_reports_errors(
    mock_from_yaml: Mock,
    mock_from_path: Mock,
    mock_compare: Mock,
    mock_print: Mock,
    config_with_bigfile,
):
    mock_from_yaml.return_value = config_with_bigfile
    mock_from_path.return_value = BigFile(size=1, folder_list=[])
    mock_compare.return_value = ["Oh no!"]

    command_compare("some_path", path_a="path_a", path_b="path_b")

    mock_print.assert_has_calls(
        [call("1 differences found between 'path_a' and 'path_b':"), call("\tOh no!")]
    )


@patch("cd_dat_utils.cli.commands.Config.from_yaml")
def test_command_unpack_fails_no_bigfile(mock_from_yaml: Mock):
    mock_from_yaml.return_value = Config()

    with pytest.raises(SystemExit):
        command_unpack("some_path")


@patch("cd_dat_utils.cli.commands.from_dat")
@patch("cd_dat_utils.cli.commands.unpack_bigfile")
@patch("cd_dat_utils.core.config.Config.from_yaml")
def test_command_unpack_input_overrides(
    mock_from_yaml: Mock,
    _mock_unpack_bigfile,
    mock_from_dat: Mock,
    config_with_bigfile,
):
    mock_from_yaml.return_value = config_with_bigfile
    mock_from_dat.return_value = BigFile(size=1, folder_list=[])

    command_unpack("some_path", input="new_path_a")

    mock_from_dat.assert_has_calls([call("new_path_a", config_with_bigfile.bigfile)])


@patch("cd_dat_utils.cli.commands.from_dat")
@patch("cd_dat_utils.cli.commands.unpack_bigfile")
@patch("cd_dat_utils.core.config.Config.from_yaml")
def test_command_unpack_output_overrides(
    mock_from_yaml: Mock,
    mock_unpack_bigfile: Mock,
    mock_from_dat: Mock,
    config_with_bigfile,
):
    mock_from_yaml.return_value = config_with_bigfile
    mock_from_dat.return_value = BigFile(size=1, folder_list=[])

    command_unpack("some_path", output="new_path_b")

    mock_unpack_bigfile.assert_called_once_with(
        BigFile(size=1, folder_list=[]), "new_path_b", config_with_bigfile.bigfile
    )


@patch("cd_dat_utils.cli.commands.from_dat")
@patch("cd_dat_utils.cli.commands.unpack_bigfile")
@patch("cd_dat_utils.core.config.Config.from_yaml")
def test_command_unpack_uses_defaults(
    mock_from_yaml: Mock,
    mock_unpack_bigfile: Mock,
    mock_from_dat: Mock,
    config_with_bigfile,
):
    mock_from_yaml.return_value = config_with_bigfile
    mock_from_dat.return_value = BigFile(size=1, folder_list=[])

    command_unpack("some_path")

    mock_from_dat.assert_called_once_with(DAT_PATH, config_with_bigfile.bigfile)
    mock_unpack_bigfile.assert_called_once_with(
        BigFile(size=1, folder_list=[]), UNPACKED_PATH, config_with_bigfile.bigfile
    )


@patch("cd_dat_utils.cli.commands.Config.from_yaml")
def test_command_pack_fails_no_bigfile(mock_from_yaml: Mock):
    mock_from_yaml.return_value = Config()

    with pytest.raises(SystemExit):
        command_pack("some_path")


@patch("cd_dat_utils.cli.commands.from_unpacked")
@patch("cd_dat_utils.cli.commands.pack_bigfile")
@patch("cd_dat_utils.core.config.Config.from_yaml")
def test_command_pack_input_overrides(
    mock_from_yaml: Mock,
    _mock_pack_bigfile,
    mock_from_unpacked: Mock,
    config_with_bigfile,
):
    mock_from_yaml.return_value = config_with_bigfile
    mock_from_unpacked.return_value = BigFile(size=1, folder_list=[])

    command_pack("some_path", input="new_path_a")

    mock_from_unpacked.assert_called_once_with(
        "new_path_a", config_with_bigfile.bigfile
    )


@patch("cd_dat_utils.cli.commands.from_unpacked")
@patch("cd_dat_utils.cli.commands.pack_bigfile")
@patch("cd_dat_utils.core.config.Config.from_yaml")
def test_command_pack_output_overrides(
    mock_from_yaml: Mock,
    mock_pack_bigfile: Mock,
    mock_from_unpacked: Mock,
    config_with_bigfile,
):
    mock_from_yaml.return_value = config_with_bigfile
    mock_from_unpacked.return_value = BigFile(size=1, folder_list=[])

    command_pack("some_path", output="new_path_b")

    mock_pack_bigfile.assert_called_once_with(
        BigFile(size=1, folder_list=[]), "new_path_b"
    )


@patch("cd_dat_utils.cli.commands.from_unpacked")
@patch("cd_dat_utils.cli.commands.pack_bigfile")
@patch("cd_dat_utils.core.config.Config.from_yaml")
def test_command_pack_uses_defaults(
    mock_from_yaml: Mock,
    mock_pack_bigfile: Mock,
    mock_from_upacked: Mock,
    config_with_bigfile,
):
    mock_from_yaml.return_value = config_with_bigfile
    mock_from_upacked.return_value = BigFile(size=1, folder_list=[])

    command_pack("some_path")

    mock_from_upacked.assert_called_once_with(
        UNPACKED_PATH, config_with_bigfile.bigfile
    )
    mock_pack_bigfile.assert_called_once_with(BigFile(size=1, folder_list=[]), DAT_PATH)


@patch("os.path.exists")
def test_from_path_raises_does_not_exist(mock_exists: Mock, config_with_bigfile):
    mock_exists.return_value = False
    with pytest.raises(Exception, match=r".* does not exist!"):
        _from_path("hello", config_with_bigfile.bigfile)


@patch("cd_dat_utils.cli.commands.from_dat")
@patch("os.path.isfile")
@patch("os.path.exists")
def test_from_path_uses_dat_for_files(
    mock_exists: Mock, mock_isfile: Mock, mock_from_dat: Mock, config_with_bigfile
):
    mock_exists.return_value = True
    mock_isfile.return_value = True

    _ = _from_path("hello", config_with_bigfile.bigfile)

    mock_from_dat.assert_called_once()


@patch("cd_dat_utils.cli.commands.from_unpacked")
@patch("os.path.isfile")
@patch("os.path.exists")
def test_from_path_uses_unpacked_for_folders(
    mock_exists: Mock, mock_isfile: Mock, mock_from_unpacked: Mock, config_with_bigfile
):
    mock_exists.return_value = True
    mock_isfile.return_value = False

    _ = _from_path("hello", config_with_bigfile.bigfile)

    mock_from_unpacked.assert_called_once()


@patch("cd_dat_utils.cli.commands.Config.from_yaml")
def test_command_undrm_fails_no_overlays(mock_from_yaml: Mock, config_with_overlays):
    mock_from_yaml.return_value = Config()

    with pytest.raises(SystemExit):
        command_undrm("some_path")


@patch("cd_dat_utils.cli.commands.undrm")
@patch("cd_dat_utils.cli.commands.Config.from_yaml")
def test_command_undrm_processes_each_overlay(
    mock_from_yaml: Mock, mock_undrm: Mock, config_with_overlays
):
    mock_from_yaml.return_value = config_with_overlays
    command_undrm("some_path")

    assert mock_undrm.call_count == len(config_with_overlays.overlays)
