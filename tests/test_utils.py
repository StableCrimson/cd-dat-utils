from io import BufferedReader, BytesIO
from unittest.mock import Mock, patch
import json
from src.dat_utils import (
    read_file,
    read_folder,
    from_dat,
    from_unpacked,
    hash_from_file_path,
)

CONFIG_PATH = "tests/test_data/test_config.json"
with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)


def test_hash_file_name():
    path = "tests\\test_data\\hello_file.drm"
    expected = 3261577552
    assert hash_from_file_path(path) == expected


def test_read_file():
    mock_file = open("tests/test_data/hello_file.bin", "rb").read()
    reader = BufferedReader(BytesIO(mock_file))

    expected_contents = "hello world! this is the first file"

    parsed_file = read_file(reader, 0)

    assert parsed_file.hash == 4073469856
    assert parsed_file.size == len(expected_contents)
    assert parsed_file.offset == 0x1000
    assert parsed_file.checksum == 0x11223344
    assert parsed_file.contents == expected_contents.encode("ascii")


@patch("src.dat_utils.read_file")
def test_read_folder(mock_read_folder: Mock):
    folder_bytes = open("tests/test_data/hello_folder.bin", "rb").read()
    reader = BufferedReader(BytesIO(folder_bytes))

    parsed_folder = read_folder(reader, 0)

    assert parsed_folder.offset == 0x800
    assert parsed_folder.encryption == 0
    assert parsed_folder.magic == 1122
    assert mock_read_folder.call_count == 2


def test_from_dat():
    bigfile = from_dat("tests/test_data/hello_dat.dat", CONFIG, CONFIG_PATH)

    assert len(bigfile.folder_list) == 2
    assert bigfile.unmapped_data is not None
    assert bigfile.unmapped_data.size == 100
    assert bigfile.unmapped_data.contents == b"\x44" * 100


def test_from_unpacked():
    bigfile = from_unpacked(
        "tests/test_data/unpacked",
        CONFIG,
    )

    assert len(bigfile.folder_list) == 2
    assert bigfile.unmapped_data is not None
    assert bigfile.unmapped_data.size == 100
    assert bigfile.unmapped_data.contents == b"\x44" * 100


def test_write_file():
    assert False, "Not implemented yet"


def test_write_folder():
    assert False, "Not implemented yet"


def test_pack_bigfile():
    assert False, "Not implemented yet"


def test_unpack_bigfile():
    assert False, "Not implemented yet"


def test_structure_written_if_not_exists():
    assert False, "Not implemented yet"


def test_compare_file():
    assert False, "Not implemented yet"


def test_compare_folder():
    assert False, "Not implemented yet"


def test_compare_bigfile():
    assert False, "Not implemented yet"
