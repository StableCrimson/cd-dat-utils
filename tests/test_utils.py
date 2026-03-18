from io import BufferedReader, BytesIO
from unittest.mock import Mock, patch
import json
from src.dat_utils import (
    read_file,
    read_folder,
    from_dat,
    from_unpacked,
    hash_from_file_path,
    compare_file,
    compare_folder,
    compare,
    FileEntry,
    FolderEntry,
    BigFile,
)

DAT_PATH = "tests/test_data/hello_dat.DAT"
UNPACKED_PATH = "tests/test_data/unpacked"
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
    bigfile = from_dat(DAT_PATH, CONFIG, CONFIG_PATH)

    assert len(bigfile.folder_list) == 2
    assert bigfile.unmapped_data is not None
    assert bigfile.unmapped_data.size == 100
    assert bigfile.unmapped_data.contents == b"\x44" * 100


def test_from_unpacked():
    bigfile = from_unpacked(UNPACKED_PATH, CONFIG)

    assert len(bigfile.folder_list) == 2
    assert bigfile.unmapped_data is not None
    assert bigfile.unmapped_data.size == 100
    assert bigfile.unmapped_data.contents == b"\x44" * 100


@patch("builtins.open")
def test_structure_written_if_not_present(mock_open: Mock):
    expected_path = "some_path.json"
    config = {}

    _ = from_dat(DAT_PATH, config, expected_path)

    assert config.get("structure") is not None
    mock_open.assert_called_with(expected_path, "w")


def test_write_file():
    assert False, "Not implemented yet"


def test_write_folder():
    assert False, "Not implemented yet"


def test_pack_bigfile():
    assert False, "Not implemented yet"


def test_unpack_bigfile():
    assert False, "Not implemented yet"


def test_compare_unmapped_data():
    assert False, "Not implemented yet"


def test_compare_file():
    a = FileEntry(size=1, offset=0, hash=0, checksum=0, contents=(b"\x11" * 3))
    b = FileEntry(size=1, offset=1, hash=1, checksum=1, contents=(b"\x11" * 4))
    errors = []

    compare_file(a, b, 0, 0, errors)

    assert len(errors) == 4
    assert "offset" in errors[0]
    assert "hash" in errors[1]
    assert "checksum" in errors[2]
    assert "contents" in errors[3]


@patch("src.dat_utils.compare_file")
def test_compare_folder(mock_compare_file: Mock):
    a = FolderEntry(offset=0, magic=0, encryption=0, file_list=[Mock(FileEntry)] * 3)
    b = FolderEntry(offset=1, magic=1, encryption=1, file_list=[Mock(FileEntry)] * 4)
    errors = []

    compare_folder(a, b, 0, errors)

    assert len(errors) == 4
    assert "files" in errors[0]
    assert "offset" in errors[1]
    assert "magic" in errors[2]
    assert "encryption" in errors[3]
    assert mock_compare_file.call_count == 3


@patch("src.dat_utils.compare_folder")
@patch("src.dat_utils.compare_unmapped_data")
def test_compare_bigfile(mock_compare_unmapped: Mock, mock_compare_folder: Mock):
    a = BigFile(size=0, folder_list=[Mock(FolderEntry)] * 2)
    b = BigFile(size=1, folder_list=[Mock(FolderEntry)] * 3)

    errors = compare(a, b)

    assert len(errors) == 2
    assert "folders" in errors[0]
    assert "size" in errors[1]
    assert mock_compare_folder.call_count == 2
    mock_compare_unmapped.assert_called()


def test_compare_e2e():
    a = from_dat(DAT_PATH, CONFIG, CONFIG_PATH)
    b = from_unpacked(UNPACKED_PATH, CONFIG)
    errors = compare(a, b)

    assert len(errors) == 0
