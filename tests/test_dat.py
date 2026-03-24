import json
from copy import deepcopy
from io import BufferedReader, BytesIO
from tempfile import NamedTemporaryFile
from unittest.mock import Mock, call, mock_open, patch

import pytest

from cd_dat_utils.core.dat import (
    BigFile,
    FileEntry,
    FolderEntry,
    UnmappedEntry,
    compare,
    compare_file,
    compare_folder,
    compare_unmapped_data,
    from_dat,
    from_unpacked,
    hash_from_file_path,
    pack_bigfile,
    read_file,
    read_folder,
    unpack_bigfile,
    write_file,
    write_folder,
    write_unmapped_data,
)

DAT_PATH = "tests/test_data/hello_cd_dat_utils.core.dat.DAT"
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


@patch("cd_dat_utils.core.dat.read_file")
def test_read_folder(mock_read_file: Mock):
    folder_bytes = open("tests/test_data/hello_folder.bin", "rb").read()
    reader = BufferedReader(BytesIO(folder_bytes))

    parsed_folder = read_folder(reader, 0)

    assert parsed_folder.offset == 0x800
    assert parsed_folder.encryption == 0
    assert parsed_folder.magic == 1122
    assert mock_read_file.call_count == 2


def test_from_dat():
    bigfile = from_dat(DAT_PATH, CONFIG, CONFIG_PATH)

    assert len(bigfile.folder_list) == 2
    assert len(bigfile.unmapped_data) == 2
    assert bigfile.unmapped_data[0].size == 100
    assert bigfile.unmapped_data[0].contents == b"\x44" * 100


def test_from_unpacked():
    bigfile = from_unpacked(UNPACKED_PATH, CONFIG)

    assert len(bigfile.folder_list) == 2
    assert len(bigfile.unmapped_data) == 2
    assert bigfile.unmapped_data[0].size == 100
    assert bigfile.unmapped_data[0].contents == b"\x44" * 100


@patch("os.path.exists")
@patch("builtins.open")
def test_from_unpacked_raises_input_dir_not_found(_: Mock, mock_exists: Mock):
    mock_exists.return_value = False

    with pytest.raises(Exception, match=r"Input directory .* does not exist"):
        from_unpacked("some_file", CONFIG)


@patch("os.path.exists")
@patch("builtins.open")
def test_from_unpacked_raises_subfile_not_found(_: Mock, mock_exists: Mock):
    mock_exists.side_effect = [True, False]

    with pytest.raises(Exception, match=r"File .* cannot be found!"):
        from_unpacked("some_file", CONFIG)


@patch("os.path.exists")
@patch("builtins.open")
def test_from_unpacked_raises_no_structure(_: Mock, mock_exists: Mock):
    mock_exists.return_value = True

    config = deepcopy(CONFIG)
    del config["structure"]

    with pytest.raises(Exception, match="'structure' does not exist in config file!"):
        from_unpacked("some_file", config)


@patch("struct.unpack")
@patch("builtins.open", new_callable=mock_open, read_data=b"\x00" * 100)
def test_from_unpacked_writes_structure_if_not_present(
    mock_open: Mock, mock_unpack: Mock
):
    expected_path = "some_path.json"
    config = {}

    # mock_open.return_value = NamedTemporaryFile("rb", buffering=4)

    _ = from_dat(DAT_PATH, config, expected_path)
    mock_unpack.return_value = (0, 0)

    assert config.get("structure") is not None
    mock_open.assert_called_with(expected_path, "w")


def test_write_file():
    temp_file = NamedTemporaryFile("wb")

    expected = (
        b"\x44\x33\x22\x11\x0c\x00\x00\x00\x10\x00\x00\x00\x88\x77\x66\x55"
        + "hello world!".encode("ascii")
    )

    file = FileEntry(
        size=12,
        offset=16,
        hash=0x11223344,
        checksum=0x55667788,
        contents="hello world!".encode("ascii"),
    )

    with open(temp_file.name, "wb") as f:
        write_file(file, 0, f)

    with open(temp_file.name, "rb") as f:
        assert f.read() == expected


@patch("cd_dat_utils.core.dat.write_file")
def test_write_folder(mock_write_file: Mock):
    temp_folder = NamedTemporaryFile("wb")

    expected = b"\x22\x11\x01\x00\x08\x00\x00\x00\x01\x00\x00\x00"

    folder = FolderEntry(
        offset=8,
        magic=0x1122,
        encryption=0,
        file_list=[Mock(FileEntry)],
    )

    with open(temp_folder.name, "wb") as f:
        write_folder(folder, 0, f)

    with open(temp_folder.name, "rb") as f:
        assert f.read() == expected

    assert mock_write_file.call_count == 1


def test_write_unmapped_data():
    unmapped = UnmappedEntry(
        size=0, offset=0, contents="this is unmapped data".encode("ascii")
    )

    file = NamedTemporaryFile("wb")

    with open(file.name, "wb") as f:
        write_unmapped_data(unmapped, f)

    with open(file.name, "rb") as f:
        assert f.read() == "this is unmapped data".encode("ascii")


@patch("cd_dat_utils.core.dat.write_unmapped_data")
@patch("cd_dat_utils.core.dat.write_folder")
@patch("builtins.open")
def test_pack_bigfile(mock_open: Mock, mock_write_folder: Mock, _):
    file = BigFile(size=1, folder_list=[Mock(FolderEntry)] * 2)
    written_file = NamedTemporaryFile("wb")
    mock_open.return_value = written_file

    pack_bigfile(file, "fake_dir")

    assert mock_write_folder.call_count == len(file.folder_list)
    mock_open.assert_called_once_with("fake_dir", "wb", 0)


@patch("cd_dat_utils.core.dat.write_unmapped_data")
@patch("cd_dat_utils.core.dat.write_folder")
@patch("builtins.open")
def test_pack_bigfile_writes_unmapped_data(
    mock_open: Mock, mock_write_folder: Mock, mock_write_unmapped: Mock
):
    file = BigFile(size=1, folder_list=[], unmapped_data=[Mock(UnmappedEntry)] * 15)

    mock_open.return_value = NamedTemporaryFile("wb")

    pack_bigfile(file, "fake_dir")

    assert mock_write_folder.call_count == len(file.folder_list)
    mock_open.assert_called_once_with("fake_dir", "wb", 0)
    assert mock_write_unmapped.call_count == len(file.unmapped_data)


@patch("os.makedirs")
@patch("shutil.rmtree")
@patch("builtins.open")
@patch("os.path.exists")
def test_unpack_bigfile_writes_unmapped_data(mock_exists: Mock, mock_open: Mock, *_):
    unmapped_data = UnmappedEntry(size=1, offset=1234, contents=b"\x01")

    file = BigFile(size=1, folder_list=[], unmapped_data=[unmapped_data])
    mock_exists.return_value = False

    unpack_bigfile(file, CONFIG, "fake_dir")

    mock_open.assert_has_calls(
        [call("fake_dir/unmapped_data/unmapped_1234.bin", "wb")], True
    )


@patch("os.makedirs")
@patch("shutil.rmtree")
@patch("builtins.open")
@patch("os.path.exists")
def test_unpack_bigfile_unknown_hashes(mock_exists: Mock, mock_open: Mock, *_):
    file_0 = FileEntry(size=1, offset=1, hash=1, checksum=1, contents=b"\x01")
    file_1 = FileEntry(size=1, offset=1, hash=2, checksum=1, contents=b"\x01")

    folder = FolderEntry(offset=0, magic=1, encryption=0, file_list=[file_0, file_1])

    file = BigFile(size=1, folder_list=[folder])
    mock_exists.return_value = False

    unpack_bigfile(file, CONFIG, "fake_dir")

    mock_open.assert_has_calls(
        [call("fake_dir/1.bin", "wb"), call("fake_dir/2.bin", "wb")], True
    )


@patch("os.makedirs")
@patch("shutil.rmtree")
@patch("builtins.open")
@patch("os.path.exists")
def test_unpack_bigfile_known_hashes(mock_exists: Mock, mock_open: Mock, *_):
    file_0 = FileEntry(size=1, offset=1, hash=1, checksum=1, contents=b"\x01")
    file_1 = FileEntry(size=1, offset=1, hash=2, checksum=1, contents=b"\x01")

    folder = FolderEntry(offset=0, magic=1, encryption=0, file_list=[file_0, file_1])

    file = BigFile(size=1, folder_list=[folder])
    mock_exists.return_value = False

    config = deepcopy(CONFIG)
    config["file_names"]["1"] = "file_1.drm"
    config["file_names"]["2"] = "file_2.chr"

    unpack_bigfile(file, config, "fake_dir")

    mock_open.assert_has_calls(
        [call("fake_dir/file_1.drm", "wb"), call("fake_dir/file_2.chr", "wb")], True
    )


@patch("os.makedirs")
@patch("shutil.rmtree")
@patch("builtins.open")
@patch("os.path.exists")
def test_unpack_bigfile_names_duplicates(mock_exists: Mock, mock_open: Mock, *_):
    file_0 = FileEntry(size=1, offset=1, hash=1, checksum=1, contents=b"\x01")

    folder = FolderEntry(offset=0, magic=1, encryption=0, file_list=[file_0, file_0])

    file = BigFile(size=1, folder_list=[folder])
    mock_exists.return_value = False

    unpack_bigfile(file, CONFIG, "fake_dir")

    mock_open.assert_has_calls(
        [call("fake_dir/1.bin", "wb"), call("fake_dir/1_duplicate1.bin", "wb")], True
    )


@patch("os.makedirs")
@patch("shutil.rmtree")
@patch("builtins.open")
@patch("pathlib.Path.mkdir")
@patch("os.path.exists")
def test_unpack_bigfile_creates_subdirs(
    mock_exists: Mock, mock_mkdir: Mock, mock_open: Mock, *_
):
    file_0 = FileEntry(size=1, offset=1, hash=1, checksum=1, contents=b"\x01")
    file_1 = FileEntry(size=1, offset=1, hash=2, checksum=1, contents=b"\x01")

    folder = FolderEntry(offset=0, magic=1, encryption=0, file_list=[file_0, file_1])

    file = BigFile(size=1, folder_list=[folder])
    mock_exists.side_effect = [False, False, True]

    config = deepcopy(CONFIG)
    config["file_names"]["1"] = "my_dir\\file_1.drm"
    config["file_names"]["2"] = "my_dir\\file_2.chr"

    unpack_bigfile(file, config, "fake_dir")

    mock_mkdir.assert_called_once()
    mock_open.assert_has_calls(
        [
            call("fake_dir/my_dir/file_1.drm", "wb"),
            call("fake_dir/my_dir/file_2.chr", "wb"),
        ],
        True,
    )


@patch("builtins.open")
@patch("os.makedirs")
@patch("os.path.exists")
@patch("shutil.rmtree")
def test_unpack_bigfile_deletes_existing_dir(mock_rmtree: Mock, mock_exists: Mock, *_):
    file = BigFile(size=1, folder_list=[])
    mock_exists.return_value = True

    unpack_bigfile(file, CONFIG, "fake_dir")

    mock_rmtree.assert_called_once_with("fake_dir")


def test_compare_unmapped_data():
    a = UnmappedEntry(size=0, offset=0, contents=(b"\x11" * 3))
    b = UnmappedEntry(size=1, offset=1, contents=(b"\x11" * 4))

    mismatches = compare_unmapped_data(a, b, 0)

    assert len(mismatches) == 3
    assert "Size" in mismatches[0]
    assert "Offset" in mismatches[1]
    assert "Content" in mismatches[2]


def test_compare_file():
    a = FileEntry(size=0, offset=0, hash=0, checksum=0, contents=(b"\x11" * 3))
    b = FileEntry(size=1, offset=1, hash=1, checksum=1, contents=(b"\x11" * 4))

    mismatches = compare_file(a, b, 0, 0)

    assert len(mismatches) == 5
    assert "size" in mismatches[0]
    assert "offset" in mismatches[1]
    assert "hash" in mismatches[2]
    assert "checksum" in mismatches[3]
    assert "contents" in mismatches[4]


@patch("cd_dat_utils.core.dat.compare_file")
def test_compare_folder(mock_compare_file: Mock):
    a = FolderEntry(offset=0, magic=0, encryption=0, file_list=[Mock(FileEntry)] * 3)
    b = FolderEntry(offset=1, magic=1, encryption=1, file_list=[Mock(FileEntry)] * 4)

    mock_compare_file.side_effect = [["some file mismatch"], [], []]

    mismatches = compare_folder(a, b, 0)

    assert len(mismatches) == 5
    assert "files" in mismatches[0]
    assert "offset" in mismatches[1]
    assert "magic" in mismatches[2]
    assert "encryption" in mismatches[3]
    assert mismatches[-1] == "some file mismatch"
    assert mock_compare_file.call_count == 3


@patch("cd_dat_utils.core.dat.compare_folder")
@patch("cd_dat_utils.core.dat.compare_unmapped_data")
def test_compare_bigfile(mock_compare_unmapped: Mock, mock_compare_folder: Mock):
    a = BigFile(
        size=0,
        folder_list=[Mock(FolderEntry)] * 2,
        unmapped_data=[Mock(UnmappedEntry)] * 3,
    )
    b = BigFile(
        size=1,
        folder_list=[Mock(FolderEntry)] * 3,
        unmapped_data=[Mock(UnmappedEntry)] * 4,
    )

    errors = compare(a, b)

    assert len(errors) == 3
    assert "folders" in errors[0]
    assert "unmapped sections" in errors[1]
    assert "size" in errors[2]
    assert mock_compare_folder.call_count == 2
    assert mock_compare_unmapped.call_count == 3


def test_compare_e2e():
    a = from_dat(DAT_PATH, CONFIG, CONFIG_PATH)
    b = from_unpacked(UNPACKED_PATH, CONFIG)
    errors = compare(a, b)

    assert len(errors) == 0
