import pytest
from pathlib import Path
from io import BufferedReader, BytesIO
from typing import BinaryIO

from src.dat_utils import BigFile, read_file, FileEntry


def test_read_file():
    mock_file = b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    reader = BufferedReader(BytesIO(mock_file))

    parsed_file = read_file(reader, 0)

    assert parsed_file.hash == 1
    assert parsed_file.size == 2
    assert parsed_file.offset == 3
    assert parsed_file.checksum == 4
    assert parsed_file.contents is not None
    assert parsed_file.contents == b"\x00\x02"


def test_read_folder():
    assert False, "Not implemented yet"


def test_from_dat():
    assert False, "Not implemented yet"


def test_from_unpacked():
    assert False, "Not implemented yet"


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


def test_hash_file_name():
    assert False, "Not implemented yet"
