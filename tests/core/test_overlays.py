from io import BytesIO
from struct import pack, unpack
from unittest.mock import Mock, patch

from cd_dat_utils.core.overlays import (
    SECTOR_SIZE,
    Reloc,
    RelocType,
    _advance_to_sector_boundary,
    _read_relocs,
    _read_s32,
    _read_u32,
    _write_u32,
    find_mod_and_relocs,
    undrm,
)


def test_read_s32():
    assert _read_s32(BytesIO(pack("<i", -1234))) == -1234
    assert _read_s32(BytesIO(pack("<i", 1234))) == 1234


def test_read_s32_peeks():
    bytes = BytesIO(pack("<i", 1234))
    _read_s32(bytes)

    assert bytes.tell() == 4

    bytes = BytesIO(pack("<i", 1234))
    _read_s32(bytes, True)

    assert bytes.tell() == 0


def test_read_u32():
    assert _read_u32(BytesIO(pack("<i", -1234))) != -1234
    assert _read_u32(BytesIO(pack("<i", 1234))) == 1234


def test_read_u32_peeks():
    bytes = BytesIO(pack("<I", 1234))
    _read_u32(bytes)

    assert bytes.tell() == 4

    bytes = BytesIO(pack("<I", 1234))
    _read_u32(bytes, True)

    assert bytes.tell() == 0


def test_write_u32():
    bytes = BytesIO()
    _write_u32(bytes, 1234)
    bytes.seek(0)

    assert unpack("<I", bytes.read(4))[0] == 1234


def test_write_u32_masks_32_bits():
    bytes = BytesIO()
    _write_u32(bytes, 0x1FFFFFFFF)
    bytes.seek(0)

    assert unpack("<I", bytes.read(4))[0] == 0xFFFFFFFF


def test_advance_to_sector_boundary():
    bytes = BytesIO(b"\x00" * 100000)
    _advance_to_sector_boundary(bytes)

    assert bytes.tell() == 0

    bytes.seek(1)
    _advance_to_sector_boundary(bytes)

    assert bytes.tell() == SECTOR_SIZE

    bytes.seek(SECTOR_SIZE + 1)
    _advance_to_sector_boundary(bytes)

    assert bytes.tell() == SECTOR_SIZE * 2


@patch("cd_dat_utils.core.overlays._read_s32")
def test_read_relocs(mock_s32: Mock):
    bytes = BytesIO()

    mock_s32.side_effect = [
        0b10101000 | RelocType.R_MIPS_32,
        0b11111100 | RelocType.R_MIPS_HI16,
        1234,  # addend for hi 16
        0b11001100 | RelocType.R_MIPS_LO16,
        0b10000100 | RelocType.R_MIPS_26,
        -1,
    ]

    relocs = _read_relocs(bytes)
    assert len(relocs) == 4
    assert relocs[0].type == RelocType.R_MIPS_32
    assert relocs[0].addr == 0b10101000
    assert relocs[0].addend == 0
    assert relocs[1].type == RelocType.R_MIPS_HI16
    assert relocs[1].addr == 0b11111100
    assert relocs[1].addend == 1234
    assert relocs[2].type == RelocType.R_MIPS_LO16
    assert relocs[2].addr == 0b11001100
    assert relocs[2].addend == 0
    assert relocs[3].type == RelocType.R_MIPS_26
    assert relocs[3].addr == 0b10000100
    assert relocs[3].addend == 0
