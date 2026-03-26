import json
from dataclasses import dataclass
from enum import IntEnum
from io import BytesIO
from pathlib import Path
from struct import pack, unpack
from typing import BinaryIO

from cd_dat_utils.core.config import OverlayConfig

MODULE_BASE = 0x88000000
RELOC_MASK = 0x3


def read_s16(f: BinaryIO, peek: bool = False) -> int:
    val: int = unpack("<h", f.read(2))[0]
    if peek:
        f.seek(-2, 1)
    return val


def write_s16(f: BinaryIO, val: int):
    f.write(pack("<H", val & 0xFFFF))


def read_s32(f: BinaryIO, peek: bool = False) -> int:
    val: int = unpack("<i", f.read(4))[0]
    if peek:
        f.seek(-4, 1)
    return val


def read_u32(f: BinaryIO, peek: bool = False) -> int:
    val: int = unpack("<I", f.read(4))[0]
    if peek:
        f.seek(-4, 1)
    return val


def write_u32(f: BinaryIO, val: int):
    f.write(pack("<I", val & 0xFFFFFFFF))


class RelocType(IntEnum):
    R_MIPS_32 = 0
    R_MIPS_HI16 = 1
    R_MIPS_LO16 = 2
    R_MIPS_26 = 3


@dataclass
class Reloc:
    type: RelocType
    addr: int
    addend: int = 0


def read_relocs(f: BinaryIO) -> list[Reloc]:
    relocs: list[Reloc] = []

    while True:
        val = read_s32(f)
        if val == -1:
            break

        rel_type = val & RELOC_MASK
        rel_addr = val & ~RELOC_MASK
        rel = Reloc(RelocType(rel_type), rel_addr)

        if rel.type == RelocType.R_MIPS_HI16:
            rel.addend = read_s32(f)
        relocs.append(rel)

    return relocs


def get_relmod(f: BinaryIO) -> tuple[list[Reloc], bytes]:
    # Skip RedirectList
    count = read_s32(f)
    f.seek((count + 1) * 4)

    while (f.tell() % 0x800) != 0:
        f.read(1)

    # Save RELMOD offset
    relmod_off = f.tell()

    # Only grab relocs and the module
    f.seek(relmod_off + 0x3C)
    rel_off = read_s32(f)
    mod_off = read_s32(f)

    assert mod_off != 0, "No module in DRM file"
    assert rel_off != 0, "No relocation data found in module"

    f.seek(relmod_off + rel_off)
    relocs = read_relocs(f)

    f.seek(relmod_off + mod_off)
    mod_bytes = f.read()

    return relocs, mod_bytes


def undrm(config: OverlayConfig):
    with open(config.src_path, "rb") as f:
        relocs, mod_bytes = get_relmod(f)

    mod_new = BytesIO(mod_bytes)

    # Apply relocs
    for rel in relocs:
        mod_new.seek(rel.addr)
        r = read_u32(mod_new, True)
        top = r & 0xFFFF0000

        match rel.type:
            case RelocType.R_MIPS_32:
                if r >= 0:
                    write_u32(mod_new, MODULE_BASE + r)

            case RelocType.R_MIPS_HI16:
                imm = ((MODULE_BASE + rel.addend + 0x8000) >> 16) & 0xFFFF
                write_u32(mod_new, top | imm)

            case RelocType.R_MIPS_LO16:
                imm = (MODULE_BASE + r) & 0xFFFF
                write_u32(mod_new, top | imm)

            case RelocType.R_MIPS_26:
                write_u32(mod_new, r + ((MODULE_BASE // 4) & 0x03FFFFFF))

    mod_new.seek(0)

    mod_path = Path(config.out_path)
    mod_name = mod_path.stem
    output_dir = mod_path.parent

    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_dir / f"{mod_name}.bin", "wb") as f:
        f.write(mod_new.read())

    if config.preserve_original:
        with open(output_dir / f"{mod_name}.orig.bin", "wb") as f:
            f.write(mod_bytes)

    # TODO: Config flags to create splat YAML
