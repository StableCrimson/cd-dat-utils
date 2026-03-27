import hashlib
import os
from dataclasses import dataclass
from enum import IntEnum
from io import BytesIO
from os import SEEK_CUR, SEEK_END
from pathlib import Path
from struct import pack, unpack
from typing import BinaryIO

from cd_dat_utils.core.config import OverlayConfig

MODULE_BASE = 0x88000000
"""Base to use for memory relocations"""

SECTOR_SIZE = 0x800
"""Size of a PSX disc sector"""

RELOC_MASK = 0x3
"""Mask used to retrieve relocation type"""


class RelocType(IntEnum):
    """MIPS relocation types used for patching addresses at link/load time."""

    R_MIPS_32 = 0
    """Direct 32-bit relocation.

    Writes the full 32-bit value of the symbol (plus addend) into the target word.

    Relocation is applied as follows:
        *(u32*)addr = symbol + addend
    """

    R_MIPS_HI16 = 1
    """High 16 bits of a split 32-bit address. Must be paired with a corresponding LO16 relocation.

    Relocation is applied as follows:
        hi = (symbol + addend + 0x8000) >> 16
        *(u16*)addr = hi

    The "+ 0x8000" accounts for sign-extension of the low 16-bit immediate.
    """

    R_MIPS_LO16 = 2
    """Low 16 bits of a split 32-bit address. Completes the address formed by the preceding HI16 relocation.

    Relocation is applied as follows:
        lo = (symbol + addend) & 0xFFFF
        *(u16*)addr = lo
    """

    R_MIPS_26 = 3
    """26-bit jump target relocation.

    Relocation is applied as follows:
        target = (symbol + addend) >> 2
        instr = (instr & ~0x03FFFFFF) | (target & 0x03FFFFFF)
    """


@dataclass
class Reloc:
    """Represents a MIPS memory relocation."""

    type: RelocType
    addr: int
    addend: int = 0


def _read_s32(f: BinaryIO, peek: bool = False) -> int:
    val: int = unpack("<i", f.read(4))[0]
    if peek:
        f.seek(-4, SEEK_CUR)
    return val


def _read_u32(f: BinaryIO, peek: bool = False) -> int:
    val: int = unpack("<I", f.read(4))[0]
    if peek:
        f.seek(-4, SEEK_CUR)
    return val


def _write_u32(f: BinaryIO, val: int):
    f.write(pack("<I", val & 0xFFFFFFFF))


def _advance_to_sector_boundary(f: BinaryIO):
    # Only advance if we're not already at a boundary
    if f.tell() % SECTOR_SIZE != 0:
        f.read(SECTOR_SIZE - (f.tell() % SECTOR_SIZE))


def _read_relocs(f: BinaryIO) -> list[Reloc]:
    relocs: list[Reloc] = []
    reloc_table_terminator = -1

    while True:
        val = _read_s32(f)
        if val == reloc_table_terminator:
            break

        rel_type = val & RELOC_MASK
        rel_addr = val & ~RELOC_MASK
        rel = Reloc(RelocType(rel_type), rel_addr)

        if rel.type == RelocType.R_MIPS_HI16:
            rel.addend = _read_s32(f)
        relocs.append(rel)

    return relocs


def find_mod_and_relocs(f: BinaryIO) -> tuple[bytes, list[Reloc]]:
    """Extract overlay module and relocation list from binary file stream.

    Args:
        f (BinaryIO): File stream containing the overlay and relocation table.

    Returns:
        tuple[bytes, list[Reloc]]: The bytes of the overlay module and the parsed relocation table.

    Raises:
        AssertionError: If no relocation data can be found.
        AssertionError: If no module can be found.

    """
    # Skip RedirectList
    count = _read_s32(f)
    f.seek((count + 1) * 4)

    _advance_to_sector_boundary(f)

    module_start = f.tell()

    # Only grab relocs and the module
    f.seek(module_start + 0x3C)
    reloc_table_offset = _read_s32(f)
    overlay_offset = _read_s32(f)

    assert overlay_offset != 0, "No module in DRM file"
    assert reloc_table_offset != 0, "No relocation data found in module"

    f.seek(module_start + reloc_table_offset)
    relocs = _read_relocs(f)

    f.seek(module_start + overlay_offset)
    mod_bytes = f.read()

    return mod_bytes, relocs


def create_splat_template(name: str, eof: int, sha_hash: str) -> str:
    """Create a `splat` template for an overlay, if it doesn't already exist.

    Args:
        name (str): Name of the overlay.
        eof (int): Byte offset that marks EOF for the overlay. Usually just the module size.
        sha_hash (str): The SHA1 hash of the overlay bytes.

    Returns:
        str: The `splat` YAML template.

    """
    template = f"""
name: {name} (Overlay)
sha1: {sha_hash}
options:
  basename: KAIN2_{name.upper()}
  target_path: {name}.bin
  base_path: .
  platform: psx
  compiler: gcc
  build_path: BUILD_PATH
  ld_script_path: game/ld/{name}.ld
  find_file_boundaries: False
  use_legacy_include_asm: False
  gp_value: 0x800D7598
  section_order: [".rodata", ".text", ".data", ".bss"]
  symbol_addrs_path:
    - config/syms/symbol_addrs.txt
    - config/syms/symbol_addrs.{name}.txt
  reloc_addrs_path: 
    - config/syms/reloc_addrs.{name}.txt
  undefined_funcs_auto_path: config/syms/undefined_funcs_auto.{name}.txt
  undefined_syms_auto_path: config/syms/undefined_syms_auto.{name}.txt
  extensions_path: tools/splat_ext
  string_encoding: ASCII
  rodata_string_guesser_level: 2
  data_string_encoding: ASCII
  data_string_guesser_level: 2
  subalign: 4
  migrate_rodata_to_functions: True
  hasm_in_src_path: True
  make_full_disasm_for_code: True
  generate_asm_macros_files: False
  asm_data_macro: "glabel"
  asm_data_end_label: ""
  asm_end_label: ""
  asm_function_alt_macro: glabel
  asm_jtbl_label_macro: jlabel
  asm_nonmatching_label_macro: ""
  ld_bss_is_noload: False
  global_vram_start: 0x80010000
  global_vram_end: 0x800E0000
segments:
  - name: main
    type: code
    start: 0x00
    vram: 0x{MODULE_BASE:08X}
    align: 4
    # bss_size: 0x#### # Fill me!
    bss_contains_common: True
    subsegments:
      # - [0x######, rodata, overlay/] # Pick the correct rodata/text/data splits
      - [0x000000, asm, overlay/{name}/asm]
  - [0x{eof:06X}]
"""

    return template


def apply_reloc(module: BytesIO, reloc: Reloc):
    """Apply a single MIPS memory relocation to a binary source.

    Args:
        module (BytesIO): The bytes to apply the relocation to.
        reloc (Reloc): The MIPS relocation to be applied.

    """
    module.seek(reloc.addr)
    symbol = _read_u32(module, True)
    upper = symbol & 0xFFFF0000

    match reloc.type:
        case RelocType.R_MIPS_32:
            if symbol >= 0:
                _write_u32(module, MODULE_BASE + symbol)

        case RelocType.R_MIPS_HI16:
            imm = ((MODULE_BASE + reloc.addend + 0x8000) >> 16) & 0xFFFF
            _write_u32(module, upper | imm)

        case RelocType.R_MIPS_LO16:
            imm = (MODULE_BASE + symbol) & 0xFFFF
            _write_u32(module, upper | imm)

        case RelocType.R_MIPS_26:
            _write_u32(module, symbol + ((MODULE_BASE >> 2) & 0x03FFFFFF))


def undrm(config: OverlayConfig):
    """Apply memory relocations to PSX overlay.

    Args:
        config (OverlayConfig): Configuration for the overlay to be worked on.

    """
    with open(config.src_path, "rb") as f:
        mod_bytes, relocs = find_mod_and_relocs(f)

    mod_new = BytesIO(mod_bytes)

    for reloc in relocs:
        apply_reloc(mod_new, reloc)

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

    if config.splat_yaml_path is not None:
        if not os.path.exists(config.splat_yaml_path):
            config_path = Path(config.splat_yaml_path)
            config_path.parent.mkdir(parents=True, exist_ok=True)

            with open(config_path, "w") as f:
                mod_new.seek(0, SEEK_END)
                mod_len = mod_new.tell()
                sha = hashlib.file_digest(mod_new, "sha1").hexdigest()

                f.write(create_splat_template(config.name, mod_len, sha))
