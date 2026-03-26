import hashlib
import os
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


def create_splat_template(name: str, eof: int, sha_hash: str) -> str:
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

    if config.splat_yaml_path is not None:
        if not os.path.exists(config.splat_yaml_path):
            config_path = Path(config.splat_yaml_path)
            config_path.parent.mkdir(parents=True, exist_ok=True)

            with open(config_path, "w") as f:
                mod_new.seek(0, 2)
                mod_len = mod_new.tell()
                sha = hashlib.file_digest(mod_new, "sha1").hexdigest()

                f.write(create_splat_template(config.name, mod_len, sha))
