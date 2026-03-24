import sys
from typing import Optional

from cd_dat_utils.core.config import Config
from cd_dat_utils.core.dat import (
    compare,
    from_dat,
    from_path,
    from_unpacked,
    pack_bigfile,
    unpack_bigfile,
)


def command_pack(
    config_path: str, input: Optional[str] = None, output: Optional[str] = None
):
    config = Config.from_yaml(config_path)

    if config.bigfile is None:
        print("`bigfile` not found in configuration!")
        sys.exit(1)

    if input is None:
        input = config.bigfile.unpacked_path

    if output is None:
        # NOTE: Unreachable. packed_path is always a value,
        # the type checker just doesn't know that.
        if config.bigfile.packed_path is None:  # noqa
            return

        output = config.bigfile.packed_path

    pack_bigfile(from_dat(input, config.bigfile), output)


def command_unpack(
    config_path: str, input: Optional[str] = None, output: Optional[str] = None
):
    config = Config.from_yaml(config_path)

    if config.bigfile is None:
        print("`bigfile` not found in configuration!")
        sys.exit(1)

    if input is None:
        input = config.bigfile.src_path

    if output is None:
        output = config.bigfile.unpacked_path

    unpack_bigfile(from_dat(input, config.bigfile), output, config.bigfile)


def command_compare(
    config_path: str, path_a: Optional[str] = None, path_b: Optional[str] = None
):
    config = Config.from_yaml(config_path)

    if config.bigfile is None:
        print("`bigfile` not found in configuration!")
        sys.exit(1)

    if path_a is None:
        # NOTE: Unreachable. packed_path is always a value,
        # the type checker just doesn't know that.
        if config.bigfile.packed_path is None:  # noqa
            return

        path_a = config.bigfile.packed_path

    if path_b is None:
        path_b = config.bigfile.unpacked_path

    a = from_path(path_a, config.bigfile)
    b = from_path(path_b, config.bigfile)

    mismatches = compare(a, b)

    if len(mismatches) > 0:
        print(f"{len(mismatches)} differences found between '{path_a}' and '{path_b}:")
        for mismatch in mismatches:
            print(f"\t{mismatch}")
    else:
        print(f"No differences found between '{path_a}' and '{path_b}'")
