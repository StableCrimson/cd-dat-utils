import argparse
import os

from cd_dat_utils.core.config import Config
from cd_dat_utils.core.dat import (
    compare,
    from_dat,
    from_unpacked,
    pack_bigfile,
    unpack_bigfile,
)


def main():  # noqa
    parser = argparse.ArgumentParser(
        prog="cd-dat-utils",
        description="A command line utility for working with BIGFILEs",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    pack_parser = subparsers.add_parser(
        name="pack", help="Pack files", description="Pack files"
    )
    pack_parser.add_argument(
        "config",
        help="Path to JSON config. Defaults to 'config.json'",
    )

    unpack_parser = subparsers.add_parser(
        name="unpack", help="Unpack files", description="Unpack files"
    )
    unpack_parser.add_argument(
        "config",
        help="Path to JSON config. Defaults to 'config.json'",
    )

    compare_parser = subparsers.add_parser(
        name="compare", help="Compare files", description="Compare files"
    )
    compare_parser.add_argument("input1", help="First input path")
    compare_parser.add_argument("input2", help="Second input path")
    compare_parser.add_argument(
        "config", help="Path to JSON config. Defaults to 'config.json'"
    )

    compare_parser = subparsers.add_parser(
        name="unrelocate",
        help="Undo overlay memory address relocations",
        description="Undo overlay memory address relocations",
    )
    compare_parser.add_argument("input", help="Path to the overlay")

    args = parser.parse_args()

    if not os.path.exists(args.config):
        raise Exception(f"config file {args.config} could not be found")

    config = Config.from_yaml(args.config)

    match args.command:
        case "unpack":
            unpack_bigfile(from_dat(config), config)
        case "pack":
            pack_bigfile(from_unpacked(config), config)
        case "compare":
            assert os.path.exists(args.input1), f"Input {args.input1} does not exist!"
            assert os.path.exists(args.input2), f"Input {args.input2} does not exist!"

            if os.path.isfile(args.input1):
                a = from_dat(config)
            else:
                a = from_unpacked(config)

            if os.path.isfile(args.input2):
                b = from_dat(config)
            else:
                b = from_unpacked(config)

            mismatches = compare(a, b)

            if len(mismatches) > 0:
                print(
                    f"{len(mismatches)} differences found between '{args.input1}' and '{args.input2}:"
                )
                for mismatch in mismatches:
                    print(f"\t{mismatch}")
            else:
                print(
                    f"No differences found between '{args.input1}' and '{args.input2}'"
                )
