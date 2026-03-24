import argparse
import os
import sys

from cd_dat_utils.core.config import Config
from cd_dat_utils.core.dat import (
    compare,
    from_dat,
    from_path,
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
    pack_parser.add_argument("config", help="Path to YAML config.")
    pack_parser.add_argument(
        "-i",
        "--input",
        metavar="PATH",
        required=False,
        help="Path to unpacked BIGFILE. Default to config if not provided.",
    )
    pack_parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        required=False,
        help="Path to write packed BIGFILE. Default to config if not provided.",
    )

    unpack_parser = subparsers.add_parser(
        name="unpack", help="Unpack files", description="Unpack files"
    )
    unpack_parser.add_argument("config", help="Path to YAML config.")
    unpack_parser.add_argument(
        "-i",
        "--input",
        metavar="PATH",
        required=False,
        help="Path to packed BIGFILE. Default to config if not provided.",
    )
    unpack_parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        required=False,
        help="Path to write unpacked BIGFILE. Default to config if not provided.",
    )

    compare_parser = subparsers.add_parser(
        name="compare", help="Compare files", description="Compare files"
    )
    compare_parser.add_argument(
        "-a",
        metavar="PATH",
        help="First input path. Defaults to `packed_path` in config.",
        required=False,
    )
    compare_parser.add_argument(
        "-b",
        metavar="PATH",
        help="Second input path. Defaults to `unpacked_path` in config.",
        required=False,
    )
    compare_parser.add_argument("config", help="Path to YAML config.")

    compare_parser = subparsers.add_parser(
        name="unrelocate",
        help="Undo overlay memory address relocations",
        description="Undo overlay memory address relocations",
    )
    compare_parser.add_argument("input", help="Path to the overlay")

    args = parser.parse_args()

    config = Config.from_yaml(args.config)

    match args.command:
        case "unpack":
            if config.bigfile is None:
                print("`bigfile` not found in configuration!")
                sys.exit(1)

            if args.input is not None:
                input = args.input
            else:
                input = config.bigfile.src_path

            if args.output is not None:
                output = args.output
            else:
                output = config.bigfile.src_path

            unpack_bigfile(from_dat(input, config.bigfile), output, config.bigfile)
        case "pack":
            if config.bigfile is None:
                print("`bigfile` not found in configuration!")
                sys.exit(1)

            if args.input is not None:
                input = args.input
            else:
                input = config.bigfile.unpacked_path

            if args.output is not None:
                output = args.output
            else:
                output = config.bigfile.src_path

            pack_bigfile(from_unpacked(input, config.bigfile), output)
        case "compare":
            if config.bigfile is None:
                print("`bigfile` not found in configuration!")
                sys.exit(1)

            if args.a is not None:
                path_a = args.a
            else:
                # NOTE: Unreachable. packed_path is always a value,
                # the type checker just doesn't know that.
                if config.bigfile.packed_path is None:
                    return

                path_a = config.bigfile.packed_path

            if args.b is not None:
                path_b = args.b
            else:
                path_b = config.bigfile.unpacked_path

            a = from_path(path_a, config.bigfile)
            b = from_path(path_b, config.bigfile)

            mismatches = compare(a, b)

            if len(mismatches) > 0:
                print(
                    f"{len(mismatches)} differences found between '{args.a}' and '{args.b}:"
                )
                for mismatch in mismatches:
                    print(f"\t{mismatch}")
            else:
                print(f"No differences found between '{args.a}' and '{args.b}'")


if __name__ == "__main__":  # noqa
    main()
