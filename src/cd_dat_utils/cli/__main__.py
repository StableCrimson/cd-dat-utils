import argparse

from cd_dat_utils.cli.commands import (
    command_compare,
    command_pack,
    command_undrm,
    command_unpack,
)


def main():  # noqa
    parser = argparse.ArgumentParser(
        prog="cd-dat-utils",
        description="A command line utility for working with BIGFILEs",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Pack
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

    # Unpack
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

    # Compare
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

    # Un-DRM
    undrm_parser = subparsers.add_parser(
        name="undrm",
        help="Perform memory relocations to generate a binary that can be decompiled",
        description="Perform memory relocations to generate a binary that can be decompiled",
    )
    undrm_parser.add_argument("config", help="Path to the YAML config.")

    args = parser.parse_args()

    match args.command:
        case "unpack":
            command_unpack(args.config, args.input, args.output)
        case "pack":
            command_pack(args.config, args.input, args.output)
        case "compare":
            command_compare(args.config, args.a, args.b)
        case "undrm":
            command_undrm(args.config)


if __name__ == "__main__":  # noqa
    main()
