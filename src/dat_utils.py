from io import BufferedWriter
import os
import json
import shutil
import argparse
from typing import BinaryIO
from pathlib import Path
from pydantic import BaseModel, Field

FOLDER_ENTRY_SIZE = 8
FILE_ENTRY_SIZE = 16


class FileEntry(BaseModel):
    size: int
    offset: int
    hash: int
    checksum: int
    contents: bytes | None = Field(exclude=True, default=None)


class FolderEntry(BaseModel):
    offset: int
    magic: int
    encryption: int
    file_list: list[FileEntry]


class BigFile(BaseModel):
    size: int
    folder_list: list[FolderEntry]
    unmapped_data: FileEntry | None = Field(exclude=True, default=None)


# TODO: If this isn't used in multiple CD titles, make a function table with the different hash methods so
#       they can be specified in the config.
def hash_from_file_path(file_path: str) -> int:
    """
    Generate a hash from a file path using the algorithm from Legacy of Kain: Soul Reaver.
    """

    HASH_EXTENSIONS = ["drm", "crm", "tim", "smp", "snd", "smf", "snf"]

    sum = 0
    xor = 0
    length = 0
    ext_index = 0

    components = file_path.rsplit(".", 1)
    name = file_path

    if len(components) > 1:
        name_no_ext, ext = components

        if ext in HASH_EXTENSIONS:
            ext_index = HASH_EXTENSIONS.index(ext)
            name = name_no_ext

    for c in name[::-1]:
        if c == "\\":
            continue

        c = c.upper()
        c = chr(ord(c) - 0x1A)
        sum += ord(c)
        xor ^= ord(c) * length
        length += 1

    return (length << 27) | (sum << 15) | (xor << 3) | ext_index


def read_file(file: BinaryIO, offset: int) -> FileEntry:
    file.seek(offset)
    hash = int.from_bytes(file.read(4), "little")
    size = int.from_bytes(file.read(4), "little")
    file_offset = int.from_bytes(file.read(4), "little")
    checksum = int.from_bytes(file.read(4), "little")

    file.seek(file_offset)
    return FileEntry(
        size=size,
        offset=file_offset,
        hash=hash,
        checksum=checksum,
        contents=file.read(size),
    )


def read_folder(file: BinaryIO, offset: int) -> FolderEntry:
    file.seek(offset)
    magic = int.from_bytes(file.read(2), "little")
    num_files = int.from_bytes(file.read(2), "little")
    folder_offset = int.from_bytes(file.read(4), "little")
    folder = FolderEntry(
        offset=folder_offset,
        magic=magic,
        encryption=0,  # TODO
        file_list=[],
    )

    file.seek(folder_offset)
    num_files_record = int.from_bytes(file.read(2), "little")
    assert file.read(2) == b"\x00\x00", (
        "Encrypted bytes found. Encryption not supported at this time."
    )

    assert num_files == num_files_record, (
        f"Mismatch between number of files in folder entry and folder record. Entry: {num_files} Record: {num_files_record}"
    )

    for i in range(num_files):
        entry_offset = (i * FILE_ENTRY_SIZE) + folder_offset + 4
        folder.file_list.append(read_file(file, entry_offset))

    return folder


def from_dat(path: str, config: dict, config_path: str) -> BigFile:
    with open(path, "rb") as file:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)

        bigfile = BigFile(
            size=size,
            folder_list=[],
        )

        num_folders = int.from_bytes(file.read(2), "little")
        file.read(2)

        for i in range(num_folders):
            offset = (i * FOLDER_ENTRY_SIZE) + 4
            bigfile.folder_list.append(read_folder(file, offset))

        unmapped_data = config.get("unmapped_data")

        if unmapped_data is not None:
            file.seek(unmapped_data["offset"])

            bigfile.unmapped_data = FileEntry(
                size=unmapped_data["size"],
                offset=unmapped_data["offset"],
                hash=0,
                checksum=0,
                contents=file.read(unmapped_data["size"]),
            )

        if config.get("structure") is None:
            print("File structure not found in config. Writing...")
            config["structure"] = bigfile.model_dump()
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)

        return bigfile


def unpack_bigfile(bigfile: BigFile, config: dict, output_dir: str) -> None:
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    os.makedirs(output_dir)

    if bigfile.unmapped_data and bigfile.unmapped_data.contents:
        with open(os.path.join(output_dir, "UNMAPPED_DATA.bin"), "wb") as f:
            f.write(bigfile.unmapped_data.contents)

    duplicates = {}

    for folder in bigfile.folder_list:
        for file in folder.file_list:
            file_name = config.get("file_names", {}).get(
                str(file.hash), f"{file.hash}.bin"
            )

            if file_name not in duplicates.keys():
                duplicates[file_name] = 0
            else:
                duplicates[file_name] += 1
                base, ext = os.path.splitext(file_name)
                file_name = f"{base}_duplicate{duplicates[file_name]}{ext}"

            full_path = os.path.join(output_dir, file_name)

            if "\\" in file_name:
                *subfolders, file_name = file_name.split("\\")
                subpath = os.path.join(output_dir, *subfolders)

                if not os.path.exists(subpath):
                    Path(subpath).mkdir(parents=True, exist_ok=True)

                full_path = os.path.join(subpath, file_name)

            if file.contents:
                with open(full_path, "wb") as outfile:
                    outfile.write(file.contents)


def write_file(file: FileEntry, header_offset: int, writer: BufferedWriter):
    if file.contents:
        writer.seek(header_offset)
        writer.write(file.hash.to_bytes(4, "little"))
        writer.write(file.size.to_bytes(4, "little"))
        writer.write(file.offset.to_bytes(4, "little"))
        writer.write(file.checksum.to_bytes(4, "little"))

        writer.seek(file.offset)
        writer.write(file.contents)


def write_folder(folder: FolderEntry, header_offset: int, writer: BufferedWriter):
    writer.seek(header_offset)

    writer.write(folder.magic.to_bytes(2, "little"))
    writer.write(len(folder.file_list).to_bytes(2, "little"))
    writer.write(folder.offset.to_bytes(4, "little"))

    writer.seek(folder.offset)
    writer.write(len(folder.file_list).to_bytes(2, "little"))
    writer.write(b"\x00\x00")

    for i, file in enumerate(folder.file_list):
        offset = (i * FILE_ENTRY_SIZE) + folder.offset + 4
        write_file(file, offset, writer)


def pack_bigfile(bigfile: BigFile, output_path: str) -> None:
    with open(output_path, "wb", 0) as f:
        with BufferedWriter(f, bigfile.size) as writer:
            writer.write(len(bigfile.folder_list).to_bytes(2, "little"))
            writer.write(b"\x00\x00")

            for i, folder in enumerate(bigfile.folder_list):
                offset = (i * FOLDER_ENTRY_SIZE) + 4
                write_folder(folder, offset, writer)

            if bigfile.unmapped_data and bigfile.unmapped_data.contents:
                writer.seek(bigfile.unmapped_data.offset)
                writer.write(bigfile.unmapped_data.contents)


def from_unpacked(input_dir: str, config: dict) -> BigFile:
    if not os.path.exists(input_dir):
        raise Exception(f"Input directory {input_dir} does not exist")

    if config.get("structure") is None:
        raise Exception("'structure' does not exist in config file!")

    bigfile = BigFile.model_validate_json(json.dumps(config["structure"]))

    already_read_files = {}
    file_names = config.get("file_names", {})

    for folder in bigfile.folder_list:
        for file in folder.file_list:
            file_name = file_names.get(str(file.hash), f"{file.hash}.bin")

            if already_read_files.get(file_name) is None:
                already_read_files[file_name] = 0
            else:
                already_read_files[file_name] += 1
                name, ext = file_name.rsplit(".", 1)
                file_name = f"{name}_duplicate{already_read_files[file_name]}.{ext}"

            full_file_path = os.path.join(input_dir, file_name)

            if "\\" in file_name:
                *subfolders, file_name = file_name.split("\\")
                subpath = os.path.join(input_dir, *subfolders)

                full_file_path = os.path.join(subpath, file_name)

            if not os.path.exists(full_file_path):
                raise Exception(f"File {full_file_path} cannot be found!")

            with open(full_file_path, "rb") as f:
                file.contents = f.read()

    unmapped_data = config.get("unmapped_data")

    if unmapped_data is not None:
        with open(os.path.join(input_dir, "UNMAPPED_DATA.bin"), "rb") as f:
            bigfile.unmapped_data = FileEntry(
                size=unmapped_data["size"],
                offset=unmapped_data["offset"],
                hash=0,
                checksum=0,
                contents=f.read(),
            )

    return bigfile


def compare_unmapped_data(a: FileEntry | None, b: FileEntry | None, errors: list[str]):
    if a is None and b is not None:
        errors.append("Unmapped data mismatch! a has no unmapped data, but b does")
        return

    if a is not None and b is None:
        errors.append("Unmapped data mismatch! a has unmapped data, but b doesn't")
        return

    if a is not None and b is not None:
        if a.size != b.size:
            errors.append(
                f"Size mismatch for unmapped data! a: {a.size} bytes, b: {b.size} bytes"
            )

        if a.offset != b.offset:
            errors.append(
                f"Offset mismatch for unmapped data! a: {a.offset}, b: {b.offset}"
            )

        if a.contents != b.contents:
            errors.append("Content mismatch for unmapped data!")


def compare_file(
    a: FileEntry, b: FileEntry, folder_idx: int, file_idx: int, errors: list[str]
):
    if a.size != b.size:
        errors.append(
            f"Mismatch between file sizes at folder {folder_idx} - file {file_idx}! a: {a.size} bytes, b: {b.size} bytes"
        )

    if a.offset != b.offset:
        errors.append(
            f"Mismatch between file offsets at folder {folder_idx} - file {file_idx}! a: {a.offset}, b: {b.offset}"
        )

    if a.hash != b.hash:
        errors.append(
            f"Mismatch between file hashes at folder {folder_idx} - file {file_idx}! a: {a.hash}, b: {b.hash}"
        )

    if a.checksum != b.checksum:
        errors.append(
            f"Mismatch between file checksums at folder {folder_idx} - file {file_idx}! a: {a.checksum}, b: {b.checksum}"
        )

    if a.contents != b.contents:
        errors.append(
            f"Mismatch between file contents at folder {folder_idx} - file {file_idx}!"
        )


def compare_folder(
    folder_a: FolderEntry, folder_b: FolderEntry, folder_idx: int, errors: list[str]
):
    if len(folder_a.file_list) != len(folder_b.file_list):
        errors.append(
            f"Mismatch between number of files at folder {folder_idx}! a: {len(folder_a.file_list)}, b: {len(folder_b.file_list)}"
        )

    if folder_a.offset != folder_b.offset:
        errors.append(
            f"Mismatch between offsets at folder {folder_idx}! a: {folder_a.offset}, b: {folder_b.offset}"
        )

    if folder_a.magic != folder_b.magic:
        errors.append(
            f"Mismatch between magic bytes folder {folder_idx}! a: {folder_a.magic}, b: {folder_b.magic}"
        )

    if folder_a.encryption != folder_b.encryption:
        errors.append(
            f"Mismatch between encryption key at folder {folder_idx}! a: {folder_a.encryption}, b: {folder_b.encryption}"
        )

    for i, (a, b) in enumerate(zip(folder_a.file_list, folder_b.file_list)):
        compare_file(a, b, folder_idx, i, errors)


def compare(path_a: str, path_b: str, config: dict, config_path: str) -> list[str]:
    errors = []

    if os.path.isfile(path_a):
        bigfile_a = from_dat(path_a, config, config_path)
    else:
        bigfile_a = from_unpacked(path_a, config)

    if os.path.isfile(path_b):
        bigfile_b = from_dat(path_b, config, config_path)
    else:
        bigfile_b = from_unpacked(path_b, config)

    if len(bigfile_a.folder_list) != len(bigfile_b.folder_list):
        errors.append(
            f"Mismatch between number of folders! a: {len(bigfile_a.folder_list)}, b: {len(bigfile_b.folder_list)}"
        )

    if bigfile_a.size != bigfile_b.size:
        errors.append(
            f"Mismatch between file sizes! a: {bigfile_a.size} bytes, b: {bigfile_b.size} bytes"
        )

    compare_unmapped_data(bigfile_a.unmapped_data, bigfile_b.unmapped_data, errors)

    for i, (a, b) in enumerate(zip(bigfile_a.folder_list, bigfile_b.folder_list)):
        compare_folder(a, b, i, errors)

    return errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="command", required=True)

    pack_parser = subparsers.add_parser("pack", help="Pack files")
    pack_parser.add_argument("input", help="Input path")
    pack_parser.add_argument("output", help="Output path")

    unpack_parser = subparsers.add_parser("unpack", help="Unpack files")
    unpack_parser.add_argument("input", help="Input path")
    unpack_parser.add_argument("output", help="Output path")

    compare_parser = subparsers.add_parser("compare", help="Compare files")
    compare_parser.add_argument("input1", help="First input path")
    compare_parser.add_argument("input2", help="Second input path")

    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to JSON config. Defaults to 'config.json'",
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        raise Exception(f"config file {args.config} could not be found")

    with open(args.config) as f:
        config = json.load(f)

    match args.command:
        case "unpack":
            assert os.path.exists(args.input), (
                f"Input file {args.input} does not exist!"
            )
            assert os.path.isfile(args.input), f"Input file {args.input} is not a file!"
            unpack_bigfile(
                from_dat(args.input, config, args.config), config, args.output
            )
        case "pack":
            assert os.path.exists(args.input), (
                f"Input directory {args.input} does not exist!"
            )
            assert os.path.isdir(args.input), (
                f"Input directory {args.input} is not a directory!"
            )
            pack_bigfile(from_unpacked(args.input, config), args.output)
        case "compare":
            assert os.path.exists(args.input1), f"Input {args.input1} does not exist!"
            assert os.path.exists(args.input2), f"Input {args.input2} does not exist!"
            errors = compare(args.input1, args.input2, config, args.config)

            if len(errors) > 0:
                print(f"Differences found between '{args.input1}' and '{args.input2}:")
                for error in errors:
                    print(f"\t{error}")
            else:
                print(
                    f"No differences found between '{args.input1}' and '{args.input2}'"
                )
