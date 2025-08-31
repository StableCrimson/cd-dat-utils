from io import BufferedReader, BufferedWriter
import os
import json
import shutil
import argparse
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


CONFIG = {}


def hash_from_file_path(file_path: str) -> int:
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


def read_file(file: BufferedReader, offset: int) -> FileEntry:
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


def read_folder(file: BufferedReader, offset: int) -> FolderEntry:
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
    assert (
        file.read(2) == b"\x00\x00"
    ), "Encrypted bytes found. Encryption not supported at this time."

    assert (
        num_files == num_files_record
    ), f"Mismatch between number of files in folder entry and folder record. Entry: {num_files} Record: {num_files_record}"

    for i in range(num_files):
        entry_offset = (i * FILE_ENTRY_SIZE) + folder_offset + 4
        folder.file_list.append(read_file(file, entry_offset))

    return folder


def from_dat(path: str, config_path: str) -> BigFile:
    with open(path, "rb") as file:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)

        bigfile = BigFile(
            size=size,
            folder_list=[],
        )

        num_folders = int.from_bytes(file.read(2), "little")
        assert file.read(2) == b"\x00\x00"

        for i in range(num_folders):
            offset = (i * FOLDER_ENTRY_SIZE) + 4
            bigfile.folder_list.append(read_folder(file, offset))

        unmapped_data = CONFIG.get("unmapped_data")

        if unmapped_data is not None:
            file.seek(unmapped_data["offset"])

            bigfile.unmapped_data = FileEntry(
                size=unmapped_data["size"],
                offset=unmapped_data["offset"],
                hash=0,
                checksum=0,
                contents=file.read(unmapped_data["size"]),
            )

        if CONFIG.get("structure") is None:
            print(f"File structure not found in config. Writing...")
            CONFIG["structure"] = bigfile.model_dump()
            with open(config_path, "w") as f:
                json.dump(CONFIG, f, indent=2)

        return bigfile


def unpack_bigfile(bigfile: BigFile, output_dir: str) -> None:
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    os.makedirs(output_dir)

    if bigfile.unmapped_data and bigfile.unmapped_data.contents:
        with open(os.path.join(output_dir, "UNMAPPED_DATA.bin"), "wb") as f:
            f.write(bigfile.unmapped_data.contents)

    duplicates = {}

    for folder in bigfile.folder_list:
        for file in folder.file_list:
            file_name = CONFIG.get("file_names", {}).get(
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


def from_unpacked(input_dir: str) -> BigFile:
    if not os.path.exists(input_dir):
        raise Exception(f"Input directory {input_dir} does not exist")

    if CONFIG.get("structure") is None:
        raise Exception("'structure' does not exist in config file!")

    bigfile = BigFile.model_validate_json(json.dumps(CONFIG["structure"]))

    already_read_files = {}
    file_names = CONFIG.get("file_names", {})

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

    unmapped_data = CONFIG.get("unmapped_data")

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


def compare_unmapped_data(a: FileEntry | None, b: FileEntry | None):

    if a is None:
        assert b is None, "Unmapped data mismatch! a has no unmapped data, but b does"
        return

    if b is None:
        assert a is None, "Unmapped data mismatch! a has unmapped data, but b doesn't"
        return

    assert (
        a.size == b.size
    ), f"Size mismatch for unmapped data! a: {a.size} bytes, b: {b.size} bytes"

    assert (
        a.offset == b.offset
    ), f"Offset mismatch for unmapped data! a: {a.offset}, b: {b.offset}"

    assert a.contents == b.contents, "Content mismatch for unmapped data!"


def compare_file(a: FileEntry, b: FileEntry, folder_idx: int, file_idx: int):

    assert (
        a.size == b.size
    ), f"Mismatch between file sizes at folder {folder_idx} - file {file_idx}! a: {a.size} bytes, b: {b.size} bytes"

    assert (
        a.offset == b.offset
    ), f"Mismatch between file offsets at folder {folder_idx} - file {file_idx}! a: {a.offset}, b: {b.offset}"

    assert (
        a.hash == b.hash
    ), f"Mismatch between file hashes at folder {folder_idx} - file {file_idx}! a: {a.hash}, b: {b.hash}"

    assert (
        a.checksum == b.checksum
    ), f"Mismatch between file checksums at folder {folder_idx} - file {file_idx}! a: {a.checksum}, b: {b.checksum}"

    assert (
        a.contents == b.contents
    ), f"Mismatch between file contents at folder {folder_idx} - file {file_idx}!"


def compare_folder(folder_a: FolderEntry, folder_b: FolderEntry, folder_idx: int):

    assert len(folder_a.file_list) == len(
        folder_b.file_list
    ), f"Mismatch between number of files at folder {folder_idx}! a: {len(folder_a.file_list)}, b: {len(folder_b.file_list)}"

    assert (
        folder_a.offset == folder_b.offset
    ), f"Mismatch between offsets at folder {folder_idx}! a: {folder_a.offset}, b: {folder_b.offset}"

    assert (
        folder_a.magic == folder_b.magic
    ), f"Mismatch between magic bytes folder {folder_idx}! a: {folder_a.magic}, b: {folder_b.magic}"

    assert (
        folder_a.encryption == folder_b.encryption
    ), f"Mismatch between encryption key at folder {folder_idx}! a: {folder_a.encryption}, b: {folder_b.encryption}"

    for i, (a, b) in enumerate(zip(folder_a.file_list, folder_b.file_list)):
        compare_file(a, b, folder_idx, i)


def compare(path_a: str, path_b: str, config_path: str):
    if os.path.isfile(path_a):
        bigfile_a = from_dat(path_a, config_path)
    else:
        bigfile_a = from_unpacked(path_a)

    if os.path.isfile(path_b):
        bigfile_b = from_dat(path_b, config_path)
    else:
        bigfile_b = from_unpacked(path_b)

    compare_unmapped_data(bigfile_a.unmapped_data, bigfile_b.unmapped_data)

    assert len(bigfile_a.folder_list) == len(
        bigfile_b.folder_list
    ), f"Mismatch between number of folders! a: {len(bigfile_a.folder_list)}, b: {len(bigfile_b.folder_list)}"

    assert (
        bigfile_a.size == bigfile_b.size
    ), f"Mismatch between file sizes! a: {bigfile_a.size} bytes, b: {bigfile_b.size} bytes"

    for i, (a, b) in enumerate(zip(bigfile_a.folder_list, bigfile_b.folder_list)):
        compare_folder(a, b, i)

    print(f"No differences found between '{path_a}' and '{path_b}'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to JSON config. Defaults to 'config.json'",
    )

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

    args = parser.parse_args()

    if not os.path.exists(args.config):
        raise Exception(f"Config file {args.config} could not be found")

    with open(args.config) as f:
        CONFIG = json.load(f)

    match args.command:
        case "unpack":
            assert os.path.exists(
                args.input
            ), f"Input file {args.input} does not exist!"
            assert os.path.isfile(args.input), f"Input file {args.input} is not a file!"
            unpack_bigfile(from_dat(args.input, args.config), args.output)
        case "pack":
            assert os.path.exists(
                args.input
            ), f"Input directory {args.input} does not exist!"
            assert os.path.isdir(
                args.input
            ), f"Input directory {args.input} is not a directory!"
            pack_bigfile(from_unpacked(args.input), args.output)
        case "compare":
            assert os.path.exists(args.input1), f"Input {args.input1} does not exist!"
            assert os.path.exists(args.input2), f"Input {args.input2} does not exist!"
            compare(args.input1, args.input2, args.config)
