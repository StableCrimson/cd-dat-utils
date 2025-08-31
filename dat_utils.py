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


def from_unpacked(input_dir: str, json_config: str) -> BigFile:
    if not os.path.exists(input_dir):
        raise Exception(f"Input directory {input_dir} does not exist")

    if not os.path.exists(json_config):
        raise Exception(f"JSON config file {json_config} does not exist")

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices={"unpack", "pack"})
    parser.add_argument("input", help="Path to source")
    parser.add_argument("output", help="Path to target")
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to JSON config. Defaults to 'config.json'",
    )
    args = parser.parse_args()

    if not os.path.exists(args.config):
        raise Exception(f"Config file {args.config} could not be found")

    with open(args.config) as f:
        CONFIG = json.load(f)

    if not os.path.exists(args.input):
        raise Exception(f"Input {args.input} could not be found")

    if args.operation == "pack":
        bigfile = from_unpacked(args.input, args.config)
        pack_bigfile(bigfile, args.output)
    else:
        bigfile = from_dat(args.input, args.config)
        unpack_bigfile(bigfile, args.output)
