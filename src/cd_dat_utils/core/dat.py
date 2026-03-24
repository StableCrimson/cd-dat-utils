import json
import os
import shutil
from io import BufferedWriter
from pathlib import Path
from struct import pack, unpack
from typing import BinaryIO, Optional

import pylibyaml  # Needed - Patches several `yaml` methods for huge performance improvements
import yaml
from pydantic import BaseModel, Field

from cd_dat_utils.core.config import BigFileConfig

PADDING = 0

BIGFILE_HEADER_SIZE = 4
"""Size in bytes of BIGFILE header."""

FOLDER_ENTRY_SIZE = 8
"""Size in bytes of folder entry."""

FOLDER_RECORD_SIZE = 4
"""Size in bytes of folder header preceding files."""

FILE_ENTRY_SIZE = 16
"""Size in bytes of file entry."""


class FileEntry(BaseModel):
    """A parsed file header and its contents."""

    size: int
    offset: int
    hash: int
    checksum: int
    contents: bytes | None = Field(exclude=True, default=None)


class FolderEntry(BaseModel):
    """A parsed folder header and its constituent files."""

    offset: int
    magic: int
    encryption: int
    file_list: list[FileEntry]


class UnmappedEntry(BaseModel):
    """Parsed segment of unmapped non-padding data and its contents."""

    size: int
    offset: int
    contents: bytes | None = Field(exclude=True, default=None)


class BigFile(BaseModel):
    """A fully parsed BIGFILE."""

    size: int
    folder_list: list[FolderEntry]
    unmapped_data: list[UnmappedEntry] = Field(default=[])

    @classmethod
    def from_json(cls, path: str):
        """Create a `BigFile` instance from a JSON file.

        Args:
            path (str): Path to the JSON file.

        Returns:
            BigFile: The deserialized BIGFILE.

        """
        with open(path) as f:
            return cls.model_validate(json.load(f) or {})

    def write_json(self, path: str):
        """Write a `BigFile` instance to a JSON file.

        Args:
            path (str): Path to the JSON file.

        """
        with open(path, "w") as f:
            json.dump(self.model_dump(), f, indent=2)

    @classmethod
    def from_yaml(cls, path: str):
        """Create a `BigFile` instance from a YAML file.

        Args:
            path (str): Path to the YAML file.

        Returns:
            BigFile: The deserialized BIGFILE.

        """
        with open(path) as f:
            return cls.model_validate(yaml.safe_load(f) or {})

    def write_yaml(self, path: str):
        """Write a `BigFile` instance to a YAML file.

        Args:
            path (str): Path to the JSON file.

        """
        with open(path, "w") as f:
            f.write(yaml.safe_dump(self.model_dump(), sort_keys=False, indent=2))


# TODO: If this isn't used in multiple CD titles, make a function table with the different hash methods so
#       they can be specified in the config.
def hash_from_file_path(file_path: str) -> int:
    """Generate a hash from a file path using the algorithm from Legacy of Kain: Soul Reaver.

    Args:
        file_path (str): The path of the file relative to the BIGFILE root.

    Returns:
        int: The hash generated from the file path.

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


# TODO: Make all of these class methods


def read_file(file: BinaryIO, header_offset: int) -> FileEntry:
    """Given a binary bytestream and a file header offset, read the header and contents to create a `FileEntry`.

    Args:
        file (BinaryIO): The binary source to read from.
        header_offset (int): The byte offset of the file header entry.

    Returns:
        FileEntry: The parsed file header and its contents.

    """
    file.seek(header_offset)
    hash, size, offset, checksum = unpack("<IIII", file.read(FILE_ENTRY_SIZE))
    file.seek(offset)

    return FileEntry(
        size=size,
        offset=offset,
        hash=hash,
        checksum=checksum,
        contents=file.read(size),
    )


def read_folder(file: BinaryIO, header_offset: int) -> FolderEntry:
    """Given a binary bytestream and a folder header offset, read the header and all files it contains to create a `FolderEntry`.

    Args:
        file (BinaryIO): The binary source to read from.
        header_offset (int): The byte offset of the folder header entry.

    Returns:
        FolderEntry: The parsed folder header and all files within it.

    Raises:
        AssertionError: If the folder contains encryption, which is not supported at this time.
        AssertionError: If there is a mismatch between the number of files stated in the folder header and
                        the actual folder record.

    """
    file.seek(header_offset)
    magic, num_files, offset = unpack("<HHI", file.read(FOLDER_ENTRY_SIZE))

    folder = FolderEntry(
        offset=offset,
        magic=magic,
        encryption=0,  # TODO
        file_list=[],
    )

    file.seek(offset)
    num_files_record, encryption = unpack("<HH", file.read(FOLDER_RECORD_SIZE))
    assert encryption == PADDING, (
        "Encrypted bytes found. Encryption not supported at this time."
    )

    assert num_files == num_files_record, (
        f"Mismatch between number of files in folder entry and folder record. Entry: {num_files} Record: {num_files_record}"
    )

    for i in range(num_files):
        entry_offset = (i * FILE_ENTRY_SIZE) + offset + FOLDER_RECORD_SIZE
        folder.file_list.append(read_file(file, entry_offset))

    return folder


def from_dat(path: str, config: BigFileConfig) -> BigFile:
    """Create a `BigFile` instance from a packed DAT.

    Args:
        path (str): Path to the DAT.
        config (BigFileConfig): The BIGFILE config.

    Returns:
        BigFile: The parsed BIGFILE.

    Raises:
        Exception: Source path does not exist.
        Exception: Source path exists, but is not a file.

    """
    if not os.path.exists(path):
        raise Exception(f"Input {path} does not exist!")

    if not os.path.isfile(path):
        raise Exception(f"Input {path} is not a file!")

    with open(path, "rb") as file:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)

        bigfile = BigFile(size=size, folder_list=[], unmapped_data=[])

        num_folders, *_ = unpack("<HH", file.read(BIGFILE_HEADER_SIZE))

        for i in range(num_folders):
            offset = (i * FOLDER_ENTRY_SIZE) + BIGFILE_HEADER_SIZE
            bigfile.folder_list.append(read_folder(file, offset))

        if not os.path.exists(config.structure_path):
            bigfile.write_yaml(config.structure_path)
        else:
            structure = BigFile.from_yaml(config.structure_path)

            for unmapped in structure.unmapped_data:
                file.seek(unmapped.offset)
                bigfile.unmapped_data.append(
                    UnmappedEntry(
                        size=unmapped.size,
                        offset=unmapped.offset,
                        contents=file.read(unmapped.size),
                    )
                )

        return bigfile


def unpack_bigfile(bigfile: BigFile, path: str, config: BigFileConfig):
    """Unpack a parsed BIGFILE to a target folder.

    Args:
        bigfile (BigFile): Parsed BIGFILE to be unpacked.
        path (str): Path to write the unpacked BIGFILE to.
        config (BigFileConfig): The BIGFILE config.

    """
    if os.path.exists(path):
        shutil.rmtree(path)

    os.makedirs(path)

    if len(bigfile.unmapped_data) > 0:
        unmapped_folder = os.path.join(path, "unmapped_data")

        if not os.path.exists(unmapped_folder):
            Path(unmapped_folder).mkdir(parents=True, exist_ok=True)

        for unmapped in bigfile.unmapped_data:
            if unmapped.contents is not None:
                filename = f"unmapped_{unmapped.offset}.bin"
                path = os.path.join(path, "unmapped_data", filename)
                with open(path, "wb") as f:
                    f.write(unmapped.contents)

    duplicates: dict[str, int] = {}

    for folder in bigfile.folder_list:
        for file in folder.file_list:
            file_name = config.file_map.get(file.hash, f"{file.hash}.bin")

            if file_name not in duplicates.keys():
                duplicates[file_name] = 0
            else:
                duplicates[file_name] += 1
                base, ext = os.path.splitext(file_name)
                file_name = f"{base}_duplicate{duplicates[file_name]}{ext}"

            full_path = os.path.join(path, file_name)

            if "\\" in file_name:
                *subfolders, file_name = file_name.split("\\")
                subpath = os.path.join(path, *subfolders)

                if not os.path.exists(subpath):
                    Path(subpath).mkdir(parents=True, exist_ok=True)

                full_path = os.path.join(subpath, file_name)

            if file.contents:
                with open(full_path, "wb") as outfile:
                    outfile.write(file.contents)


def write_unmapped_data(unmapped_data: UnmappedEntry, buffer: BufferedWriter):
    """Write an unmapped segment to a BIGFILE.

    Args:
        unmapped_data (UnmappedEntry): The unmapped segment to be written.
        buffer (BufferedWriter): The buffer the unmapped segment will be written to.

    """
    if unmapped_data.contents is not None:
        buffer.seek(unmapped_data.offset)
        buffer.write(unmapped_data.contents)


def write_file(file: FileEntry, header_offset: int, buffer: BufferedWriter):
    """Write a file to a BIGFILE.

    Args:
        file (FileEntry): The FileEntry to be written.
        header_offset (int): The byte offset where the file header should be written.
        buffer (BufferedWriter): The buffer the file will be written to.

    """
    if file.contents:
        buffer.seek(header_offset)
        buffer.write(pack("<IIII", file.hash, file.size, file.offset, file.checksum))

        buffer.seek(file.offset)
        buffer.write(file.contents)


def write_folder(folder: FolderEntry, header_offset: int, buffer: BufferedWriter):
    """Write a folder and all files it contains to a BIGFILE.

    Args:
        folder (FolderEntry): The FolderEntry to be written.
        header_offset (int): The byte offset where the folder header should be written.
        buffer (BufferedWriter): The buffer the folder will be written to.

    """
    buffer.seek(header_offset)
    buffer.write(pack("<HHI", folder.magic, len(folder.file_list), folder.offset))

    buffer.seek(folder.offset)
    buffer.write(pack("<HH", len(folder.file_list), PADDING))

    for i, file in enumerate(folder.file_list):
        offset = (i * FILE_ENTRY_SIZE) + folder.offset + FOLDER_RECORD_SIZE
        write_file(file, offset, buffer)


def pack_bigfile(bigfile: BigFile, path: str):
    """Packs and writes a `BigFile` object to a DAT.

    Args:
        bigfile (BigFile): The BigFile to be written.
        path (str): Path to write the packed BIGFILE to.

    """
    with open(path, "wb", 0) as f:
        with BufferedWriter(f, bigfile.size) as buffer:
            buffer.write(pack("<HH", len(bigfile.folder_list), PADDING))

            for i, folder in enumerate(bigfile.folder_list):
                offset = (i * FOLDER_ENTRY_SIZE) + BIGFILE_HEADER_SIZE
                write_folder(folder, offset, buffer)

            for i, unmapped in enumerate(bigfile.unmapped_data):
                write_unmapped_data(unmapped, buffer)


def from_unpacked(path: str, config: BigFileConfig) -> BigFile:
    """Create a `BigFile` instance from an unpacked DAT.

    Args:
        path (str): Path to the unpacked DAT.
        config (BigFileConfig): The BIGFILE config


    Returns:
        BigFile: The parsed BIGFILE.

    Raises:
        Exception: If the source directory cannot be found.
        Exception: If the source exists but is not a directory.
        Exception: If the config does not contain the `structure` component.
        Exception: If one of the unpacked files cannot be found.

    """
    if not os.path.exists(path):
        raise Exception(f"Input directory {path} does not exist!")

    if not os.path.isdir(path):
        raise Exception(f"Input {path} is a file!")

    if not os.path.exists(config.structure_path):
        raise Exception(f"BIGFILE structure '{config.structure_path}' does not exist!")

    bigfile: BigFile = BigFile.from_yaml(config.structure_path)

    already_read_files: dict[str, int] = {}

    for folder in bigfile.folder_list:
        for file in folder.file_list:
            file_name = config.file_map.get(file.hash, f"{file.hash}.bin")

            if already_read_files.get(file_name) is None:
                already_read_files[file_name] = 0
            else:
                already_read_files[file_name] += 1
                name, ext = file_name.rsplit(".", 1)
                file_name = f"{name}_duplicate{already_read_files[file_name]}.{ext}"

            full_file_path = os.path.join(path, file_name)

            if "\\" in file_name:
                *subfolders, file_name = file_name.split("\\")
                subpath = os.path.join(path, *subfolders)

                full_file_path = os.path.join(subpath, file_name)

            if not os.path.exists(full_file_path):
                raise Exception(f"File {full_file_path} cannot be found!")

            with open(full_file_path, "rb") as f:
                file.contents = f.read(file.size)

    for unmapped in bigfile.unmapped_data:
        filename = f"unmapped_{unmapped.offset}.bin"
        segment_path = os.path.join(path, "unmapped_data", filename)

        with open(segment_path, "rb") as f:
            unmapped.contents = f.read(unmapped.size)

    return bigfile


def from_path(path: str, config: BigFileConfig) -> BigFile:
    """Create a `BigFile` from either a packed or unpacked state.

    Args:
        path (str): Path to the BIGFILE.
        config (BigFileConfig): The BIGFILE config.

    Raises:
        Exception: If path does not exist.

    """
    if not os.path.exists(path):
        raise Exception(f"'{path}' does not exist!")

    if os.path.isfile(path):
        return from_dat(path, config)
    else:
        return from_unpacked(path, config)


def compare_unmapped_data(
    a: UnmappedEntry, b: UnmappedEntry, segment_idx: int
) -> list[str]:
    """Compare two unmapped data segments.

    Args:
        a (UnmappedEntry): The first segment in the comparison.
        b (UnmappedEntry): The second segment in the comparison.
        segment_idx (int): Index of the unmapped segment.

    Returns:
        list[str]: List of all mismatches between the two segments.

    """
    mismatches = []

    if a.size != b.size:
        mismatches.append(
            f"Size mismatch for unmapped data segment {segment_idx}! a: {a.size} bytes, b: {b.size} bytes"
        )

    if a.offset != b.offset:
        mismatches.append(
            f"Offset mismatch for unmapped data segment {segment_idx}! a: {a.offset}, b: {b.offset}"
        )

    if a.contents != b.contents:
        mismatches.append(f"Content mismatch for unmapped data segment {segment_idx}!")

    return mismatches


def compare_file(
    a: FileEntry, b: FileEntry, folder_idx: int, file_idx: int
) -> list[str]:
    """Compare two `FileEntry` instances.

    Args:
        a (FileEntry): The first file entry in the comparison.
        b (FileEntry): The second file entry in the comparison.
        folder_idx (int): Index of the folder containing the file.
        file_idx (int): Index of the file within its folder.

    Returns:
        list[str]: List of all mismatches between the two entries.

    """
    mismatches = []

    if a.size != b.size:
        mismatches.append(
            f"Mismatch between file sizes at folder {folder_idx} - file {file_idx}! a: {a.size} bytes, b: {b.size} bytes"
        )

    if a.offset != b.offset:
        mismatches.append(
            f"Mismatch between file offsets at folder {folder_idx} - file {file_idx}! a: {a.offset}, b: {b.offset}"
        )

    if a.hash != b.hash:
        mismatches.append(
            f"Mismatch between file hashes at folder {folder_idx} - file {file_idx}! a: {a.hash}, b: {b.hash}"
        )

    if a.checksum != b.checksum:
        mismatches.append(
            f"Mismatch between file checksums at folder {folder_idx} - file {file_idx}! a: {a.checksum}, b: {b.checksum}"
        )

    if a.contents != b.contents:
        mismatches.append(
            f"Mismatch between file contents at folder {folder_idx} - file {file_idx}!"
        )

    return mismatches


def compare_folder(a: FolderEntry, b: FolderEntry, folder_idx: int) -> list[str]:
    """Compare two `FolderEntry` instances.

    Args:
        a (FolderEntry): The first folder entry in the comparison.
        b (FolderEntry): The second folder entry in the comparison.
        folder_idx (int): Index of the folder.

    Returns:
        list[str]: List of all mismatches between the two folders.

    """
    mismatches = []

    if len(a.file_list) != len(b.file_list):
        mismatches.append(
            f"Mismatch between number of files at folder {folder_idx}! a: {len(a.file_list)}, b: {len(b.file_list)}"
        )

    if a.offset != b.offset:
        mismatches.append(
            f"Mismatch between offsets at folder {folder_idx}! a: {a.offset}, b: {b.offset}"
        )

    if a.magic != b.magic:
        mismatches.append(
            f"Mismatch between magic bytes folder {folder_idx}! a: {a.magic}, b: {b.magic}"
        )

    if a.encryption != b.encryption:
        mismatches.append(
            f"Mismatch between encryption key at folder {folder_idx}! a: {a.encryption}, b: {b.encryption}"
        )

    for i, (file_a, file_b) in enumerate(zip(a.file_list, b.file_list)):
        mismatches.extend(compare_file(file_a, file_b, folder_idx, i))

    return mismatches


def compare(a: BigFile, b: BigFile) -> list[str]:
    """Compare two `BigFile` instances.

    Args:
        a (BigFile): The first `BigFile` in the comparison.
        b (BigFile): The second `BigFile` in the comparison.

    Returns:
        list[str]: List of all mismatches between the two folders.

    """
    mismatches = []

    if len(a.folder_list) != len(b.folder_list):
        mismatches.append(
            f"Mismatch between number of folders! a: {len(a.folder_list)}, b: {len(b.folder_list)}"
        )

    if len(a.unmapped_data) != len(b.unmapped_data):
        mismatches.append(
            f"Mismatch between number of unmapped sections! a: {len(a.unmapped_data)}, b: {len(b.unmapped_data)}"
        )

    if a.size != b.size:
        mismatches.append(
            f"Mismatch between file sizes! a: {a.size} bytes, b: {b.size} bytes"
        )

    for i, (unmapped_a, unmapped_b) in enumerate(zip(a.unmapped_data, b.unmapped_data)):
        mismatches.extend(compare_unmapped_data(unmapped_a, unmapped_b, i))

    for i, (folder_a, folder_b) in enumerate(zip(a.folder_list, b.folder_list)):
        mismatches.extend(compare_folder(folder_a, folder_b, i))

    return mismatches
