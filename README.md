# cd-dat-utils

Utility for working with BIGFILEs in Crystal Dynamics games.

> [!NOTE]
> cd-dat-utils is still an experimental tool under development. Usage and configuration is subject to change. As of now, it is developed for use with the Legacy of Kain: Soul Reaver project. Compatibility for other CD titles _at this time_ is not guaranteed.

## Context

PSX games published by Crystal Dynamics often contain a file on the disc called `BIGFILE.DAT`, which is a giant blob of files such as fonts, sounds, images, code, etc. This utility was made as a tool to assist with decompiling games that use BIGFILEs, since the overlays for these games are contained within them.

Since the PSX only had 2MB of RAM, it was inefficient (or even impossible) to load all of the game's code into memory at once. Some pieces of code aren't always needed, and so they would be wasting space if they were loaded in memory the entire time. The solution to this problem is overlays. Overlays are small pieces of executable code that can be loaded and unloaded at runtime, very similar to DLLs. This allows situational code (such as enemy AI), to only be loaded when it's needed, and can be removed from memory when the game no longer needs it.

## Installation

To install locally:

```bash
pip install .
```

To install in another project you can install via CLI:

```bash
pip install git+https://github.com/StableCrimson/cd-dat-utils
```

or add to your requirements file:

```bash
git+https://github.com/StableCrimson/cd-dat-utils
```

## Usage

To unpack a BIGFILE:

```bash
cd-dat-utils unpack <src_file> <dest_dir> <config_path>
```

To pack a folder into a BIGFILE:

```bash
cd-dat-utils pack <src_dir> <dest_file> <config_path>
```

To compare 2 BIGFILEs (packed or unpacked):

```bash
cd-dat-utils compare <path_a> <path_b> <config_path>
```

## Config

The JSON config is a required file. The structure of a BIGFILE will be written to this the first time it's unpacked. This structure is used later when repackaging the file.

The structure of the config file is as follows:

```json
{
  "structure": {
    "size": 123456,
    "folder_list": [
      {
        "offset": 1234,
        "magic": 5678,
        "encryption": 0,
        "file_list": [
          {
            "size": 1234,
            "offset": 5678,
            "hash": 1234,
            "checksum": 5678
          },
          ...
        ]
      },
      ...
    ]
  },
  "file_names": {
    "file_hash": "file_name",
    ...
  },
  "unmapped_data": [
    {
      "size": 123456,
      "offset": 7890
    },
    ...
  ]
}
```

- `structure` - The serialized structure of the file. Required for packing. This will be automatically written to the config file when unpacking for the first time.

- `file_names` - Optional. A map of file hashes to their respective names. Used for naming files during unpacking, and reading files during repacking. Files without name mappings will be named `<file_hash>.bin`.

- `unmapped_data` - Optional. Stores the byte offsets and sizes of any non-padding data that is not considered a file. Not needed to package the file but may be required for a perfect match. When unpacking, these segments will be written to `<output_dir>/unmapped_data/unmapped_<offset>.bin` in the output directory.

---

BIGFILE spec from [PlayStation Specification psx-spx](https://psx-spx.consoledev.net/cdromfileformats/#legacy-of-kain-soul-reaver-bigfiledat)

## Planned Features

- [ ] Encryption support
- [ ] Compression + decompression
- [ ] Overlay utils (undo and redo mem relocation)
- [ ] Config as YAML file
