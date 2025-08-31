# cd-dat-utils

Utility for working with BIGFILEs in Crystal Dynamics games.

Only works for Legact of Kain: Soul Reaver. But would like to add support for other
Crystal Dynamics titles.

No support for encrypted or compressed files at this time.

## Context

PSX games published by Crystal Dynamics often contain a file on the disc called `BIGFILE.DAT`, which is a giant blob of files such as fonts, sounds, images, code, etc. This utility was made as a tool to assist with decompiling games that use BIGFILEs, since the overlays for these games are contained within them.

Since the PSX only had 2MB of RAM, it was inefficient to load all of the game's code into memory at once. Some pieces of code aren't always needed, and so they would be wasting space if they were loaded in memory the entire time. The solution to this problem is overlays. Overlays are small pieces of executable code that can be loaded and unloaded at runtime, very similar to DLLs. This allows situational code (such as enemy AI), to only be loaded when it's needed, and can be removed from memory when the game no longer needs it.

## Usage

First, make sure to install the requirements via:

```bash
pip install -r requirements.txt
```

To unpack a BIGFILE:

```bash
python dat_utils.py unpack <src_file> <dest_dir>
```

To pack a folder into a BIGFILE:

```bash
python dat_utils.py pack <src_dir> <dest_file>
```

The config path defaults to `config.json`, though a different path can be provided using `-c` or `--config`.

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
  "unmapped_data": {
    "size": 123456,
    "offset": 7890
  }
}
```

- `structure` - Required. The serialized structure of the file. This is automatically written when the file is unpacked.

- `file_names` - Optional. A map of file hashes to their respective names. Used for naming files during unpacking, and reading files during repacking. Files without name mappings will be named `<file_hash>.bin`.

- `unmapped_data` - Optional. Stores the byte offset and size of any non-padding data that is not considered a file. Required for a perfect match. Will be written to `UNMAPPED_DATA.bin` in the output directory.

---

BIGFILE spec from [PlayStation Specification psx-spx](https://psx-spx.consoledev.net/cdromfileformats/#legacy-of-kain-soul-reaver-bigfiledat)
