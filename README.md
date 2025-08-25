# cd-dat-utils

Utility for working with BIGFILEs in Crystal Dynamics games

Only works for Legact of Kain: Soul Reaver. But would like to add support for other
Crystal Dynamics titles.

Currently no support for encrypted or compressed files at this time.

## Usage

To unpack a BIGFILE:

```bash
python dat_utils.py unpack <src_file> <dest_dir>
```

To pack a folder into a BIFILE:

```bash
python dat_utils.py pack <src_dir> <dest_file>
```

By default, the JSON config path will just be `config.json`, though a different path can be provided using `-c` or `--config`.

## Config

The JSON config is a required file. I plan to allow it to be generated if it doesn't exist, but support is not added yet.

The config is mainly used to map file hashes to a file name.

The structure of this file is a WIP and subject to change.

### Fields

- `dat_size_bytes` - Size of the source DAT in bytes. Required for repacking. This will automatically populate in the config during the DAT file unpacking.
- `unmapped_data` - Optional. Any non-padding data that is not recognized as a file. Usually needed for a perfect match.

## Magic Data

Folder entries have a few bytes that right now serve no known purpose, but must be preserved if we want the repacked file to perfectly match the original. These are stored in `folder_magic_data.json` which gets generated automatically when a DAT is first unpacked. If this file doesn't exist or there is a missing entry, the magic bytes will default to zeroes.
