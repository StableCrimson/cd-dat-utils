# cd-dat-utils

Utility for working with BIGFILEs in Crystal Dynamics games

Only works for Legact of Kain: Soul Reaver. But would like to add support for other
Crystal Dynamics titles.

Currently no support for encrypted or compressed files at this time.

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

By default, the JSON config path will just be `config.json`, though a different path can be provided using `-c` or `--config`.

## Config

The JSON config is a required file. The first time you unpack the BIGFILE, it's structure will be serialized and written to the config file, this is used to repackage the file later.

The structure of the config file is as follows:

```json
{
  "file_names": {
    "file_hash": "file_name",
    ...
  },
  "unmapped_data": {
    "size": 123456,
    "offset": 7890
  },
  "structure": { ... }
}
```

- `file_names` - A map of file hashes to their respective names. Used for naming files during unpacking, and reading files during repacking.

- `unmapped_data` - Stores the byte offset and size of any non-padding data that is not considered a file. Required for a perfect match.

- `structure` - The serialized structure of the file. This is automatically written when the file is unpacked.
