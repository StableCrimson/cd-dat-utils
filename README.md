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

## Configuration

The YAML config is a required file. The tools uses several different files for configuration, but many of them are auto-generated during use. The only file required to be manually written is the main config file, which is outlined below.

The structure of the config file is as follows:

```yaml
bigfile:
  src_path: BIGFILE.DAT
  packed_path: packed.DAT
  unpacked_path: output
  structure_path: bigfile.yaml
  file_map_path: symbols.yaml
```

### `bigfile`

This optional section contains the BIGFILE configuration. Required for BIGFILE operations.

| Field            | Type  | Required | Description                                                                                       |
| ---------------- | ----- | -------- | ------------------------------------------------------------------------------------------------- |
| `src_path`       | `str` | Yes      | Path to the original DAT file                                                                     |
| `unpacked_path`  | `str` | Yes      | Directory where the unpacked contents will be placed                                              |
| `packed_path`    | `str` | No       | Path of the newly repacked BIGFILE. If not specified, will default to `src_path`                  |
| `structure_path` | `str` | Yes      | Where the serialized structure will be written to. Will be auto-generated, does not need to exist |
| `file_map_path`  | `str` | No       | Path to the YAML file mapping file hashes to their names                                          |

### The File Map

The file map (whose path is recorded in `file_map_path` in the config) is an optional file, but immensely helpful when working with unpacked files. It is just a YAML file mapping file hashes to their output paths. Ex:

```yaml
2576260384: "game\\object\\ov1.drm"
2576293153: "game\\object\\ov1.crm"
2576293152: "game\\maps\\areaIntro.drm"
2576293157: "game\\object\\enemy.smf"
2576293158: "game\\object\\enemy.snf"
```

---

BIGFILE spec from [PlayStation Specification psx-spx](https://psx-spx.consoledev.net/cdromfileformats/#legacy-of-kain-soul-reaver-bigfiledat)

## Planned Features

- [ ] Encryption support
- [ ] Compression + decompression
- [ ] Overlay utils (undo and redo mem relocation)
