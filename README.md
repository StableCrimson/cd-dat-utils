# cd-dat-utils

Utility for working with BIGFILEs in Crystal Dynamics games.

> [!NOTE]
> cd-dat-utils is developed for use with the Legacy of Kain: Soul Reaver project. Compatibility with other Crystal Dynamics titles is not guaranteed.

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
cd-dat-utils unpack <config_path> [-i <src>] [-o <dest>]
```

If `-i` is not specified, it will use `src_path` from the config.

If `-o` is not specified, it will use `unpacked_path` from the config.

To pack a folder into a BIGFILE:

```bash
cd-dat-utils pack <src_dir> [-i <src>] [-o <dest>]
```

If `-i` is not specified, it will use `unpacked_path` from the config.

If `-o` is not specified, it will use `packed_path` from the config.

To compare 2 BIGFILEs (packed or unpacked):

```bash
cd-dat-utils compare <config_path> [-a <a>] [-b <b>]
```

If `-a` is not specified, it will use `packed_path` from the config.

If `-b` is not specified, it will use `unpacked_path` from the config.

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
overlays:
  - name: MyOverlay
    src_path: ov1.drm
    out_path: ov1.bin
    relocs_path: ov1_relocs.yaml
  - name: MyOtherOverlay
    src_path: ov2.drm
    out_path: ov2.bin
```

### `bigfile`

This optional section contains the BIGFILE configuration. Required for BIGFILE operations.

| Field            | Type  | Required | Description                                                                                                                            |
| ---------------- | ----- | -------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `src_path`       | `str` | Yes      | Path to the original DAT file                                                                                                          |
| `unpacked_path`  | `str` | Yes      | Directory where the unpacked contents will be placed                                                                                   |
| `packed_path`    | `str` | No       | Path of the newly repacked BIGFILE. If not specified, will default to `src_path`                                                       |
| `structure_path` | `str` | Yes      | Where the serialized structure will be written to. Will be auto-generated. Will need to be updated if any unmapped data segments exist |
| `file_map_path`  | `str` | No       | Path to the YAML file mapping file hashes to their names                                                                               |

### `overlays`

This optional section contains a list of configurations for all overlays. Required for overlay operations.

| Field      | Type  | Required | Description                                                                    |
| ---------- | ----- | -------- | ------------------------------------------------------------------------------ |
| `name`     | `str` | Yes      | Overlay name                                                                   |
| `src_path` | `str` | Yes      | Path to the binary containing the overlay. Often ends with `.drm`              |
| `out_path` | `str` | Yes      | Path to where the extracted and memory patched overlay module will be written. |

### The File Map

The file map (whose path is recorded in `file_map_path` in the config) is an optional file, but immensely helpful when working with unpacked files. It is just a YAML file mapping file hashes to their output paths. Ex:

```yaml
2576260384: game\object\ov1.drm
2576293153: game\object\ov1.crm
2576293152: game\maps\areaIntro.drm
2576293157: game\object\enemy.smf
2576293158: game\object\enemy.snf
```

### The BIGFILE Structure

The BIGFILE structure is something that is automatically generated. The only thing that you may need to is populate the `unmapped_data` segment. This is an optional field that contains the sizes and offsets for any non-padding data that is not considered a file. While optional, it in some instances may be required for a full match.

The config is written as follows:

```yaml
unmapped_data:
  - offset: 12288
    size: 100
  - offset: 12388
    size: 100
```

---

BIGFILE spec from [PlayStation Specification psx-spx](https://psx-spx.consoledev.net/cdromfileformats/#legacy-of-kain-soul-reaver-bigfiledat)
