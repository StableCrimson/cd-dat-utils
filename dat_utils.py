from dataclasses import dataclass
from io import BufferedReader, BufferedWriter
import os
import json
import shutil
import argparse

# BIGFILE spec from https://psx-spx.consoledev.net/cdromfileformats/#legacy-of-kain-soul-reaver-bigfiledat
# Cross referenced with Soul Spiral and decompiled code from the soul-re project
# None of the files in Soul Reaver appear to be compressed or encrypted

@dataclass
class FileEntry:
  size: int
  offset: int
  hash: int
  checksum: int
  contents: bytes

@dataclass
class FolderEntry:
  num_files: int
  offset: int
  magic: int
  file_list: list[FileEntry]

@dataclass
class BigFile:
  num_folders: int
  folder_list: list[FolderEntry]  
  unmapped_data: FileEntry | None = None

CONFIG = {}

def hash_from_file_path(file_path: str) -> int:

  HASH_EXTENSIONS = [ "drm", "crm", "tim", "smp", "snd", "smf", "snf" ]

  sum = 0
  xor = 0
  length = 0
  ext_index = 0

  components = file_path.rsplit('.', 1)
  name = file_path

  if len(components) > 1:
    name_no_ext, ext = components

    if ext in HASH_EXTENSIONS:
      ext_index = HASH_EXTENSIONS.index(ext)
      name = name_no_ext

  for c in name[::-1]:
    if c == '\\':
      continue

    c = c.upper()
    c = chr(ord(c) - 0x1A)
    sum += ord(c)
    xor ^= ord(c) * length
    length += 1

  return (length << 27) | (sum << 15) | (xor << 3) | ext_index
  
def read_file(file: BufferedReader, offset: int) -> FileEntry:
  file.seek(offset)
  hash        = int.from_bytes(file.read(4), 'little')
  size        = int.from_bytes(file.read(4), 'little')
  file_offset = int.from_bytes(file.read(4), 'little')
  checksum    = int.from_bytes(file.read(4), 'little')

  file.seek(file_offset)
  return FileEntry(size, file_offset, hash, checksum, file.read(size))

def read_folder(file: BufferedReader, offset: int) -> FolderEntry:
  file.seek(offset)
  magic         = int.from_bytes(file.read(2), 'little')
  num_files     = int.from_bytes(file.read(2), 'little')
  folder_offset = int.from_bytes(file.read(4), 'little')
  folder = FolderEntry(num_files, folder_offset, magic, [])

  file.seek(folder_offset)
  assert(int.from_bytes(file.read(2), 'little') == num_files)
  assert(file.read(2) == b'\x00\x00')

  for i in range(num_files):
    entry_offset = (i * 0x10) + folder_offset + 4
    folder.file_list.append(read_file(file, entry_offset))

  return folder

def from_dat(path: str, config_path: str) -> BigFile:
  with open(path, 'rb') as file:

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    CONFIG['dat_size_bytes'] = size

    with open(config_path, 'w') as f:
      json.dump(CONFIG, f, indent=2)

    bigfile = BigFile(int.from_bytes(file.read(2), 'little'), [])
    assert(file.read(2) == b'\x00\x00')
    
    for i in range(bigfile.num_folders):
      offset = (i * 8) + 4
      bigfile.folder_list.append(read_folder(file, offset))

    if CONFIG.get('unmapped_data') is not None:
      unmapped_data = CONFIG['unmapped_data']
      file.seek(unmapped_data['offset'])

      bigfile.unmapped_data = FileEntry(unmapped_data['size'], unmapped_data['offset'], 0, 0, file.read(unmapped_data['size']))

    return bigfile
  
def unpack_bigfile(bigfile: BigFile, output_dir: str) -> None:

  if os.path.exists(output_dir):
    shutil.rmtree(output_dir)

  os.makedirs(output_dir)

  if CONFIG.get('unmapped_data') and bigfile.unmapped_data:
    unmapped_data = CONFIG['unmapped_data']
    with open(os.path.join(output_dir, unmapped_data['name']), 'wb') as f:
      f.write(bigfile.unmapped_data.contents)

  duplicates = {}
  folder_magic = {}

  for folder_idx, folder in enumerate(bigfile.folder_list):

    folder_magic[folder_idx] = folder.magic

    for file in folder.file_list:

      file_data = CONFIG.get(str(file.hash), {})
      file_name = file_data['name']

      if file_name not in duplicates.keys():
        duplicates[file_name] = 0
      else:
        duplicates[file_name] += 1
        base, ext = os.path.splitext(file_name)
        file_name = f'{base}_duplicate{duplicates[file_name]}{ext}'

      with open(os.path.join(output_dir, file_name), 'wb') as outfile:
        outfile.write(file.contents)

  with open('folder_magic_data.json', 'w') as f:
    json.dump(folder_magic, f, indent=2)

def write_file(file: FileEntry, header_offset: int, writer: BufferedWriter):
 
  writer.seek(header_offset)
  writer.write(file.hash.to_bytes(4, 'little'))
  writer.write(file.size.to_bytes(4, 'little'))
  writer.write(file.offset.to_bytes(4, 'little'))
  writer.write(file.checksum.to_bytes(4, 'little'))

  writer.seek(file.offset)
  writer.write(file.contents)

def write_folder(folder: FolderEntry, header_offset: int, writer: BufferedWriter):

  writer.seek(header_offset)

  # Folder header
  HALFWORD_PADDING = b'\x00\x00'  
  writer.write(folder.magic.to_bytes(2, 'little'))
  writer.write(folder.num_files.to_bytes(2, 'little'))
  writer.write(folder.offset.to_bytes(4, 'little'))

  writer.seek(folder.offset)
  writer.write(folder.num_files.to_bytes(2, 'little'))
  writer.write(HALFWORD_PADDING)

  for i, file in enumerate(folder.file_list):
    offset = (i * 16) + folder.offset + 4
    write_file(file, offset, writer)

def pack_bigfile(bigfile: BigFile, output_path: str) -> None:
  
  if CONFIG.get('dat_size_bytes') is None:
    raise Exception('Field \'dat_size_bytes\' not found in config')

  with open(output_path, 'wb', 0) as f:
    with BufferedWriter(f, CONFIG['dat_size_bytes']) as file_data:

      HALFWORD_PADDING = b'\x00\x00'

      file_data.write(bigfile.num_folders.to_bytes(2, 'little'))
      file_data.write(HALFWORD_PADDING)

      for i, folder in enumerate(bigfile.folder_list):
        offset = (i * 8) + 4
        write_folder(folder, offset, file_data)

      if bigfile.unmapped_data:
        file_data.seek(bigfile.unmapped_data.offset)
        file_data.write(bigfile.unmapped_data.contents)

def from_unpacked(input_dir: str, json_config: str) -> BigFile:
  
  if not os.path.exists(input_dir):
    raise Exception(f'Input directory {input_dir} does not exist')
  
  if not os.path.exists(json_config):
    raise Exception(f'JSON config file {json_config} does not exist')
  
  if not os.path.exists('folder_magic_data.json'):
    print('Warning, no magic data found for DAT file. Writing null bytes to magic data segments')
    folder_magic = {}
  else:
    with open('folder_magic_data.json', 'r') as f:
      folder_magic = json.load(f)

  unmapped_data = CONFIG.get('unmapped_data', {})

  bigfile = BigFile(0, [])

  file_structure = {}

  for file in os.listdir(input_dir):

    if file == unmapped_data.get('name'):
      with open(os.path.join(input_dir, file), 'rb') as f:
        contents = f.read()
      bigfile.unmapped_data = FileEntry(unmapped_data.get('size'), unmapped_data.get('offset'), 0, 0, contents)
      continue

    file_name, ext = file.split('.')
    file_duplicate_index = 0

    components = file_name.split('_')
    if len(components) > 1 and components[-1].startswith('duplicate'):
      file_name = '_'.join(components[:-1])
      file_duplicate_index = int(components[-1].strip('duplicate'))

    if components[0] != 'UNKNOWN':
      file_hash = hash_from_file_path(f'{file_name}.{ext}')
    else:
      file_hash = int(components[1], 16)

    file_record = CONFIG[str(file_hash)]
    file_data_for_folder = file_record['folders'][file_duplicate_index]

    with open(os.path.join(input_dir, file), 'rb') as f:
      contents = f.read()

    file_entry = FileEntry(
      file_data_for_folder['size'],
      file_data_for_folder['offset'],
      file_hash,
      file_data_for_folder['checksum'],
      contents
    )

    if file_structure.get(file_data_for_folder['folder']) is None:
      file_structure[file_data_for_folder['folder']] = { 'files': {} }

    file_structure[file_data_for_folder['folder']]['offset'] = file_data_for_folder['folder_offset']
    file_structure[file_data_for_folder['folder']]['files'][file_data_for_folder['file']] = file_entry

  for i in range(len(file_structure)):
    
    folder_structure = file_structure[i]
    folder_entry = FolderEntry(0, 0, 0, [])
    folder_entry.offset = folder_structure['offset']
    folder_entry.magic = folder_magic.get(str(i), 0)

    for j in range(len(folder_structure['files'])):
      folder_entry.file_list.append(folder_structure['files'][j])

    folder_entry.num_files = len(folder_entry.file_list)
    bigfile.folder_list.append(folder_entry)

  bigfile.num_folders = len(bigfile.folder_list)
  return bigfile

if __name__ == "__main__":

  parser = argparse.ArgumentParser()
  parser.add_argument('operation', choices={'unpack', 'pack'})
  parser.add_argument('input', help='Path to source')
  parser.add_argument('output', help='Path to target')
  parser.add_argument('--config', default='config.json', help='Path to JSON config. Defaults to \'config.json\'')
  args = parser.parse_args()

  if not os.path.exists(args.config):
    raise Exception(f'Config file {args.config} could not be found')

  with open(args.config) as f:
    CONFIG = json.load(f)

  if not os.path.exists(args.input):
    raise Exception(f'Input {args.input} could not be found')

  if args.operation == 'pack':
    bigfile = from_unpacked(args.input, args.config)
    pack_bigfile(bigfile, args.output)
  else:
    bigfile = from_dat(args.input, args.config)
    unpack_bigfile(bigfile, args.output)