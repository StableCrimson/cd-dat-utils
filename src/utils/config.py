import os
from typing import Optional

import pylibyaml  # Needed - Patches several `yaml` methods for huge performance improvements
import yaml
from pydantic import BaseModel, Field


class BigFileConfig(BaseModel):
    src_path: str
    """Path to the source BIGFILE"""

    unpacked_path: str
    """Directory where the unpacked BIGFILE contents will be written"""

    packed_path: Optional[str] = Field(default=None)
    """Directory where the repacked BIGFILE contents will be written"""

    structure_path: str
    """Path to yaml file containing BIGFILE structure"""

    file_map_path: Optional[str] = Field(default=None)
    """Path to yaml file containing a map of hashes to their respective names"""

    file_map: dict[int, str] = Field(default={}, exclude=True)
    """Map of file hashes to their respective names"""


class Config(BaseModel):
    bigfile: Optional[BigFileConfig] = Field(default=None)
    """Configuration for BIGFILE"""

    @classmethod
    def from_yaml(cls, path: str):
        with open(path) as f:
            config = cls.model_validate(yaml.safe_load(f.read()) or {})

        if config.bigfile is not None:
            # If no dedicated output path for packed file, repack as the source file
            if config.bigfile.packed_path is None:
                config.bigfile.packed_path = config.bigfile.src_path

            # If a file list is defined, load the symbol map
            if config.bigfile.file_map_path is not None:
                if not os.path.exists(config.bigfile.file_map_path):
                    raise Exception(
                        f"File list YAML '{config.bigfile.file_map_path}' does not exist!"
                    )

                with open(config.bigfile.file_map_path) as f:
                    config.bigfile.file_map = yaml.safe_load(f.read()) or {}

        return config

    def write(self, path: str):
        with open(path, "w") as f:
            f.write(yaml.safe_dump(self.model_dump(), sort_keys=False, indent=2))
