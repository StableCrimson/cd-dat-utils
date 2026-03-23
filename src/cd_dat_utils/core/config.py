import os
from typing import Optional

import pylibyaml  # Needed - Patches several `yaml` methods for huge performance improvements
import yaml
from pydantic import BaseModel, Field


class BigFileConfig(BaseModel):
    """Configuration for BIGFILE operations."""

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

    # TODO: Allow optional flag to process all configured overlays during unpacking

    # TODO: Allow optional flag to preserve files with identical hashes


class OverlayConfig(BaseModel):
    """Configuration for a single overlay."""

    name: str
    """Name of the overlay"""

    src_path: str
    """Path to the source overlay binary"""

    out_path: str
    """Path to the un-relocated ovelay"""

    relocs_path: str
    """Path to the yaml containing relocation data for the overlay"""

    # TODO: Allow optional flag to create splat config


class Config(BaseModel):
    """Configuration for the DAT utils."""

    bigfile: Optional[BigFileConfig] = Field(default=None)
    """Configuration for BIGFILE"""

    overlays: Optional[list[OverlayConfig]] = Field(default=None)
    """List of overlay configurations"""

    @classmethod
    def from_yaml(cls, path: str):
        """Create a `Config` instance from YAML.

        Args:
            path (str): Path to the YAML file.

        Returns:
            Config: The validated configuration.

        Raises:
            ValidationError: If the YAML data does not abide by the `Config` spec.
            Exception: If `file_map_path` is defined but does not exist.

        """
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

    def write_yaml(self, path: str):
        """Write the configuration as a YAML file.

        Args:
            path (str): Path of the YAML file to be written to.

        """
        with open(path, "w") as f:
            f.write(yaml.safe_dump(self.model_dump(), sort_keys=False, indent=2))
