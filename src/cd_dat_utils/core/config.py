import os
from typing import Optional, Self

import pylibyaml  # Needed - Patches several `yaml` methods for huge performance improvements
import yaml
from pydantic import BaseModel, Field, model_validator


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

    @model_validator(mode="after")
    def _post_process(self) -> Self:
        # If no dedicated output path for packed file, repack as the source file
        if self.packed_path is None:
            self.packed_path = self.src_path

        # If a file list is defined, load the symbol map
        if self.file_map_path is not None:
            if not os.path.exists(self.file_map_path):
                raise Exception(
                    f"File list YAML '{self.file_map_path}' does not exist!"
                )

            with open(self.file_map_path) as f:
                self.file_map = yaml.safe_load(f.read()) or {}

        return self


class Config(BaseModel):
    """Configuration for the DAT utils."""

    bigfile: Optional[BigFileConfig] = Field(default=None)
    """Configuration for BIGFILE"""

    @classmethod
    def from_yaml(cls, path: str):
        """Create a `Config` instance from YAML.

        Args:
            path (str): Path to the YAML file.

        Returns:
            Config: The validated configuration.

        Raises:
            ValidationError: If the YAML data does not abide by the `Config` spec.

        """
        with open(path) as f:
            return cls.model_validate(yaml.safe_load(f.read()) or {})

    def write_yaml(self, path: str):
        """Write the configuration as a YAML file.

        Args:
            path (str): Path of the YAML file to be written to.

        """
        with open(path, "w") as f:
            f.write(yaml.safe_dump(self.model_dump(), sort_keys=False, indent=2))
