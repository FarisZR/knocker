"""Project metadata shared by the application and packaging tools."""

from pathlib import Path
import tomllib


_PROJECT_FILE = Path(__file__).resolve().parents[1] / "pyproject.toml"
with _PROJECT_FILE.open("rb") as _handle:
    __version__ = str(tomllib.load(_handle)["project"]["version"])
