"""Physical storage for encrypted vault files."""

from __future__ import annotations

import re
from pathlib import Path

STORAGE_NAME_PATTERN = re.compile(r"^[a-z0-9]{1,64}$")
FILE_SUFFIX = ".enc"


class FileStorage:
    """Stores encrypted blobs on disk, one directory per vault."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def create_vault_dir(self, vault_id: int) -> Path:
        """Create and return the directory that holds one vault's files."""
        path = self._root / f"vault_{self._check_vault_id(vault_id)}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save(self, vault_id: int, storage_name: str, data: bytes) -> Path:
        """Write encrypted bytes without overwriting an existing file."""
        if not isinstance(data, bytes):
            raise ValueError("data must be bytes")
        path = self._path(vault_id, storage_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(data)
        return path

    def read(self, vault_id: int, storage_name: str) -> bytes:
        """Return the encrypted bytes stored under this name."""
        return self._path(vault_id, storage_name).read_bytes()

    def delete(self, vault_id: int, storage_name: str) -> None:
        """Remove the encrypted file from disk."""
        self._path(vault_id, storage_name).unlink()

    def exists(self, vault_id: int, storage_name: str) -> bool:
        """Return True when the encrypted file is on disk."""
        return self._path(vault_id, storage_name).is_file()

    def contains(self, path: Path) -> bool:
        """Return True when a path is inside the storage root."""
        try:
            Path(path).resolve().relative_to(self._root.resolve())
        except ValueError:
            return False
        return True

    def _path(self, vault_id: int, storage_name: str) -> Path:
        self._check_vault_id(vault_id)
        if not isinstance(storage_name, str) or not STORAGE_NAME_PATTERN.match(
            storage_name
        ):
            raise ValueError("storage_name must be 1-64 lowercase letters or digits")
        return self._root / f"vault_{vault_id}" / f"{storage_name}{FILE_SUFFIX}"

    @staticmethod
    def _check_vault_id(vault_id: int) -> int:
        if not isinstance(vault_id, int) or vault_id < 1:
            raise ValueError("vault_id must be a positive integer")
        return vault_id
