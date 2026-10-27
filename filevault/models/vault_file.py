"""VaultFile domain model."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime

FILENAME_MAX_LENGTH = 255
STORAGE_NAME_BYTES = 16
STORAGE_NAME_MAX_LENGTH = 64


def generate_storage_name() -> str:
    """Return a random name for the encrypted file on disk."""
    return secrets.token_hex(STORAGE_NAME_BYTES)


@dataclass(frozen=True, slots=True)
class VaultFile:
    """Metadata of one encrypted file stored inside a vault."""

    vault_id: int
    filename: str
    size: int
    storage_name: str = field(default_factory=generate_storage_name)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    id: int | None = None

    @classmethod
    def create(cls, vault_id: int, filename: str, size: int) -> VaultFile:
        """Build a file entry from raw input, normalizing the filename first."""
        return cls(
            vault_id=vault_id,
            filename=filename.strip(),
            size=size,
        )

    def __post_init__(self) -> None:
        if self.vault_id < 1:
            raise ValueError("vault_id must be a positive integer")
        if not self.filename:
            raise ValueError("filename must not be empty")
        if len(self.filename) > FILENAME_MAX_LENGTH:
            raise ValueError(
                f"filename must be at most {FILENAME_MAX_LENGTH} characters"
            )
        if "/" in self.filename or "\\" in self.filename:
            raise ValueError("filename must not contain path separators")
        if self.filename in (".", ".."):
            raise ValueError("filename must not be '.' or '..'")
        if self.size < 0:
            raise ValueError("size must be zero or positive")
        if not self.storage_name:
            raise ValueError("storage_name must not be empty")
        if len(self.storage_name) > STORAGE_NAME_MAX_LENGTH:
            raise ValueError(
                f"storage_name must be at most {STORAGE_NAME_MAX_LENGTH} characters"
            )
        if "/" in self.storage_name or "\\" in self.storage_name:
            raise ValueError("storage_name must not contain path separators")
        if self.storage_name in (".", ".."):
            raise ValueError("storage_name must not be '.' or '..'")
        if self.id is not None and self.id < 1:
            raise ValueError("id must be a positive integer")
