"""Vault domain model."""

from __future__ import annotations #type hints amanat

import secrets #genereate random bytes for password salt imprev dpdv criptografic
from dataclasses import dataclass, field #genereaza boilerplate code for classes, like __init__, __repr__, __eq__, etc.
from datetime import UTC, datetime

VAULT_NAME_MAX_LENGTH = 60
PASSWORD_SALT_LENGTH = 16


def normalize_name(raw: str) -> str:
    """Trim a vault name as typed by the user."""
    return raw.strip()


@dataclass(frozen=True, slots=True)
class Vault:
    """A named container of encrypted files, owned by a single user."""

    name: str
    user_id: int
    password_salt: bytes = field(
        default_factory=lambda: secrets.token_bytes(PASSWORD_SALT_LENGTH) #
    )
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    id: int | None = None

    @classmethod
    def create(cls, name: str, user_id: int) -> Vault:
        """Build a vault from raw input, normalizing the name first."""
        return cls(name=normalize_name(name), user_id=user_id)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("name must not be empty")
        if len(self.name) > VAULT_NAME_MAX_LENGTH:
            raise ValueError(
                f"name must be at most {VAULT_NAME_MAX_LENGTH} characters"
            )
        if self.user_id < 1:
            raise ValueError("user_id must be a positive integer")
        if not isinstance(self.password_salt, bytes):
            raise ValueError("password_salt must be bytes")
        if len(self.password_salt) != PASSWORD_SALT_LENGTH:
            raise ValueError(
                f"password_salt must be {PASSWORD_SALT_LENGTH} bytes"
            )
        if self.id is not None and self.id < 1:
            raise ValueError("id must be a positive integer")
