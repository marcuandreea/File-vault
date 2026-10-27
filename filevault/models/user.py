"""User domain model."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

USERNAME_PATTERN = re.compile(r"^[a-z0-9_.-]{3,32}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$")


def normalize_username(raw: str) -> str:
    """Trim and lowercase a username as typed by the user."""
    return raw.strip().lower()


def normalize_email(raw: str) -> str:
    """Trim and lowercase an email address as typed by the user."""
    return raw.strip().lower()


@dataclass(frozen=True, slots=True) #slots=true optimizeaza memoria si performanta, dar face clasa mai putin flexibila prin restrictionarea atributelor la cele definite in clasa
class User:
    """An account that can own vaults. Only the password hash is stored."""

    username: str
    email: str
    password_hash: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    id: int | None = None

    @classmethod
    def create(cls, username: str, email: str, password_hash: str) -> User:
        """Build a user from raw input, normalizing username and email first."""
        return cls(
            username=normalize_username(username),
            email=normalize_email(email),
            password_hash=password_hash,
        )

    def __post_init__(self) -> None:
        if not USERNAME_PATTERN.match(self.username):
            raise ValueError(
                "username must be 3-32 chars using a-z, 0-9, '_', '.', '-'"
            )
        if not EMAIL_PATTERN.match(self.email):
            raise ValueError("email must look like name@example.com")
        if not self.password_hash:
            raise ValueError("password_hash must not be empty")
        if self.id is not None and self.id < 1:
            raise ValueError("id must be a positive integer")
