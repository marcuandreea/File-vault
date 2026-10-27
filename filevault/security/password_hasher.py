"""Password hashing with Argon2id."""

from __future__ import annotations

from argon2 import PasswordHasher as Argon2PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError


class PasswordHasher:
    """Hashes and verifies account passwords with Argon2id."""

    def __init__(self) -> None:
        self._argon2 = Argon2PasswordHasher()

    def hash(self, password: str) -> str:
        """Return an Argon2id hash for a plaintext password."""
        return self._argon2.hash(password)

    def verify(self, password: str, password_hash: str) -> bool:
        """Return True when the plaintext password matches the stored hash."""
        # VerifyMismatchError is a VerificationError, so this covers wrong passwords
        # as well as hashes that cannot be parsed.
        try:
            return self._argon2.verify(password_hash, password)
        except (VerificationError, InvalidHashError):
            return False
