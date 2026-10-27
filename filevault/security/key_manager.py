"""Vault key derivation with Argon2id."""

from __future__ import annotations

from argon2 import Type # type is an enumeration from the argon2 library that defines the different variants of the Argon2 password hashing algorithm. In this code, Type.ID is used to specify that the Argon2id variant should be used for key derivation.
from argon2.low_level import hash_secret_raw # hash_secret_raw is a low-level function from the argon2 library that allows you to derive a cryptographic key from a password and salt using the Argon2id algorithm. It takes several parameters, including the password, salt, time cost, memory cost, parallelism, hash length, and type of Argon2 variant to use. The function returns the derived key as bytes.

KEY_LENGTH = 32
SALT_LENGTH = 16

# RFC 9106 low-memory profile: 64 MiB, 3 passes, 4 lanes.
TIME_COST = 3
MEMORY_COST = 65536  # KiB
PARALLELISM = 4


class KeyManager:
    """Derives a 32-byte vault encryption key from password and salt."""

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Return an Argon2id key for this vault password and salt."""
        self._validate(password, salt)
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=TIME_COST,
            memory_cost=MEMORY_COST,
            parallelism=PARALLELISM,
            hash_len=KEY_LENGTH,
            type=Type.ID,
        )

    @staticmethod
    def _validate(password: str, salt: bytes) -> None:
        if not password:
            raise ValueError("password must not be empty")
        if not isinstance(salt, bytes):
            raise ValueError("salt must be bytes")
        if len(salt) != SALT_LENGTH:
            raise ValueError(f"salt must be {SALT_LENGTH} bytes")
