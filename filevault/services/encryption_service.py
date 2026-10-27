"""AES-256-GCM encryption for vault data."""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM 

KEY_LENGTH = 32
NONCE_LENGTH = 12 
TAG_LENGTH = 16 


class DecryptionError(Exception):
    """Raised when data is corrupted or was encrypted with another key."""


class EncryptionService:
    """Encrypts and decrypts bytes with AES-256-GCM."""

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """Return nonce + ciphertext + tag as a single blob."""
        self._validate_key(key)
        if not isinstance(plaintext, bytes):
            raise ValueError("plaintext must be bytes")

        nonce = secrets.token_bytes(NONCE_LENGTH)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        return nonce + ciphertext 

    def decrypt(self, key: bytes, blob: bytes) -> bytes:
        """Return the plaintext, or raise DecryptionError."""
        self._validate_key(key)
        if not isinstance(blob, bytes):
            raise ValueError("blob must be bytes")
        if len(blob) < NONCE_LENGTH + TAG_LENGTH:
            raise DecryptionError("data is too short to be encrypted")

        nonce = blob[:NONCE_LENGTH] 
        ciphertext = blob[NONCE_LENGTH:]
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise DecryptionError("wrong key or corrupted data") from exc

    @staticmethod
    def _validate_key(key: bytes) -> None:
        if not isinstance(key, bytes):
            raise ValueError("key must be bytes")
        if len(key) != KEY_LENGTH:
            raise ValueError(f"key must be {KEY_LENGTH} bytes")
