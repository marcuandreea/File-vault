"""Encrypting, listing, exporting and deleting vault files."""

from __future__ import annotations

from pathlib import Path

from filevault.models import AuditEventType, Vault, VaultFile
from filevault.repositories.vault_file_repository import VaultFileRepository
from filevault.security.key_manager import KeyManager
from filevault.services.audit_service import AuditService
from filevault.services.encryption_service import DecryptionError, EncryptionService
from filevault.storage.file_storage import FileStorage


class FileServiceError(Exception):
    """Base class for file management failures."""


class NotInVaultError(FileServiceError):
    """Raised when a file id does not belong to the given vault."""


class EncryptedFileMissingError(FileServiceError):
    """Raised when metadata exists but the encrypted file does not."""


class FileService:
    """Coordinates metadata, encrypted storage and encryption."""

    def __init__(
        self,
        files: VaultFileRepository,
        storage: FileStorage,
        keys: KeyManager,
        crypto: EncryptionService,
        audit: AuditService,
    ) -> None:
        self._files = files
        self._storage = storage
        self._keys = keys
        self._crypto = crypto
        self._audit = audit

    def add_file(
        self,
        vault: Vault,
        source_path: str | Path,
        vault_password: str,
    ) -> VaultFile:
        """Encrypt a file into the vault and store its metadata."""
        vault_id = self._vault_id(vault)
        source = Path(source_path)
        if not source.is_file():
            raise FileNotFoundError(f"source file not found: {source}")

        plaintext = source.read_bytes()
        key = self._keys.derive_key(vault_password, vault.password_salt) # derive the encryption key from the vault password and salt
        vault_file = VaultFile.create(vault_id, source.name, len(plaintext))  # create metadata first to get a storage name
        encrypted = self._crypto.encrypt(key, plaintext)

        stored_path = self._storage.save(
            vault_id, vault_file.storage_name, encrypted
        )
        try:
            added = self._files.add(vault_file) 
        except Exception:
            # Keep the storage clean when the metadata insert fails.
            stored_path.unlink(missing_ok=True)
            raise
        self._audit.record(
            AuditEventType.FILE_ADDED,
            vault_id=vault_id,
            file_id=added.id,
            message="file added",
        )
        return added

    def list_files(self, vault_id: int) -> list[VaultFile]:
        """Return file metadata without decrypting anything."""
        return self._files.list_by_vault(vault_id)

    def export_file(
        self,
        vault: Vault,
        file_id: int,
        destination_path: str | Path,
        vault_password: str,
    ) -> Path:
        """Decrypt one file to a location outside the vault storage."""
        vault_id = self._vault_id(vault)
        vault_file = self._require_file(vault_id, file_id)

        if not self._storage.exists(vault_id, vault_file.storage_name):
            self._audit.record(
                AuditEventType.ENCRYPTED_FILE_MISSING,
                vault_id=vault_id,
                file_id=file_id,
                message="encrypted file missing on export",
            )
            raise EncryptedFileMissingError(
                f"encrypted file for id {file_id} is missing"
            )
        encrypted = self._storage.read(vault_id, vault_file.storage_name)
        key = self._keys.derive_key(vault_password, vault.password_salt)
        try:
            plaintext = self._crypto.decrypt(key, encrypted)
        except DecryptionError:
            # Wrong vault password or tampered data; never log the key or plaintext.
            self._audit.record(
                AuditEventType.DECRYPTION_FAILED,
                vault_id=vault_id,
                file_id=file_id,
                message="file decryption failed",
            )
            raise

        destination = Path(destination_path)
        if destination.is_dir():
            destination = destination / vault_file.filename
        if self._storage.contains(destination):
            raise ValueError("cannot export into the vault storage directory")

        with destination.open("xb") as handle:
            handle.write(plaintext)
        self._audit.record(
            AuditEventType.FILE_EXPORTED,
            vault_id=vault_id,
            file_id=file_id,
            message="file exported",
        )
        return destination

    def delete_file(self, vault_id: int, file_id: int) -> None:
        """Delete the encrypted file and its metadata."""
        vault_file = self._require_file(vault_id, file_id)

        if not self._storage.exists(vault_id, vault_file.storage_name):
            self._audit.record(
                AuditEventType.ENCRYPTED_FILE_MISSING,
                vault_id=vault_id,
                file_id=file_id,
                message="encrypted file missing on delete",
            )
            raise EncryptedFileMissingError(
                f"encrypted file for id {file_id} is missing, metadata kept"
            )
        self._storage.delete(vault_id, vault_file.storage_name)
        self._files.delete(file_id)
        self._audit.record(
            AuditEventType.FILE_DELETED,
            vault_id=vault_id,
            file_id=file_id,
            message="file deleted",
        )

    @staticmethod
    def _vault_id(vault: Vault) -> int:
        if vault.id is None:
            raise ValueError("vault must be persisted")
        return vault.id

    def _require_file(self, vault_id: int, file_id: int) -> VaultFile:
        vault_file = self._files.get_by_id(file_id)
        if vault_file is None or vault_file.vault_id != vault_id:
            self._audit.record(
                AuditEventType.FILE_ACCESS_DENIED,
                vault_id=vault_id,
                file_id=file_id,
                message="file does not belong to vault",
            )
            raise NotInVaultError(f"file {file_id} does not exist in vault {vault_id}")
        return vault_file
