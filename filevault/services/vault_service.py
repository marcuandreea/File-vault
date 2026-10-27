"""Vault creation and listing."""

from __future__ import annotations

from filevault.models import AuditEventType, Vault
from filevault.repositories.vault_repository import VaultRepository
from filevault.services.audit_service import AuditService


class VaultService:
    """Creates vaults and lists them for their owner."""

    def __init__(self, vaults: VaultRepository, audit: AuditService) -> None:
        self._vaults = vaults
        self._audit = audit

    def create_vault(self, user_id: int, name: str) -> Vault:
        """Create a vault owned by user_id and return it."""
        vault = self._vaults.add(Vault.create(name, user_id))
        self._audit.record(
            AuditEventType.VAULT_CREATED,
            user_id=user_id,
            vault_id=vault.id,
            message="vault created",
        )
        return vault

    def list_vaults(self, user_id: int) -> list[Vault]:
        """Return the vaults owned by user_id, alphabetically."""
        return self._vaults.list_by_user(user_id)
