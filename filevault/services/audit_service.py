"""Recording security-relevant events without breaking the main operation."""

from __future__ import annotations

import logging

from filevault.models import AuditEntry, AuditEventType
from filevault.repositories.audit_repository import AuditRepository

logger = logging.getLogger(__name__)


class AuditService:
    """Writes audit entries. Never accepts passwords, hashes, keys or contents."""

    def __init__(self, entries: AuditRepository) -> None:
        self._entries = entries

    def record(
        self,
        event_type: AuditEventType,
        *,
        message: str,
        user_id: int | None = None,
        vault_id: int | None = None,
        file_id: int | None = None,
    ) -> None:
        """Store one event; failures are reported but never propagated."""
        try:
            self._entries.add(
                AuditEntry(
                    event_type=event_type,
                    message=message,
                    user_id=user_id,
                    vault_id=vault_id,
                    file_id=file_id,
                )
            )
        except Exception:
            # Audit is best-effort: losing an entry must not block login,
            # encryption or file operations. Surface it for diagnostics.
            logger.exception("failed to write audit event %s", event_type)
