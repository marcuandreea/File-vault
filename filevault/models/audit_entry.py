"""Audit log domain model and event types."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class AuditEventType(StrEnum):
    """Security-relevant events that are written to the audit log."""

    USER_REGISTERED = "user_registered"
    LOGIN_SUCCEEDED = "login_succeeded"
    LOGIN_FAILED = "login_failed"
    VAULT_CREATED = "vault_created"
    FILE_ADDED = "file_added"
    FILE_EXPORTED = "file_exported"
    FILE_DELETED = "file_deleted"
    FILE_ACCESS_DENIED = "file_access_denied"
    DECRYPTION_FAILED = "decryption_failed"
    ENCRYPTED_FILE_MISSING = "encrypted_file_missing"


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One audit record. Callers must pass only ids and non-secret context."""

    event_type: AuditEventType
    message: str
    user_id: int | None = None
    vault_id: int | None = None
    file_id: int | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    id: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, AuditEventType):
            raise ValueError("event_type must be an AuditEventType")
        if not self.message:
            raise ValueError("message must not be empty")
        for field_name in ("user_id", "vault_id", "file_id"):
            value = getattr(self, field_name)
            if value is not None and value < 1:
                raise ValueError(f"{field_name} must be a positive integer")
        if self.id is not None and self.id < 1:
            raise ValueError("id must be a positive integer")
