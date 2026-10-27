"""Audit log persistence."""

from __future__ import annotations

import sqlite3
from dataclasses import replace

from filevault.models import AuditEntry


class AuditRepository:
    """SQL access for the audit_log table."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def add(self, entry: AuditEntry) -> AuditEntry:
        """Insert an audit entry and return it with the generated id."""
        if entry.id is not None:
            raise ValueError("audit entry is already persisted")

        cursor = self._connection.execute(
            """
            INSERT INTO audit_log
                (timestamp, event_type, user_id, vault_id, file_id, message)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entry.timestamp.isoformat(),
                entry.event_type.value,
                entry.user_id,
                entry.vault_id,
                entry.file_id,
                entry.message,
            ),
        )
        # Commit on its own so the event survives if the business operation
        # that follows later fails.
        self._connection.commit()
        return replace(entry, id=int(cursor.lastrowid))
