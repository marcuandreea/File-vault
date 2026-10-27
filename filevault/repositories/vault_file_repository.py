"""Vault file persistence."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime

from filevault.models import VaultFile


class VaultFileRepository:
    """SQL access for the vault_files table."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def add(self, vault_file: VaultFile) -> VaultFile:
        """Insert a new file entry and return it with the generated id."""
        if vault_file.id is not None:
            raise ValueError("vault file is already persisted")

        cursor = self._connection.execute(
            """
            INSERT INTO vault_files
                (vault_id, filename, size, storage_name, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                vault_file.vault_id,
                vault_file.filename,
                vault_file.size,
                vault_file.storage_name,
                vault_file.created_at.isoformat(),
            ),
        )
        self._connection.commit()
        return replace(vault_file, id=int(cursor.lastrowid))

    def list_by_vault(self, vault_id: int) -> list[VaultFile]:
        """Return every file entry of this vault, alphabetically."""
        rows = self._connection.execute(
            """
            SELECT id, vault_id, filename, size, storage_name, created_at
            FROM vault_files
            WHERE vault_id = ?
            ORDER BY filename COLLATE NOCASE
            """,
            (vault_id,),
        ).fetchall()
        return [self._to_vault_file(row) for row in rows]

    def get_by_id(self, file_id: int) -> VaultFile | None:
        """Return the file entry with this id, or None."""
        row = self._connection.execute(
            """
            SELECT id, vault_id, filename, size, storage_name, created_at
            FROM vault_files
            WHERE id = ?
            """,
            (file_id,),
        ).fetchone()
        return None if row is None else self._to_vault_file(row)

    def delete(self, file_id: int) -> None:
        """Remove the file entry. Does nothing when the id is unknown."""
        self._connection.execute(
            "DELETE FROM vault_files WHERE id = ?",
            (file_id,),
        )
        self._connection.commit()

    @staticmethod
    def _to_vault_file(row: sqlite3.Row) -> VaultFile:
        return VaultFile(
            vault_id=row["vault_id"],
            filename=row["filename"],
            size=row["size"],
            storage_name=row["storage_name"],
            created_at=datetime.fromisoformat(row["created_at"]),
            id=row["id"],
        )
