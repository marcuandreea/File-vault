"""Vault persistence."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime

from filevault.models import Vault


class UnknownUserError(Exception):
    """Raised when a vault is created for a user id that does not exist."""


class VaultRepository:
    """SQL access for the vaults table."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def add(self, vault: Vault) -> Vault:
        """Insert a new vault and return it with the generated id."""
        if vault.id is not None:
            raise ValueError("vault is already persisted")

        try:
            cursor = self._connection.execute(
                """
                INSERT INTO vaults (user_id, name, password_salt, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    vault.user_id,
                    vault.name,
                    vault.password_salt,
                    vault.created_at.isoformat(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            # vaults has a single constraint, its foreign key, so a failure
            # here means the owner is missing.
            raise UnknownUserError(f"user {vault.user_id} does not exist") from exc

        self._connection.commit()
        return replace(vault, id=int(cursor.lastrowid))

    def list_by_user(self, user_id: int) -> list[Vault]:
        """Return every vault owned by this user, alphabetically."""
        rows = self._connection.execute(
            """
            SELECT id, user_id, name, password_salt, created_at
            FROM vaults
            WHERE user_id = ?
            ORDER BY name COLLATE NOCASE
            """,
            (user_id,),
        ).fetchall()
        return [self._to_vault(row) for row in rows]

    @staticmethod
    def _to_vault(row: sqlite3.Row) -> Vault:
        return Vault(
            name=row["name"],
            user_id=row["user_id"],
            password_salt=row["password_salt"],
            created_at=datetime.fromisoformat(row["created_at"]),
            id=row["id"],
        )
