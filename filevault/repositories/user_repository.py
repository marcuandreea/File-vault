"""User persistence."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime

from filevault.models import User


class UserRepository:
    """SQL access for the users table."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def add(self, user: User) -> User:
        """Insert a new user and return it with the generated id."""
        if user.id is not None:
            raise ValueError("user is already persisted")

        cursor = self._connection.execute(
            """
            INSERT INTO users (username, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                user.username,
                user.email,
                user.password_hash,
                user.created_at.isoformat(),
            ),
        )
        self._connection.commit()
        return replace(user, id=int(cursor.lastrowid))

    def get_by_username(self, username: str) -> User | None:
        """Return the user with this exact username, or None."""
        row = self._connection.execute(
            """
            SELECT id, username, email, password_hash, created_at
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
        return None if row is None else self._to_user(row)

    def get_by_email(self, email: str) -> User | None:
        """Return the user with this exact email, or None."""
        row = self._connection.execute(
            """
            SELECT id, username, email, password_hash, created_at
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()
        return None if row is None else self._to_user(row)

    @staticmethod
    def _to_user(row: sqlite3.Row) -> User:
        return User(
            username=row["username"],
            email=row["email"],
            password_hash=row["password_hash"],
            created_at=datetime.fromisoformat(row["created_at"]),
            id=row["id"],
        )
