"""SQLite connection and schema setup."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vaults (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    password_salt BLOB NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_files (
    id INTEGER PRIMARY KEY,
    vault_id INTEGER NOT NULL REFERENCES vaults(id),
    filename TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    storage_name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

-- Audit ids have no foreign keys on purpose: the trail must survive deletion
-- of the user, vault or file it refers to.
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_id INTEGER,
    vault_id INTEGER,
    file_id INTEGER,
    message TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_log_timestamp ON audit_log(timestamp);
"""


class Database:
    """Owns the SQLite connection and creates the schema."""

    def __init__(self, path: str | Path) -> None:
        self.path = path
        self._connection: sqlite3.Connection | None = None

    def connect(self) -> sqlite3.Connection:
        """Open the connection once and return it."""
        if self._connection is None:
            self._connection = sqlite3.connect(self.path)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
        return self._connection

    def initialize(self) -> None:
        """Create the tables if they do not exist yet, then migrate them."""
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            self._migrate(connection)

    @staticmethod
    def _migrate(connection: sqlite3.Connection) -> None:
        """Add columns introduced after the first schema version."""
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(vault_files)")
        }
        if "storage_name" in columns:
            return
        connection.execute(
            "ALTER TABLE vault_files ADD COLUMN storage_name TEXT NOT NULL DEFAULT ''"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS vault_files_storage_name "
            "ON vault_files(storage_name)"
        )

    def close(self) -> None:
        """Close the connection if it is open."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None
