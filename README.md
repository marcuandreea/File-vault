# File Vault

Local desktop application for storing and managing files securely.

Users authenticate with an account password, then unlock individual vaults with a
separate vault password. Files are encrypted before they are written to disk.

## Stack

- Python 3.13
- SQLite
- `cryptography` (and `argon2-cffi` for password hashing)
- pytest
- PySide6 (later, for the GUI)

## Status

Work in progress. Currently at the domain model stage.
