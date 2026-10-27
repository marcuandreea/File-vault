"""Application configuration."""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DATABASE_PATH = DATA_DIR / "filevault.db"
VAULT_STORAGE_DIR = DATA_DIR / "vault_storage"


def ensure_data_dir() -> Path:
    """Create the data directory if it does not exist and return it."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR
