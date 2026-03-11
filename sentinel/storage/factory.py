"""Factory function for creating storage backends."""

from __future__ import annotations

import os
from typing import Optional

from .base import StorageBackend
from .memory import MemoryBackend
from .sqlite import SQLiteBackend


# ---- Factory ----


def create_backend(
    backend_type: Optional[str] = None,
    db_path: Optional[str] = None,
) -> StorageBackend:
    """Create a storage backend from config or environment variables.

    Environment variables:
        SHIELD_STORAGE_BACKEND  -- ``memory`` (default) or ``sqlite``
        SHIELD_STORAGE_PATH     -- path to SQLite DB (default: ``sentinel.db``)
    """
    btype = backend_type or os.getenv("SHIELD_STORAGE_BACKEND", "memory")
    if btype == "sqlite":
        path = db_path or os.getenv("SHIELD_STORAGE_PATH", "sentinel.db")
        return SQLiteBackend(path)
    return MemoryBackend()
