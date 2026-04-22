"""
Sentinel - Unified Storage Backends
Abstract storage interface with Memory and SQLite implementations.

Provides persistent storage for:
- Shield sessions and detection events
- Shield IOCs
- Red team sessions, results, scheduler jobs/runs
- Threat intelligence IOCs
- MCP guard events
- Schema migration tracking

All components share a single ``sentinel.db`` file (when using SQLite).

Usage::

    from sentinel.storage import create_backend

    # Auto-detect from environment variables
    backend = create_backend()

    # Or explicit SQLite (unified DB)
    backend = create_backend(backend_type="sqlite", db_path="sentinel.db")
    backend.save_session("sess-1", {"threat_count": 3, "escalated": True})
    backend.save_redteam_result(result_dict, "session_001")
    backend.log_mcp_event({...})
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

_CURRENT_SCHEMA_VERSION = 1


def _make_serializable(obj: Any) -> Any:
    """Convert datetime and other non-JSON types to strings."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    return obj


def _serialize_session(data: Dict[str, Any]) -> str:
    """Serialize a session dict to JSON."""
    clean = {}
    for k, v in data.items():
        clean[k] = _make_serializable(v)
    return json.dumps(clean, default=str)


# ---- Abstract Backend ----


class StorageBackend(ABC):
    """Abstract interface for unified Sentinel storage.

    Core methods (sessions, detections, IOCs) are abstract and must be
    implemented by all backends.  Extended method groups (red team,
    scheduler, threat intel, MCP) have default no-op implementations so
    existing backends and custom subclasses don't break.
    """

    # ================================================================
    # Shield Sessions (abstract)
    # ================================================================

    @abstractmethod
    def save_session(self, session_id: str, data: Dict[str, Any]) -> None:
        """Persist session state."""

    @abstractmethod
    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Load session state.  Returns None if not found."""

    @abstractmethod
    def delete_session(self, session_id: str) -> bool:
        """Delete a session.  Returns True if deleted."""

    @abstractmethod
    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Return all sessions as {session_id: data}."""

    # ================================================================
    # Shield Detection events (abstract)
    # ================================================================

    @abstractmethod
    def log_detection(self, event: Dict[str, Any]) -> None:
        """Store a detection event."""

    @abstractmethod
    def query_detections(
        self,
        verdict: Optional[str] = None,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query detection events with optional filters."""

    # ================================================================
    # Shield IOCs (abstract)
    # ================================================================

    @abstractmethod
    def save_ioc(self, ioc: Dict[str, Any]) -> None:
        """Store or update an IOC (deduplicated by payload_hash)."""

    @abstractmethod
    def query_iocs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Query stored IOCs."""

    # ================================================================
    # Red Team (default no-ops)
    # ================================================================

    def save_redteam_result(self, result: Dict[str, Any], session_id: str) -> None:
        """Save a red team test result."""

    def get_redteam_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Load all results from a red team session."""
        return None

    def list_redteam_sessions(self) -> List[Dict[str, Any]]:
        """List all red team sessions, newest first."""
        return []

    def query_redteam_results(
        self,
        session_id: Optional[str] = None,
        category: Optional[str] = None,
        result_type: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """Query red team results with optional filters."""
        return []

    def get_redteam_statistics(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Calculate red team statistics for a session."""
        return {"error": "Not implemented"}

    def delete_redteam_session(self, session_id: str) -> bool:
        """Delete a red team session and its results."""
        return False

    def cleanup_old_redteam_sessions(self, keep_latest: int = 10) -> int:
        """Remove old red team sessions, keeping the N most recent."""
        return 0

    # ================================================================
    # Scheduler (default no-ops)
    # ================================================================

    def save_job(self, job: Dict[str, Any]) -> None:
        """Save or update a scheduler job."""

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get a scheduler job by ID."""
        return None

    def list_jobs(self) -> List[Dict[str, Any]]:
        """List all scheduler jobs."""
        return []

    def delete_job(self, job_id: str) -> bool:
        """Delete a scheduler job."""
        return False

    def save_run(self, run: Dict[str, Any]) -> None:
        """Save a scheduler run record."""

    def get_run_history(self, limit: int = 50, job_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get scheduler run history."""
        return []

    # ================================================================
    # Threat Intel IOCs (default no-ops)
    # ================================================================

    def save_threat_ioc(self, ioc: Dict[str, Any]) -> None:
        """Save or update a threat intel IOC (deduplicated by payload_hash)."""

    def query_threat_iocs(
        self,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query threat intel IOCs."""
        return []

    def get_threat_ioc_by_hash(self, payload_hash: str) -> Optional[Dict[str, Any]]:
        """Get a threat intel IOC by payload hash."""
        return None

    def get_threat_statistics(self) -> Dict[str, Any]:
        """Calculate threat intel IOC statistics."""
        return {"total_iocs": 0}

    # ================================================================
    # MCP Events (default no-ops)
    # ================================================================

    def log_mcp_event(self, event: Dict[str, Any]) -> None:
        """Log an MCP guard intercept event."""

    def query_mcp_events(
        self,
        tool_name: Optional[str] = None,
        allowed: Optional[bool] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query MCP events with optional filters."""
        return []

    # ================================================================
    # Schema migration (default no-op)
    # ================================================================

    def get_schema_version(self) -> int:
        """Return current schema version."""
        return 0
