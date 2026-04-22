"""In-memory storage backend for Sentinel."""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Any

from .base import StorageBackend

# ---- Memory Backend ----


class MemoryBackend(StorageBackend):
    """In-memory storage (no persistence across restarts).

    Thread-safe.  This is the default when no backend is configured.
    Implements all method groups including red team, scheduler,
    threat intel, and MCP for testing purposes.
    """

    def __init__(self):
        self._sessions: dict[str, dict[str, Any]] = {}
        self._detections: list[dict[str, Any]] = []
        self._iocs: dict[str, dict[str, Any]] = {}  # payload_hash -> ioc
        self._redteam_sessions: dict[str, dict[str, Any]] = {}
        self._redteam_results: list[dict[str, Any]] = []
        self._scheduler_jobs: dict[str, dict[str, Any]] = {}
        self._scheduler_runs: list[dict[str, Any]] = []
        self._threat_iocs: dict[str, dict[str, Any]] = {}  # payload_hash -> ioc
        self._mcp_events: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    # -- Shield Sessions --

    def save_session(self, session_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            self._sessions[session_id] = dict(data)

    def load_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            s = self._sessions.get(session_id)
            return dict(s) if s else None

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def list_sessions(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {sid: dict(s) for sid, s in self._sessions.items()}

    # -- Shield Detections --

    def log_detection(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._detections.append(dict(event))

    def query_detections(
        self,
        verdict: str | None = None,
        session_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        with self._lock:
            results = list(reversed(self._detections))
            if verdict:
                results = [e for e in results if e.get("verdict") == verdict]
            if session_id:
                results = [e for e in results if e.get("session_id") == session_id]
            return results[:limit]

    # -- Shield IOCs --

    def save_ioc(self, ioc: dict[str, Any]) -> None:
        with self._lock:
            ph = ioc.get("payload_hash", "")
            if ph in self._iocs:
                existing = self._iocs[ph]
                existing["sighting_count"] = existing.get("sighting_count", 1) + 1
                existing["last_seen"] = ioc.get("last_seen", datetime.now().isoformat())
            else:
                self._iocs[ph] = dict(ioc)

    def query_iocs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            items = sorted(
                self._iocs.values(),
                key=lambda x: x.get("last_seen", ""),
                reverse=True,
            )
            return items[:limit]

    # -- Red Team --

    def save_redteam_result(self, result: dict[str, Any], session_id: str) -> None:
        with self._lock:
            now = datetime.now().isoformat()
            if session_id not in self._redteam_sessions:
                self._redteam_sessions[session_id] = {
                    "session_id": session_id,
                    "started_at": now,
                    "updated_at": now,
                    "total_tests": 0,
                }
            sess = self._redteam_sessions[session_id]
            sess["updated_at"] = now
            r = dict(result)
            r["session_id"] = session_id
            self._redteam_results.append(r)
            sess["total_tests"] = sum(
                1 for rr in self._redteam_results if rr.get("session_id") == session_id
            )

    def get_redteam_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            sess = self._redteam_sessions.get(session_id)
            if not sess:
                return None
            results = [dict(r) for r in self._redteam_results if r.get("session_id") == session_id]
            return {**sess, "results": results}

    def list_redteam_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            items = sorted(
                self._redteam_sessions.values(),
                key=lambda x: x.get("started_at", ""),
                reverse=True,
            )
            return [dict(s) for s in items]

    def query_redteam_results(
        self,
        session_id: str | None = None,
        category: str | None = None,
        result_type: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        with self._lock:
            results = list(self._redteam_results)
            if session_id:
                results = [r for r in results if r.get("session_id") == session_id]
            if category:
                results = [r for r in results if r.get("category") == category]
            if result_type:
                results = [r for r in results if r.get("result") == result_type]
            return results[:limit]

    def get_redteam_statistics(self, session_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            if session_id:
                sess = self.get_redteam_session(session_id)
            else:
                sessions = self.list_redteam_sessions()
                if not sessions:
                    return {"error": "No results found"}
                sess = self.get_redteam_session(sessions[0]["session_id"])
            if not sess or not sess.get("results"):
                return {"error": "No results found"}
            results = sess["results"]
            total = len(results)
            detected = sum(1 for r in results if r.get("result") == "detected")
            bypassed = sum(1 for r in results if r.get("result") == "bypass")
            return {
                "session_id": sess["session_id"],
                "total_tests": total,
                "detection_rate": (detected / total * 100) if total else 0,
                "bypass_rate": (bypassed / total * 100) if total else 0,
            }

    def delete_redteam_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id not in self._redteam_sessions:
                return False
            del self._redteam_sessions[session_id]
            self._redteam_results = [
                r for r in self._redteam_results if r.get("session_id") != session_id
            ]
            return True

    def cleanup_old_redteam_sessions(self, keep_latest: int = 10) -> int:
        with self._lock:
            sessions = self.list_redteam_sessions()
            if len(sessions) <= keep_latest:
                return 0
            to_delete = sessions[keep_latest:]
            deleted = 0
            for s in to_delete:
                if self.delete_redteam_session(s["session_id"]):
                    deleted += 1
            return deleted

    # -- Scheduler --

    def save_job(self, job: dict[str, Any]) -> None:
        with self._lock:
            self._scheduler_jobs[job["job_id"]] = dict(job)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            j = self._scheduler_jobs.get(job_id)
            return dict(j) if j else None

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(j) for j in self._scheduler_jobs.values()]

    def delete_job(self, job_id: str) -> bool:
        with self._lock:
            return self._scheduler_jobs.pop(job_id, None) is not None

    def save_run(self, run: dict[str, Any]) -> None:
        with self._lock:
            self._scheduler_runs.append(dict(run))

    def get_run_history(self, limit: int = 50, job_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            runs = list(reversed(self._scheduler_runs))
            if job_id:
                runs = [r for r in runs if r.get("job_id") == job_id]
            return runs[:limit]

    # -- Threat Intel IOCs --

    def save_threat_ioc(self, ioc: dict[str, Any]) -> None:
        with self._lock:
            ph = ioc.get("payload_hash", "")
            if ph in self._threat_iocs:
                existing = self._threat_iocs[ph]
                existing["sighting_count"] = existing.get("sighting_count", 1) + 1
                existing["last_seen"] = ioc.get("last_seen", datetime.now().isoformat())
                # Update ML score if higher
                if ioc.get("ml_score") and (
                    not existing.get("ml_score") or ioc["ml_score"] > existing["ml_score"]
                ):
                    existing["ml_score"] = ioc["ml_score"]
            else:
                self._threat_iocs[ph] = dict(ioc)

    def query_threat_iocs(
        self,
        ioc_type: str | None = None,
        severity: str | None = None,
        threat_type: str | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        with self._lock:
            results = list(self._threat_iocs.values())
            if ioc_type:
                results = [i for i in results if i.get("type") == ioc_type]
            if severity:
                results = [i for i in results if i.get("severity") == severity]
            if threat_type:
                results = [i for i in results if i.get("threat_type") == threat_type]
            if source:
                results = [i for i in results if i.get("source") == source]
            results.sort(key=lambda x: x.get("last_seen", ""), reverse=True)
            return results[:limit]

    def get_threat_ioc_by_hash(self, payload_hash: str) -> dict[str, Any] | None:
        with self._lock:
            ioc = self._threat_iocs.get(payload_hash)
            return dict(ioc) if ioc else None

    def get_threat_statistics(self) -> dict[str, Any]:
        with self._lock:
            all_iocs = list(self._threat_iocs.values())
            stats: dict[str, Any] = {
                "total_iocs": len(all_iocs),
                "by_type": {},
                "by_severity": {},
                "by_threat_type": {},
                "total_sightings": 0,
            }
            for ioc in all_iocs:
                t = ioc.get("type", "unknown")
                stats["by_type"][t] = stats["by_type"].get(t, 0) + 1
                s = ioc.get("severity", "unknown")
                stats["by_severity"][s] = stats["by_severity"].get(s, 0) + 1
                tt = ioc.get("threat_type", "unknown")
                stats["by_threat_type"][tt] = stats["by_threat_type"].get(tt, 0) + 1
                stats["total_sightings"] += ioc.get("sighting_count", 1)
            return stats

    # -- MCP Events --

    def log_mcp_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._mcp_events.append(dict(event))

    def query_mcp_events(
        self,
        tool_name: str | None = None,
        allowed: bool | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        with self._lock:
            results = list(reversed(self._mcp_events))
            if tool_name:
                results = [e for e in results if e.get("tool_name") == tool_name]
            if allowed is not None:
                results = [e for e in results if e.get("allowed") == allowed]
            return results[:limit]
