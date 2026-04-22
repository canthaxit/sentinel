"""SQLite storage backend for Sentinel."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from typing import Any

from .base import _CURRENT_SCHEMA_VERSION, StorageBackend, _serialize_session

# ---- SQLite Backend ----


_UNIFIED_SCHEMA = """
-- Shield tables (original)
CREATE TABLE IF NOT EXISTS shield_sessions (
    session_id  TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS shield_detections (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT NOT NULL,
    session_id       TEXT,
    verdict          TEXT,
    detection_method TEXT,
    ml_score         REAL,
    user_input       TEXT,
    data             TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_sd_verdict    ON shield_detections(verdict);
CREATE INDEX IF NOT EXISTS idx_sd_session    ON shield_detections(session_id);
CREATE INDEX IF NOT EXISTS idx_sd_ts         ON shield_detections(timestamp);

CREATE TABLE IF NOT EXISTS shield_iocs (
    payload_hash    TEXT PRIMARY KEY,
    data            TEXT NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    sighting_count  INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_si_last ON shield_iocs(last_seen);

-- Red team tables
CREATE TABLE IF NOT EXISTS redteam_sessions (
    session_id   TEXT PRIMARY KEY,
    started_at   TEXT NOT NULL,
    updated_at   TEXT,
    total_tests  INTEGER DEFAULT 0,
    metadata     TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS redteam_results (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id        TEXT NOT NULL REFERENCES redteam_sessions(session_id),
    scenario_id       TEXT,
    scenario_name     TEXT,
    category          TEXT,
    difficulty        TEXT,
    result            TEXT,
    confidence        REAL,
    response          TEXT,
    execution_time_ms REAL,
    bypass_indicators TEXT DEFAULT '[]',
    safe_indicators   TEXT DEFAULT '[]',
    ml_score          REAL,
    llm_verdict       TEXT,
    timestamp         TEXT,
    notes             TEXT DEFAULT '',
    extra             TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_rr_session    ON redteam_results(session_id);
CREATE INDEX IF NOT EXISTS idx_rr_category   ON redteam_results(category);
CREATE INDEX IF NOT EXISTS idx_rr_result     ON redteam_results(result);
CREATE INDEX IF NOT EXISTS idx_rr_difficulty ON redteam_results(difficulty);

-- Scheduler tables
CREATE TABLE IF NOT EXISTS scheduler_jobs (
    job_id      TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    cron        TEXT,
    target_url  TEXT,
    config      TEXT DEFAULT '{}',
    enabled     INTEGER DEFAULT 1,
    one_time    INTEGER DEFAULT 0,
    created_at  TEXT NOT NULL,
    last_run    TEXT,
    next_run    TEXT
);

CREATE TABLE IF NOT EXISTS scheduler_runs (
    run_id        TEXT PRIMARY KEY,
    job_id        TEXT,
    started_at    TEXT NOT NULL,
    completed_at  TEXT,
    status        TEXT DEFAULT 'running',
    session_id    TEXT,
    total_tests   INTEGER DEFAULT 0,
    detection_rate REAL,
    bypass_rate   REAL,
    config        TEXT DEFAULT '{}',
    error         TEXT
);

CREATE INDEX IF NOT EXISTS idx_sr_job     ON scheduler_runs(job_id);
CREATE INDEX IF NOT EXISTS idx_sr_started ON scheduler_runs(started_at);

-- Threat intelligence IOCs (replaces JSON shards)
CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    id               TEXT PRIMARY KEY,
    type             TEXT,
    threat_type      TEXT,
    severity         TEXT,
    ml_score         REAL,
    detection_method TEXT,
    first_seen       TEXT,
    last_seen        TEXT,
    sighting_count   INTEGER DEFAULT 1,
    payload_hash     TEXT UNIQUE,
    source           TEXT,
    mitre_techniques TEXT DEFAULT '[]',
    owasp_categories TEXT DEFAULT '[]',
    extra            TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_ti_hash     ON threat_intel_iocs(payload_hash);
CREATE INDEX IF NOT EXISTS idx_ti_severity ON threat_intel_iocs(severity);
CREATE INDEX IF NOT EXISTS idx_ti_type     ON threat_intel_iocs(type);

-- MCP audit trail
CREATE TABLE IF NOT EXISTS mcp_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    session_id      TEXT,
    tool_name       TEXT,
    allowed         INTEGER,
    blocked_reason  TEXT,
    severity        TEXT,
    findings        TEXT DEFAULT '[]',
    honey_triggered INTEGER DEFAULT 0,
    source_ip       TEXT
);

CREATE INDEX IF NOT EXISTS idx_mcp_ts   ON mcp_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_mcp_tool ON mcp_events(tool_name);

-- Schema versioning
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"""

# Keep backward-compat alias so _conn property still works for existing code
_SHIELD_SCHEMA = _UNIFIED_SCHEMA


class SQLiteBackend(StorageBackend):
    """SQLite-based persistent storage with WAL mode.

    Thread-safe via thread-local connections.  Stores all Sentinel
    platform data in a single database file.

    Args:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: str = "sentinel.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.executescript(_UNIFIED_SCHEMA)
            conn.commit()
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn
        conn.executescript(_UNIFIED_SCHEMA)
        conn.commit()
        self._check_schema_version()

    def _check_schema_version(self) -> None:
        """Record schema version if not already at current."""
        cur = self._conn.execute("SELECT MAX(version) FROM schema_version")
        row = cur.fetchone()
        current = row[0] if row[0] is not None else 0
        if current < _CURRENT_SCHEMA_VERSION:
            self._conn.execute(
                "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?, ?)",
                (_CURRENT_SCHEMA_VERSION, datetime.now().isoformat()),
            )
            self._conn.commit()

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # ================================================================
    # Shield Sessions
    # ================================================================

    def save_session(self, session_id: str, data: dict[str, Any]) -> None:
        now = datetime.now().isoformat()
        serialized = _serialize_session(data)
        self._conn.execute(
            """INSERT INTO shield_sessions (session_id, data, created_at, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(session_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at""",
            (session_id, serialized, now, now),
        )
        self._conn.commit()

    def load_session(self, session_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT data FROM shield_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["data"])

    def delete_session(self, session_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM shield_sessions WHERE session_id = ?", (session_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def list_sessions(self) -> dict[str, dict[str, Any]]:
        rows = self._conn.execute("SELECT session_id, data FROM shield_sessions").fetchall()
        result = {}
        for row in rows:
            result[row["session_id"]] = json.loads(row["data"])
        return result

    # ================================================================
    # Shield Detection events
    # ================================================================

    def log_detection(self, event: dict[str, Any]) -> None:
        now = event.get("timestamp", datetime.now().isoformat())
        self._conn.execute(
            """INSERT INTO shield_detections
               (timestamp, session_id, verdict, detection_method, ml_score, user_input, data)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                now,
                event.get("session_id"),
                event.get("verdict"),
                event.get("detection_method"),
                event.get("ml_score"),
                event.get("user_input"),
                json.dumps(event, default=str),
            ),
        )
        self._conn.commit()

    def query_detections(
        self,
        verdict: str | None = None,
        session_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        _ALLOWED_FILTERS = {"verdict", "session_id"}
        filters = {}
        if verdict:
            filters["verdict"] = verdict
        if session_id:
            filters["session_id"] = session_id

        clauses = []
        params: list = []
        for col, val in filters.items():
            if col not in _ALLOWED_FILTERS:
                continue
            clauses.append(f"{col} = ?")
            params.append(val)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT data FROM shield_detections{where} ORDER BY timestamp DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    # ================================================================
    # Shield IOCs
    # ================================================================

    def save_ioc(self, ioc: dict[str, Any]) -> None:
        now = datetime.now().isoformat()
        ph = ioc.get("payload_hash", "")
        self._conn.execute(
            """INSERT INTO shield_iocs (payload_hash, data, first_seen, last_seen, sighting_count)
               VALUES (?, ?, ?, ?, 1)
               ON CONFLICT(payload_hash) DO UPDATE SET
                   last_seen = excluded.last_seen,
                   sighting_count = shield_iocs.sighting_count + 1,
                   data = excluded.data""",
            (ph, json.dumps(ioc, default=str), now, now),
        )
        self._conn.commit()

    def query_iocs(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT data FROM shield_iocs ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    # ================================================================
    # Red Team
    # ================================================================

    def save_redteam_result(self, result: dict[str, Any], session_id: str) -> None:
        if hasattr(result, "__dict__"):
            rd = vars(result)
        else:
            rd = dict(result)

        conn = self._conn
        now = datetime.now().isoformat()

        # Upsert session
        conn.execute(
            """INSERT INTO redteam_sessions (session_id, started_at, updated_at, total_tests)
               VALUES (?, ?, ?, 0)
               ON CONFLICT(session_id) DO UPDATE SET updated_at=excluded.updated_at""",
            (session_id, now, now),
        )

        known_keys = {
            "scenario_id",
            "scenario_name",
            "category",
            "difficulty",
            "result",
            "confidence",
            "response",
            "execution_time_ms",
            "bypass_indicators_found",
            "safe_indicators_found",
            "ml_score",
            "llm_verdict",
            "timestamp",
            "notes",
        }
        extra = {k: v for k, v in rd.items() if k not in known_keys}

        bypass = rd.get("bypass_indicators_found") or rd.get("bypass_indicators") or []
        safe = rd.get("safe_indicators_found") or rd.get("safe_indicators") or []

        conn.execute(
            """INSERT INTO redteam_results
               (session_id, scenario_id, scenario_name, category, difficulty,
                result, confidence, response, execution_time_ms,
                bypass_indicators, safe_indicators, ml_score, llm_verdict,
                timestamp, notes, extra)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                session_id,
                rd.get("scenario_id", ""),
                rd.get("scenario_name", ""),
                rd.get("category", ""),
                rd.get("difficulty", ""),
                rd.get("result", ""),
                rd.get("confidence", 0),
                rd.get("response", ""),
                rd.get("execution_time_ms", 0),
                json.dumps(bypass),
                json.dumps(safe),
                rd.get("ml_score"),
                rd.get("llm_verdict"),
                rd.get("timestamp", now),
                rd.get("notes", ""),
                json.dumps(extra, default=str),
            ),
        )

        # Update session test count
        conn.execute(
            """UPDATE redteam_sessions SET total_tests = (
                   SELECT COUNT(*) FROM redteam_results WHERE session_id = ?
               ), updated_at = ? WHERE session_id = ?""",
            (session_id, now, session_id),
        )
        conn.commit()

    def get_redteam_session(self, session_id: str) -> dict[str, Any] | None:
        conn = self._conn
        row = conn.execute(
            "SELECT * FROM redteam_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if not row:
            return None

        results = [
            self._row_to_redteam_result(r)
            for r in conn.execute(
                "SELECT * FROM redteam_results WHERE session_id = ? ORDER BY id",
                (session_id,),
            )
        ]

        return {
            "session_id": row["session_id"],
            "started_at": row["started_at"],
            "updated_at": row["updated_at"],
            "total_tests": row["total_tests"],
            "results": results,
        }

    def list_redteam_sessions(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM redteam_sessions ORDER BY started_at DESC"
        ).fetchall()
        return [
            {
                "session_id": r["session_id"],
                "started_at": r["started_at"],
                "updated_at": r["updated_at"],
                "total_tests": r["total_tests"],
            }
            for r in rows
        ]

    def query_redteam_results(
        self,
        session_id: str | None = None,
        category: str | None = None,
        result_type: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses = []
        params: list = []
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if category:
            clauses.append("category = ?")
            params.append(category)
        if result_type:
            clauses.append("result = ?")
            params.append(result_type)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM redteam_results{where} ORDER BY id DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [self._row_to_redteam_result(r) for r in rows]

    def get_redteam_statistics(self, session_id: str | None = None) -> dict[str, Any]:
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
        by_result: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_difficulty: dict[str, int] = {}
        total_time = total_conf = detected = bypassed = high = 0

        for r in results:
            rt = r.get("result", "")
            by_result[rt] = by_result.get(rt, 0) + 1
            cat = r.get("category", "")
            by_category[cat] = by_category.get(cat, 0) + 1
            diff = r.get("difficulty", "")
            by_difficulty[diff] = by_difficulty.get(diff, 0) + 1
            total_time += r.get("execution_time_ms", 0) or 0
            total_conf += r.get("confidence", 0) or 0
            if rt == "detected":
                detected += 1
            elif rt == "bypass":
                bypassed += 1
            if (r.get("confidence") or 0) >= 0.85:
                high += 1

        return {
            "session_id": sess["session_id"],
            "total_tests": total,
            "started_at": sess["started_at"],
            "updated_at": sess.get("updated_at", ""),
            "by_result": by_result,
            "by_category": by_category,
            "by_difficulty": by_difficulty,
            "avg_execution_time_ms": total_time / total if total else 0,
            "avg_confidence": total_conf / total if total else 0,
            "detection_rate": (detected / total * 100) if total else 0,
            "bypass_rate": (bypassed / total * 100) if total else 0,
            "high_confidence_tests": high,
        }

    def delete_redteam_session(self, session_id: str) -> bool:
        conn = self._conn
        row = conn.execute(
            "SELECT session_id FROM redteam_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if not row:
            return False
        conn.execute("DELETE FROM redteam_results WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM redteam_sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        return True

    def cleanup_old_redteam_sessions(self, keep_latest: int = 10) -> int:
        sessions = self.list_redteam_sessions()
        if len(sessions) <= keep_latest:
            return 0
        to_delete = sessions[keep_latest:]
        deleted = 0
        for s in to_delete:
            if self.delete_redteam_session(s["session_id"]):
                deleted += 1
        return deleted

    # ================================================================
    # Scheduler
    # ================================================================

    def save_job(self, job: dict[str, Any]) -> None:
        config_data = {
            k: v
            for k, v in job.items()
            if k
            not in (
                "job_id",
                "name",
                "cron",
                "target_url",
                "enabled",
                "one_time",
                "created_at",
                "last_run",
                "next_run",
            )
        }
        self._conn.execute(
            """INSERT OR REPLACE INTO scheduler_jobs
               (job_id, name, cron, target_url, config, enabled,
                one_time, created_at, last_run, next_run)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                job["job_id"],
                job.get("name", ""),
                job.get("cron", ""),
                job.get("target_url", ""),
                json.dumps(config_data, default=str),
                1 if job.get("enabled", True) else 0,
                1 if job.get("one_time", False) else 0,
                job.get("created_at", datetime.now().isoformat()),
                job.get("last_run"),
                job.get("next_run"),
            ),
        )
        self._conn.commit()

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM scheduler_jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        return self._row_to_job(row) if row else None

    def list_jobs(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM scheduler_jobs ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_job(r) for r in rows]

    def delete_job(self, job_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM scheduler_jobs WHERE job_id = ?", (job_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def save_run(self, run: dict[str, Any]) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO scheduler_runs
               (run_id, job_id, started_at, completed_at, status,
                session_id, total_tests, detection_rate, bypass_rate,
                config, error)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run["run_id"],
                run.get("job_id"),
                run.get("started_at", datetime.now().isoformat()),
                run.get("completed_at"),
                run.get("status", "running"),
                run.get("session_id"),
                run.get("total_tests", 0),
                run.get("detection_rate"),
                run.get("bypass_rate"),
                json.dumps(run.get("config", {}), default=str),
                run.get("error"),
            ),
        )
        self._conn.commit()

    def get_run_history(self, limit: int = 50, job_id: str | None = None) -> list[dict[str, Any]]:
        if job_id:
            rows = self._conn.execute(
                "SELECT * FROM scheduler_runs WHERE job_id = ? ORDER BY started_at DESC LIMIT ?",
                (job_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM scheduler_runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_run(r) for r in rows]

    # ================================================================
    # Threat Intel IOCs
    # ================================================================

    def save_threat_ioc(self, ioc: dict[str, Any]) -> None:
        now = datetime.now().isoformat()
        self._conn.execute(
            """INSERT INTO threat_intel_iocs
               (id, type, threat_type, severity, ml_score, detection_method,
                first_seen, last_seen, sighting_count, payload_hash,
                source, mitre_techniques, owasp_categories, extra)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(payload_hash) DO UPDATE SET
                   last_seen = excluded.last_seen,
                   sighting_count = threat_intel_iocs.sighting_count + 1,
                   ml_score = MAX(COALESCE(threat_intel_iocs.ml_score, 0),
                                  COALESCE(excluded.ml_score, 0))""",
            (
                ioc.get("id", ""),
                ioc.get("type"),
                ioc.get("threat_type"),
                ioc.get("severity"),
                ioc.get("ml_score"),
                ioc.get("detection_method"),
                ioc.get("first_seen", now),
                ioc.get("last_seen", now),
                ioc.get("sighting_count", 1),
                ioc.get("payload_hash"),
                ioc.get("source"),
                json.dumps(ioc.get("mitre_techniques", [])),
                json.dumps(ioc.get("owasp_categories", [])),
                json.dumps(
                    {
                        k: v
                        for k, v in ioc.items()
                        if k
                        not in (
                            "id",
                            "type",
                            "threat_type",
                            "severity",
                            "ml_score",
                            "detection_method",
                            "first_seen",
                            "last_seen",
                            "sighting_count",
                            "payload_hash",
                            "source",
                            "mitre_techniques",
                            "owasp_categories",
                        )
                    },
                    default=str,
                ),
            ),
        )
        self._conn.commit()

    def query_threat_iocs(
        self,
        ioc_type: str | None = None,
        severity: str | None = None,
        threat_type: str | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list = []
        params: list = []
        if ioc_type:
            clauses.append("type = ?")
            params.append(ioc_type)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if threat_type:
            clauses.append("threat_type = ?")
            params.append(threat_type)
        if source:
            clauses.append("source = ?")
            params.append(source)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM threat_intel_iocs{where} ORDER BY last_seen DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [self._row_to_threat_ioc(r) for r in rows]

    def get_threat_ioc_by_hash(self, payload_hash: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM threat_intel_iocs WHERE payload_hash = ?", (payload_hash,)
        ).fetchone()
        return self._row_to_threat_ioc(row) if row else None

    def get_threat_statistics(self) -> dict[str, Any]:
        conn = self._conn
        total = conn.execute("SELECT COUNT(*) FROM threat_intel_iocs").fetchone()[0]
        total_sightings = conn.execute(
            "SELECT COALESCE(SUM(sighting_count), 0) FROM threat_intel_iocs"
        ).fetchone()[0]

        stats: dict[str, Any] = {
            "total_iocs": total,
            "total_sightings": total_sightings,
            "by_type": {},
            "by_severity": {},
            "by_threat_type": {},
        }

        for row in conn.execute(
            "SELECT type, COUNT(*) as cnt FROM threat_intel_iocs GROUP BY type"
        ):
            stats["by_type"][row["type"] or "unknown"] = row["cnt"]
        for row in conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM threat_intel_iocs GROUP BY severity"
        ):
            stats["by_severity"][row["severity"] or "unknown"] = row["cnt"]
        for row in conn.execute(
            "SELECT threat_type, COUNT(*) as cnt FROM threat_intel_iocs GROUP BY threat_type"
        ):
            stats["by_threat_type"][row["threat_type"] or "unknown"] = row["cnt"]

        return stats

    # ================================================================
    # MCP Events
    # ================================================================

    def log_mcp_event(self, event: dict[str, Any]) -> None:
        now = event.get("timestamp", datetime.now().isoformat())
        self._conn.execute(
            """INSERT INTO mcp_events
               (timestamp, session_id, tool_name, allowed, blocked_reason,
                severity, findings, honey_triggered, source_ip)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                now,
                event.get("session_id"),
                event.get("tool_name"),
                1 if event.get("allowed") else 0,
                event.get("blocked_reason"),
                event.get("severity"),
                json.dumps(event.get("findings", []), default=str),
                1 if event.get("honey_triggered") else 0,
                event.get("source_ip"),
            ),
        )
        self._conn.commit()

    def query_mcp_events(
        self,
        tool_name: str | None = None,
        allowed: bool | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list = []
        params: list = []
        if tool_name:
            clauses.append("tool_name = ?")
            params.append(tool_name)
        if allowed is not None:
            clauses.append("allowed = ?")
            params.append(1 if allowed else 0)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM mcp_events{where} ORDER BY timestamp DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            d["allowed"] = bool(d.get("allowed"))
            d["honey_triggered"] = bool(d.get("honey_triggered"))
            if "findings" in d and isinstance(d["findings"], str):
                try:
                    d["findings"] = json.loads(d["findings"])
                except (json.JSONDecodeError, TypeError):
                    d["findings"] = []
            results.append(d)
        return results

    # ================================================================
    # Schema migration
    # ================================================================

    def get_schema_version(self) -> int:
        cur = self._conn.execute("SELECT MAX(version) FROM schema_version")
        row = cur.fetchone()
        return row[0] if row[0] is not None else 0

    # ================================================================
    # Internal row helpers
    # ================================================================

    @staticmethod
    def _row_to_redteam_result(row) -> dict[str, Any]:
        d = dict(row)
        for key in ("bypass_indicators", "safe_indicators"):
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    d[key] = []
        if "extra" in d and isinstance(d["extra"], str):
            try:
                extra = json.loads(d["extra"])
                if isinstance(extra, dict):
                    d.update(extra)
            except (json.JSONDecodeError, TypeError):
                pass
            del d["extra"]
        d.pop("id", None)
        return d

    @staticmethod
    def _row_to_job(row) -> dict[str, Any]:
        d = dict(row)
        if "config" in d and isinstance(d["config"], str):
            try:
                config = json.loads(d["config"])
                if isinstance(config, dict):
                    d.update(config)
            except (json.JSONDecodeError, TypeError):
                pass
            del d["config"]
        d["enabled"] = bool(d.get("enabled", 1))
        d["one_time"] = bool(d.get("one_time", 0))
        return d

    @staticmethod
    def _row_to_run(row) -> dict[str, Any]:
        d = dict(row)
        if "config" in d and isinstance(d["config"], str):
            try:
                d["config"] = json.loads(d["config"])
            except (json.JSONDecodeError, TypeError):
                d["config"] = {}
        return d

    @staticmethod
    def _row_to_threat_ioc(row) -> dict[str, Any]:
        d = dict(row)
        for key in ("mitre_techniques", "owasp_categories"):
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    d[key] = []
        if "extra" in d and isinstance(d["extra"], str):
            try:
                extra = json.loads(d["extra"])
                if isinstance(extra, dict):
                    d.update(extra)
            except (json.JSONDecodeError, TypeError):
                pass
            del d["extra"]
        return d
