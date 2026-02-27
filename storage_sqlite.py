"""
SQLite persistent storage backend for Sentinel Platform.

Unified storage for detection logs and test results.  Uses a single
``sentinel.db`` file with WAL mode for concurrent read/write safety.

Tables:
    sessions        - Red team test sessions
    results         - Individual test results (FK -> sessions)
    scheduler_jobs  - Recurring / one-time scheduled jobs
    scheduler_runs  - Run history for scheduled jobs
    detection_logs  - Main detection pipeline log entries
    iocs            - Threat intelligence IOCs

Usage:
    from storage_sqlite import SQLiteStorage
    db = SQLiteStorage("sentinel.db")
    db.save_result(result_dict, "session_001")
    results = db.query_by_category("prompt_injection")
"""

import json
import csv
import io
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    started_at   TEXT NOT NULL,
    updated_at   TEXT,
    total_tests  INTEGER DEFAULT 0,
    metadata     TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS results (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT NOT NULL REFERENCES sessions(session_id),
    scenario_id      TEXT,
    scenario_name    TEXT,
    category         TEXT,
    difficulty       TEXT,
    result           TEXT,
    confidence       REAL,
    response         TEXT,
    execution_time_ms REAL,
    bypass_indicators TEXT DEFAULT '[]',
    safe_indicators   TEXT DEFAULT '[]',
    ml_score         REAL,
    llm_verdict      TEXT,
    timestamp        TEXT,
    notes            TEXT DEFAULT '',
    extra            TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_results_session  ON results(session_id);
CREATE INDEX IF NOT EXISTS idx_results_category ON results(category);
CREATE INDEX IF NOT EXISTS idx_results_result   ON results(result);
CREATE INDEX IF NOT EXISTS idx_results_difficulty ON results(difficulty);

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
    run_id       TEXT PRIMARY KEY,
    job_id       TEXT,
    started_at   TEXT NOT NULL,
    completed_at TEXT,
    status       TEXT DEFAULT 'running',
    session_id   TEXT,
    total_tests  INTEGER DEFAULT 0,
    detection_rate REAL,
    bypass_rate  REAL,
    config       TEXT DEFAULT '{}',
    error        TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_job ON scheduler_runs(job_id);
CREATE INDEX IF NOT EXISTS idx_runs_started ON scheduler_runs(started_at);

CREATE TABLE IF NOT EXISTS detection_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    session_id      TEXT,
    user_input      TEXT,
    verdict         TEXT,
    detection_method TEXT,
    ml_anomaly_score REAL,
    ml_threat_type  TEXT,
    ml_severity     TEXT,
    ml_processing_ms REAL,
    llm_verdict     TEXT,
    response_preview TEXT,
    sanitizations   TEXT DEFAULT '[]',
    extra           TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_logs_verdict ON detection_logs(verdict);
CREATE INDEX IF NOT EXISTS idx_logs_session ON detection_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_logs_ts      ON detection_logs(timestamp);

CREATE TABLE IF NOT EXISTS iocs (
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

CREATE INDEX IF NOT EXISTS idx_iocs_hash     ON iocs(payload_hash);
CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
CREATE INDEX IF NOT EXISTS idx_iocs_type     ON iocs(type);

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"""

_CURRENT_SCHEMA_VERSION = 1


class SQLiteStorage:
    """SQLite backend for unified Sentinel storage.

    Stores detection logs, test results, and session data.
    """

    def __init__(self, db_path: str = "sentinel.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    # -- Connection management (thread-safe) ---------------------------------

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        """Create tables if they don't exist and apply migrations."""
        conn = self._conn
        conn.executescript(_SCHEMA_SQL)
        # Record schema version
        cur = conn.execute("SELECT MAX(version) FROM schema_version")
        row = cur.fetchone()
        current = row[0] if row[0] is not None else 0
        if current < _CURRENT_SCHEMA_VERSION:
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?, ?)",
                (_CURRENT_SCHEMA_VERSION, datetime.now().isoformat()),
            )
            conn.commit()

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # ========================================================================
    # Red Team Results (drop-in for RedTeamResultsDB)
    # ========================================================================

    def save_result(self, result, session_id: str) -> None:
        """Save a single test result."""
        if hasattr(result, "__dict__"):
            rd = vars(result)
        else:
            rd = dict(result)

        conn = self._conn
        now = datetime.now().isoformat()

        # Upsert session
        conn.execute(
            """INSERT INTO sessions (session_id, started_at, updated_at, total_tests)
               VALUES (?, ?, ?, 0)
               ON CONFLICT(session_id) DO UPDATE SET updated_at=excluded.updated_at""",
            (session_id, now, now),
        )

        # Collect known columns, dump the rest into extra
        known_keys = {
            "scenario_id", "scenario_name", "category", "difficulty",
            "result", "confidence", "response", "execution_time_ms",
            "bypass_indicators_found", "safe_indicators_found",
            "ml_score", "llm_verdict", "timestamp", "notes",
        }
        extra = {k: v for k, v in rd.items() if k not in known_keys}

        bypass = rd.get("bypass_indicators_found") or rd.get("bypass_indicators") or []
        safe = rd.get("safe_indicators_found") or rd.get("safe_indicators") or []

        conn.execute(
            """INSERT INTO results
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
                json.dumps(extra),
            ),
        )

        # Update session test count
        conn.execute(
            """UPDATE sessions SET total_tests = (
                   SELECT COUNT(*) FROM results WHERE session_id = ?
               ), updated_at = ? WHERE session_id = ?""",
            (session_id, now, session_id),
        )
        conn.commit()

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Load all results from a session."""
        conn = self._conn
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if not row:
            return None

        results = [
            self._row_to_result(r)
            for r in conn.execute(
                "SELECT * FROM results WHERE session_id = ? ORDER BY id",
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

    def list_sessions(self) -> List[Dict]:
        """List all test sessions, newest first."""
        conn = self._conn
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC"
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

    def get_latest_session(self) -> Optional[Dict]:
        """Get the most recent test session."""
        conn = self._conn
        row = conn.execute(
            "SELECT session_id FROM sessions ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        if row:
            return self.get_session(row["session_id"])
        return None

    def query_by_category(self, category: str, session_id: Optional[str] = None) -> List[Dict]:
        conn = self._conn
        sid = session_id or self._latest_session_id()
        if not sid:
            return []
        rows = conn.execute(
            "SELECT * FROM results WHERE session_id = ? AND category = ?",
            (sid, category),
        ).fetchall()
        return [self._row_to_result(r) for r in rows]

    def query_by_result(self, result_type: str, session_id: Optional[str] = None) -> List[Dict]:
        conn = self._conn
        sid = session_id or self._latest_session_id()
        if not sid:
            return []
        rows = conn.execute(
            "SELECT * FROM results WHERE session_id = ? AND result = ?",
            (sid, result_type),
        ).fetchall()
        return [self._row_to_result(r) for r in rows]

    def query_by_difficulty(self, difficulty: str, session_id: Optional[str] = None) -> List[Dict]:
        conn = self._conn
        sid = session_id or self._latest_session_id()
        if not sid:
            return []
        rows = conn.execute(
            "SELECT * FROM results WHERE session_id = ? AND LOWER(difficulty) = LOWER(?)",
            (sid, difficulty),
        ).fetchall()
        return [self._row_to_result(r) for r in rows]

    def get_statistics(self, session_id: Optional[str] = None) -> Dict:
        """Calculate statistics for a session."""
        session_data = (
            self.get_session(session_id) if session_id else self.get_latest_session()
        )
        if not session_data or not session_data.get("results"):
            return {"error": "No results found"}

        results = session_data["results"]
        stats = {
            "session_id": session_data["session_id"],
            "total_tests": len(results),
            "started_at": session_data["started_at"],
            "updated_at": session_data.get("updated_at", ""),
            "by_result": {},
            "by_category": {},
            "by_difficulty": {},
            "avg_execution_time_ms": 0,
            "avg_confidence": 0,
            "detection_rate": 0,
            "bypass_rate": 0,
            "high_confidence_tests": 0,
        }

        total_time = total_conf = detected = bypassed = high = 0
        for r in results:
            rt = r["result"]
            stats["by_result"][rt] = stats["by_result"].get(rt, 0) + 1
            cat = r["category"]
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
            diff = r["difficulty"]
            stats["by_difficulty"][diff] = stats["by_difficulty"].get(diff, 0) + 1

            total_time += r.get("execution_time_ms", 0)
            total_conf += r.get("confidence", 0)
            if rt == "detected":
                detected += 1
            elif rt == "bypass":
                bypassed += 1
            if r.get("confidence", 0) >= 0.85:
                high += 1

        n = len(results)
        stats["avg_execution_time_ms"] = total_time / n
        stats["avg_confidence"] = total_conf / n
        stats["detection_rate"] = (detected / n) * 100
        stats["bypass_rate"] = (bypassed / n) * 100
        stats["high_confidence_tests"] = high
        return stats

    def delete_session(self, session_id: str) -> bool:
        conn = self._conn
        row = conn.execute(
            "SELECT session_id FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if not row:
            return False
        conn.execute("DELETE FROM results WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        return True

    def cleanup_old_sessions(self, keep_latest: int = 10) -> int:
        sessions = self.list_sessions()
        if len(sessions) <= keep_latest:
            return 0
        to_delete = sessions[keep_latest:]
        deleted = 0
        for s in to_delete:
            if self.delete_session(s["session_id"]):
                deleted += 1
        return deleted

    def export_to_csv(self, output_file: str, session_id: Optional[str] = None) -> None:
        session_data = (
            self.get_session(session_id) if session_id else self.get_latest_session()
        )
        if not session_data:
            return
        results = session_data["results"]
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)

    def export_to_json(self, output_file: str, session_id: Optional[str] = None) -> None:
        session_data = (
            self.get_session(session_id) if session_id else self.get_latest_session()
        )
        if not session_data:
            return
        with open(output_file, "w") as f:
            json.dump(session_data, f, indent=2)

    def generate_report(self, session_id: Optional[str] = None) -> str:
        stats = self.get_statistics(session_id)
        if "error" in stats:
            return f"# Error\n\n{stats['error']}"

        lines = [
            "# Red Team Test Report",
            f"\n**Session ID**: {stats['session_id']}",
            f"**Started**: {stats['started_at']}",
            f"**Completed**: {stats.get('updated_at', 'In progress')}",
            "\n## Summary\n",
            f"- **Total Tests**: {stats['total_tests']}",
            f"- **Detection Rate**: {stats['detection_rate']:.1f}%",
            f"- **Bypass Rate**: {stats['bypass_rate']:.1f}%",
            f"- **Average Confidence**: {stats['avg_confidence']:.2%}",
            f"- **Average Execution Time**: {stats['avg_execution_time_ms']:.2f}ms",
            f"- **High Confidence Tests**: {stats['high_confidence_tests']}",
            "\n## Results by Type\n",
        ]
        for rt, count in stats["by_result"].items():
            pct = (count / stats["total_tests"]) * 100
            lines.append(f"- **{rt}**: {count} ({pct:.1f}%)")
        lines.append("\n## Results by Category\n")
        for cat, count in sorted(stats["by_category"].items()):
            pct = (count / stats["total_tests"]) * 100
            lines.append(f"- **{cat}**: {count} ({pct:.1f}%)")
        lines.append("\n## Results by Difficulty\n")
        for diff, count in sorted(stats["by_difficulty"].items()):
            pct = (count / stats["total_tests"]) * 100
            lines.append(f"- **{diff}**: {count} ({pct:.1f}%)")
        return "\n".join(lines)

    def save_report(self, output_file: str, session_id: Optional[str] = None) -> None:
        report = self.generate_report(session_id)
        with open(output_file, "w") as f:
            f.write(report)

    # ========================================================================
    # Scheduler storage
    # ========================================================================

    def save_job(self, job: Dict) -> None:
        conn = self._conn
        config = {
            k: v for k, v in job.items()
            if k not in (
                "job_id", "name", "cron", "target_url", "enabled",
                "one_time", "created_at", "last_run", "next_run",
            )
        }
        conn.execute(
            """INSERT OR REPLACE INTO scheduler_jobs
               (job_id, name, cron, target_url, config, enabled,
                one_time, created_at, last_run, next_run)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                job["job_id"],
                job.get("name", ""),
                job.get("cron", ""),
                job.get("target_url", ""),
                json.dumps(config),
                1 if job.get("enabled", True) else 0,
                1 if job.get("one_time", False) else 0,
                job.get("created_at", datetime.now().isoformat()),
                job.get("last_run"),
                job.get("next_run"),
            ),
        )
        conn.commit()

    def get_job(self, job_id: str) -> Optional[Dict]:
        row = self._conn.execute(
            "SELECT * FROM scheduler_jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        return self._row_to_job(row) if row else None

    def list_jobs(self) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT * FROM scheduler_jobs ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_job(r) for r in rows]

    def delete_job(self, job_id: str) -> bool:
        conn = self._conn
        cur = conn.execute(
            "DELETE FROM scheduler_jobs WHERE job_id = ?", (job_id,)
        )
        conn.commit()
        return cur.rowcount > 0

    def save_run(self, run: Dict) -> None:
        conn = self._conn
        conn.execute(
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
                json.dumps(run.get("config", {})),
                run.get("error"),
            ),
        )
        conn.commit()

    def get_run_history(self, limit: int = 50, job_id: Optional[str] = None) -> List[Dict]:
        conn = self._conn
        if job_id:
            rows = conn.execute(
                "SELECT * FROM scheduler_runs WHERE job_id = ? ORDER BY started_at DESC LIMIT ?",
                (job_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scheduler_runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_run(r) for r in rows]

    # ========================================================================
    # Detection logs
    # ========================================================================

    def log_detection(self, entry: Dict) -> None:
        conn = self._conn
        conn.execute(
            """INSERT INTO detection_logs
               (timestamp, session_id, user_input, verdict, detection_method,
                ml_anomaly_score, ml_threat_type, ml_severity, ml_processing_ms,
                llm_verdict, response_preview, sanitizations, extra)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                entry.get("timestamp", datetime.now().isoformat()),
                entry.get("session_id"),
                entry.get("user_input"),
                entry.get("verdict"),
                entry.get("detection_method"),
                entry.get("ml_anomaly_score"),
                entry.get("ml_threat_type"),
                entry.get("ml_severity"),
                entry.get("ml_processing_ms"),
                entry.get("llm_verdict"),
                entry.get("response_preview"),
                json.dumps(entry.get("sanitizations_applied", [])),
                json.dumps({
                    k: v for k, v in entry.items()
                    if k not in (
                        "timestamp", "session_id", "user_input", "verdict",
                        "detection_method", "ml_anomaly_score", "ml_threat_type",
                        "ml_severity", "ml_processing_ms", "llm_verdict",
                        "response_preview", "sanitizations_applied",
                    )
                }),
            ),
        )
        conn.commit()

    def query_logs(
        self,
        verdict: Optional[str] = None,
        session_id: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        conn = self._conn
        clauses = []
        params: list = []
        if verdict:
            clauses.append("verdict = ?")
            params.append(verdict)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = conn.execute(
            f"SELECT * FROM detection_logs{where} ORDER BY timestamp DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [dict(r) for r in rows]

    def log_stats(self) -> Dict:
        conn = self._conn
        total = conn.execute("SELECT COUNT(*) FROM detection_logs").fetchone()[0]
        safe = conn.execute(
            "SELECT COUNT(*) FROM detection_logs WHERE verdict = 'SAFE'"
        ).fetchone()[0]
        malicious = conn.execute(
            "SELECT COUNT(*) FROM detection_logs WHERE verdict = 'MALICIOUS'"
        ).fetchone()[0]
        return {
            "total": total,
            "safe": safe,
            "malicious": malicious,
            "detection_rate": round(malicious / total * 100, 1) if total else 0,
        }

    # ========================================================================
    # IOC storage
    # ========================================================================

    def save_ioc(self, ioc: Dict) -> None:
        conn = self._conn
        conn.execute(
            """INSERT INTO iocs
               (id, type, threat_type, severity, ml_score, detection_method,
                first_seen, last_seen, sighting_count, payload_hash,
                source, mitre_techniques, owasp_categories, extra)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(payload_hash) DO UPDATE SET
                   last_seen = excluded.last_seen,
                   sighting_count = iocs.sighting_count + 1""",
            (
                ioc.get("id", ""),
                ioc.get("type"),
                ioc.get("threat_type"),
                ioc.get("severity"),
                ioc.get("ml_score"),
                ioc.get("detection_method"),
                ioc.get("first_seen", datetime.now().isoformat()),
                ioc.get("last_seen", datetime.now().isoformat()),
                ioc.get("sighting_count", 1),
                ioc.get("payload_hash"),
                ioc.get("source"),
                json.dumps(ioc.get("mitre_techniques", [])),
                json.dumps(ioc.get("owasp_categories", [])),
                json.dumps({
                    k: v for k, v in ioc.items()
                    if k not in (
                        "id", "type", "threat_type", "severity", "ml_score",
                        "detection_method", "first_seen", "last_seen",
                        "sighting_count", "payload_hash", "source",
                        "mitre_techniques", "owasp_categories",
                    )
                }),
            ),
        )
        conn.commit()

    def get_ioc(self, ioc_id: str) -> Optional[Dict]:
        row = self._conn.execute(
            "SELECT * FROM iocs WHERE id = ?", (ioc_id,)
        ).fetchone()
        return self._row_to_ioc(row) if row else None

    def query_iocs(
        self,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        conn = self._conn
        clauses: list = []
        params: list = []
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
        rows = conn.execute(
            f"SELECT * FROM iocs{where} ORDER BY last_seen DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [self._row_to_ioc(r) for r in rows]

    # ========================================================================
    # Migration: JSON -> SQLite
    # ========================================================================

    def migrate_from_json(
        self,
        results_dir: str = "redteam_results",
        schedules_file: str = "redteam_schedules.json",
        history_file: str = "redteam_history.json",
    ) -> Dict:
        """Migrate existing JSON data into this SQLite database.

        Returns:
            Dict with counts of migrated records.
        """
        counts = {"sessions": 0, "results": 0, "jobs": 0, "runs": 0}

        # --- Red team results ---
        results_path = Path(results_dir)
        if results_path.exists():
            index_file = results_path / "index.json"
            if index_file.exists():
                with open(index_file, "r") as f:
                    index = json.load(f)
                for sid in index.get("sessions", {}):
                    session_file = results_path / f"{sid}.json"
                    if session_file.exists():
                        with open(session_file, "r") as f:
                            session_data = json.load(f)
                        for r in session_data.get("results", []):
                            self.save_result(r, sid)
                            counts["results"] += 1
                        counts["sessions"] += 1

        # --- Scheduler jobs ---
        if os.path.exists(schedules_file):
            with open(schedules_file, "r") as f:
                sched_data = json.load(f)
            for jid, job in sched_data.get("jobs", {}).items():
                job["job_id"] = jid
                self.save_job(job)
                counts["jobs"] += 1

        # --- Scheduler history ---
        if os.path.exists(history_file):
            with open(history_file, "r") as f:
                hist_data = json.load(f)
            for run in hist_data.get("runs", []):
                self.save_run(run)
                counts["runs"] += 1

        return counts

    # ========================================================================
    # Internal helpers
    # ========================================================================

    def _latest_session_id(self) -> Optional[str]:
        row = self._conn.execute(
            "SELECT session_id FROM sessions ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return row["session_id"] if row else None

    @staticmethod
    def _row_to_result(row) -> Dict:
        d = dict(row)
        # Parse JSON fields back to lists
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
        # Remove internal auto-id
        d.pop("id", None)
        return d

    @staticmethod
    def _row_to_job(row) -> Dict:
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
    def _row_to_run(row) -> Dict:
        d = dict(row)
        if "config" in d and isinstance(d["config"], str):
            try:
                d["config"] = json.loads(d["config"])
            except (json.JSONDecodeError, TypeError):
                d["config"] = {}
        return d

    @staticmethod
    def _row_to_ioc(row) -> Dict:
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
