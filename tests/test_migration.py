"""
Tests for the unified database migration tool.
Run: python -m pytest tests/test_migration.py -v
"""

import json
import os
import sqlite3

import pytest

from sentinel.storage import SQLiteBackend


class TestMigrationFromJsonShards:
    """Test migration of threat intel JSON shards into unified DB."""

    def _create_shard(self, data_dir, shard_name, iocs):
        """Helper to create a JSON shard file."""
        os.makedirs(data_dir, exist_ok=True)
        with open(os.path.join(data_dir, shard_name), "w") as f:
            json.dump(iocs, f)

    def test_migrate_single_shard(self, tmp_path):
        from migrate_to_unified_db import migrate_threat_intel_json

        data_dir = os.path.join(tmp_path, "threat_data")
        self._create_shard(data_dir, "iocs_2026_01.json", [
            {"id": "ioc-1", "payload_hash": "h1", "severity": "high",
             "type": "injection", "threat_type": "pi", "ml_score": 0.9,
             "first_seen": "2026-01-01", "last_seen": "2026-01-15"},
            {"id": "ioc-2", "payload_hash": "h2", "severity": "critical",
             "type": "jailbreak", "threat_type": "jb", "ml_score": 0.95,
             "first_seen": "2026-01-10", "last_seen": "2026-01-20"},
        ])

        db_path = os.path.join(tmp_path, "target.db")
        backend = SQLiteBackend(db_path)
        counts = migrate_threat_intel_json(data_dir, backend)

        assert counts["shards_read"] == 1
        assert counts["threat_intel_iocs"] == 2

        iocs = backend.query_threat_iocs()
        assert len(iocs) == 2
        backend.close()

    def test_migrate_multiple_shards(self, tmp_path):
        from migrate_to_unified_db import migrate_threat_intel_json

        data_dir = os.path.join(tmp_path, "threat_data")
        self._create_shard(data_dir, "iocs_2026_01.json", [
            {"id": "1", "payload_hash": "a", "severity": "high"},
        ])
        self._create_shard(data_dir, "iocs_2026_02.json", [
            {"id": "2", "payload_hash": "b", "severity": "low"},
            {"id": "3", "payload_hash": "c", "severity": "critical"},
        ])

        db_path = os.path.join(tmp_path, "target.db")
        backend = SQLiteBackend(db_path)
        counts = migrate_threat_intel_json(data_dir, backend)

        assert counts["shards_read"] == 2
        assert counts["threat_intel_iocs"] == 3
        backend.close()

    def test_migrate_empty_dir(self, tmp_path):
        from migrate_to_unified_db import migrate_threat_intel_json

        data_dir = os.path.join(tmp_path, "empty")
        os.makedirs(data_dir)

        db_path = os.path.join(tmp_path, "target.db")
        backend = SQLiteBackend(db_path)
        counts = migrate_threat_intel_json(data_dir, backend)

        assert counts["shards_read"] == 0
        assert counts["threat_intel_iocs"] == 0
        backend.close()

    def test_migrate_missing_dir(self, tmp_path):
        from migrate_to_unified_db import migrate_threat_intel_json

        db_path = os.path.join(tmp_path, "target.db")
        backend = SQLiteBackend(db_path)
        counts = migrate_threat_intel_json("/nonexistent/path", backend)

        assert counts["threat_intel_iocs"] == 0
        backend.close()


class TestMigrationFromOldSQLite:
    """Test migration of red team data from old storage_sqlite.py DB."""

    def _create_old_db(self, db_path):
        """Create an old-format SQLite DB with test data."""
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                updated_at TEXT,
                total_tests INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}'
            );
            CREATE TABLE results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                scenario_id TEXT,
                scenario_name TEXT,
                category TEXT,
                difficulty TEXT,
                result TEXT,
                confidence REAL,
                response TEXT,
                execution_time_ms REAL,
                bypass_indicators TEXT DEFAULT '[]',
                safe_indicators TEXT DEFAULT '[]',
                ml_score REAL,
                llm_verdict TEXT,
                timestamp TEXT,
                notes TEXT DEFAULT '',
                extra TEXT DEFAULT '{}'
            );
            CREATE TABLE scheduler_jobs (
                job_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                cron TEXT,
                target_url TEXT,
                config TEXT DEFAULT '{}',
                enabled INTEGER DEFAULT 1,
                one_time INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                last_run TEXT,
                next_run TEXT
            );
            CREATE TABLE scheduler_runs (
                run_id TEXT PRIMARY KEY,
                job_id TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT DEFAULT 'running',
                session_id TEXT,
                total_tests INTEGER DEFAULT 0,
                detection_rate REAL,
                bypass_rate REAL,
                config TEXT DEFAULT '{}',
                error TEXT
            );
            CREATE TABLE iocs (
                id TEXT PRIMARY KEY,
                type TEXT,
                threat_type TEXT,
                severity TEXT,
                ml_score REAL,
                detection_method TEXT,
                first_seen TEXT,
                last_seen TEXT,
                sighting_count INTEGER DEFAULT 1,
                payload_hash TEXT UNIQUE,
                source TEXT,
                mitre_techniques TEXT DEFAULT '[]',
                owasp_categories TEXT DEFAULT '[]',
                extra TEXT DEFAULT '{}'
            );
        """)

        # Insert test data
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
            ("old-sess-1", "2026-01-01", "2026-01-01", 2, "{}"),
        )
        conn.execute(
            """INSERT INTO results (session_id, scenario_id, category, result,
               confidence, execution_time_ms, bypass_indicators, safe_indicators, extra)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("old-sess-1", "ATK-001", "injection", "detected", 0.95, 150, "[]", "[]", "{}"),
        )
        conn.execute(
            """INSERT INTO results (session_id, scenario_id, category, result,
               confidence, execution_time_ms, bypass_indicators, safe_indicators, extra)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("old-sess-1", "ATK-002", "jailbreak", "bypass", 0.4, 300, "[]", "[]", "{}"),
        )
        conn.execute(
            "INSERT INTO scheduler_jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("j1", "Daily", "0 0 * * *", "http://localhost", "{}", 1, 0, "2026-01-01", None, None),
        )
        conn.execute(
            """INSERT INTO iocs (id, type, severity, payload_hash, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("ioc-old-1", "injection", "high", "old_hash_1", "2026-01-01", "2026-01-01"),
        )
        conn.commit()
        conn.close()

    def test_migrate_redteam_from_old_db(self, tmp_path):
        from migrate_to_unified_db import migrate_redteam_from_sqlite

        old_db = os.path.join(tmp_path, "old.db")
        self._create_old_db(old_db)

        target_db = os.path.join(tmp_path, "unified.db")
        backend = SQLiteBackend(target_db)
        counts = migrate_redteam_from_sqlite(old_db, backend)

        assert counts["redteam_sessions"] == 1
        assert counts["redteam_results"] == 2
        assert counts["scheduler_jobs"] == 1
        assert counts["iocs"] == 1

        # Verify data in unified DB
        sess = backend.get_redteam_session("old-sess-1")
        assert sess is not None
        assert len(sess["results"]) == 2

        jobs = backend.list_jobs()
        assert len(jobs) == 1
        assert jobs[0]["name"] == "Daily"

        ti = backend.query_threat_iocs()
        assert len(ti) == 1
        assert ti[0]["severity"] == "high"

        backend.close()

    def test_migrate_missing_source_db(self, tmp_path):
        from migrate_to_unified_db import migrate_redteam_from_sqlite

        target_db = os.path.join(tmp_path, "unified.db")
        backend = SQLiteBackend(target_db)
        counts = migrate_redteam_from_sqlite("/nonexistent/db.db", backend)

        assert counts["redteam_sessions"] == 0
        backend.close()


class TestMigrationFromShieldDB:
    """Test migration of shield.db data."""

    def _create_shield_db(self, db_path):
        """Create a standalone shield.db with test data."""
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE shield_sessions (
                session_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE shield_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                session_id TEXT,
                verdict TEXT,
                detection_method TEXT,
                ml_score REAL,
                user_input TEXT,
                data TEXT DEFAULT '{}'
            );
            CREATE TABLE shield_iocs (
                payload_hash TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                sighting_count INTEGER DEFAULT 1
            );
        """)

        import json
        conn.execute(
            "INSERT INTO shield_sessions VALUES (?, ?, ?, ?)",
            ("shield-s1", json.dumps({"threat_count": 3}), "2026-01-01", "2026-01-01"),
        )
        det_data = json.dumps({"verdict": "MALICIOUS", "session_id": "shield-s1", "ml_score": 0.9})
        conn.execute(
            "INSERT INTO shield_detections (timestamp, session_id, verdict, data) VALUES (?, ?, ?, ?)",
            ("2026-01-01", "shield-s1", "MALICIOUS", det_data),
        )
        ioc_data = json.dumps({"payload_hash": "shield_ioc_1", "severity": "critical"})
        conn.execute(
            "INSERT INTO shield_iocs VALUES (?, ?, ?, ?, ?)",
            ("shield_ioc_1", ioc_data, "2026-01-01", "2026-01-01", 1),
        )
        conn.commit()
        conn.close()

    def test_migrate_shield_db(self, tmp_path):
        from migrate_to_unified_db import migrate_shield_db

        shield_db = os.path.join(tmp_path, "shield.db")
        self._create_shield_db(shield_db)

        target_db = os.path.join(tmp_path, "unified.db")
        backend = SQLiteBackend(target_db)
        counts = migrate_shield_db(shield_db, backend)

        assert counts["shield_sessions"] == 1
        assert counts["shield_detections"] == 1
        assert counts["shield_iocs"] == 1

        # Verify data
        sess = backend.load_session("shield-s1")
        assert sess is not None
        assert sess["threat_count"] == 3

        dets = backend.query_detections(verdict="MALICIOUS")
        assert len(dets) == 1

        iocs = backend.query_iocs()
        assert len(iocs) == 1

        backend.close()
