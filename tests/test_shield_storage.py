"""
Tests for Shield storage backends (Memory and SQLite).
Run: python -m pytest tests/test_shield_storage.py -v
"""

import os
import tempfile

import pytest

from sentinel.storage import (
    MemoryBackend,
    SQLiteBackend,
    StorageBackend,
    create_backend,
)
from sentinel.session import SessionManager


# ============================================================
# MemoryBackend Tests
# ============================================================


class TestMemoryBackend:

    def test_save_and_load_session(self):
        b = MemoryBackend()
        b.save_session("s1", {"threat_count": 3, "escalated": True})
        s = b.load_session("s1")
        assert s["threat_count"] == 3
        assert s["escalated"] is True

    def test_load_missing_returns_none(self):
        b = MemoryBackend()
        assert b.load_session("missing") is None

    def test_delete_session(self):
        b = MemoryBackend()
        b.save_session("s1", {"x": 1})
        assert b.delete_session("s1") is True
        assert b.load_session("s1") is None
        assert b.delete_session("s1") is False

    def test_list_sessions(self):
        b = MemoryBackend()
        b.save_session("a", {"n": 1})
        b.save_session("b", {"n": 2})
        sessions = b.list_sessions()
        assert set(sessions.keys()) == {"a", "b"}

    def test_log_and_query_detections(self):
        b = MemoryBackend()
        b.log_detection({"verdict": "MALICIOUS", "session_id": "s1"})
        b.log_detection({"verdict": "SAFE", "session_id": "s1"})
        b.log_detection({"verdict": "MALICIOUS", "session_id": "s2"})

        all_events = b.query_detections()
        assert len(all_events) == 3

        mal = b.query_detections(verdict="MALICIOUS")
        assert len(mal) == 2

        s1 = b.query_detections(session_id="s1")
        assert len(s1) == 2

    def test_query_detections_limit(self):
        b = MemoryBackend()
        for i in range(20):
            b.log_detection({"verdict": "SAFE", "n": i})
        assert len(b.query_detections(limit=5)) == 5

    def test_save_and_query_iocs(self):
        b = MemoryBackend()
        b.save_ioc({"payload_hash": "abc123", "severity": "high"})
        iocs = b.query_iocs()
        assert len(iocs) == 1
        assert iocs[0]["severity"] == "high"

    def test_ioc_deduplication(self):
        b = MemoryBackend()
        b.save_ioc({"payload_hash": "abc", "severity": "high", "sighting_count": 1})
        b.save_ioc({"payload_hash": "abc", "severity": "high"})
        iocs = b.query_iocs()
        assert len(iocs) == 1
        assert iocs[0]["sighting_count"] == 2


# ============================================================
# SQLiteBackend Tests
# ============================================================


class TestSQLiteBackend:

    def _make_backend(self, tmp_path):
        db_path = os.path.join(tmp_path, "test.db")
        return SQLiteBackend(db_path), db_path

    def test_save_and_load_session(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_session("s1", {"threat_count": 5, "escalated": False})
        s = b.load_session("s1")
        assert s["threat_count"] == 5
        assert s["escalated"] is False

    def test_load_missing_returns_none(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        assert b.load_session("missing") is None

    def test_delete_session(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_session("s1", {"x": 1})
        assert b.delete_session("s1") is True
        assert b.load_session("s1") is None
        assert b.delete_session("s1") is False

    def test_list_sessions(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_session("a", {"n": 1})
        b.save_session("b", {"n": 2})
        sessions = b.list_sessions()
        assert set(sessions.keys()) == {"a", "b"}

    def test_session_update_overwrites(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_session("s1", {"v": 1})
        b.save_session("s1", {"v": 2})
        assert b.load_session("s1")["v"] == 2

    def test_persistence_across_restarts(self, tmp_path):
        """Create backend, write, close, reopen, read back."""
        db_path = os.path.join(tmp_path, "persist.db")
        b1 = SQLiteBackend(db_path)
        b1.save_session("s1", {"threat_count": 7})
        b1.log_detection({"verdict": "MALICIOUS", "session_id": "s1"})
        b1.save_ioc({"payload_hash": "hash1", "severity": "critical"})
        b1.close()

        b2 = SQLiteBackend(db_path)
        assert b2.load_session("s1")["threat_count"] == 7
        assert len(b2.query_detections(verdict="MALICIOUS")) == 1
        assert len(b2.query_iocs()) == 1
        b2.close()

    def test_log_and_query_detections(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.log_detection({"verdict": "MALICIOUS", "session_id": "s1", "ml_score": 0.95})
        b.log_detection({"verdict": "SAFE", "session_id": "s1"})

        all_events = b.query_detections()
        assert len(all_events) == 2

        mal = b.query_detections(verdict="MALICIOUS")
        assert len(mal) == 1
        assert mal[0]["ml_score"] == 0.95

    def test_save_and_query_iocs(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_ioc({"payload_hash": "h1", "severity": "high", "type": "injection"})
        iocs = b.query_iocs()
        assert len(iocs) == 1

    def test_ioc_deduplication(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_ioc({"payload_hash": "h1", "severity": "high"})
        b.save_ioc({"payload_hash": "h1", "severity": "high"})
        iocs = b.query_iocs()
        assert len(iocs) == 1


# ============================================================
# Red Team CRUD Tests
# ============================================================


class TestRedTeamStorage:
    """Tests for red team method group on both backends."""

    @pytest.fixture(params=["memory", "sqlite"])
    def backend(self, request, tmp_path):
        if request.param == "memory":
            return MemoryBackend()
        db_path = os.path.join(tmp_path, "rt.db")
        return SQLiteBackend(db_path)

    def test_save_and_get_redteam_result(self, backend):
        backend.save_redteam_result(
            {"scenario_id": "ATK-001", "category": "injection", "result": "detected",
             "confidence": 0.95, "execution_time_ms": 150},
            "sess-rt-1",
        )
        sess = backend.get_redteam_session("sess-rt-1")
        assert sess is not None
        assert sess["total_tests"] == 1
        assert len(sess["results"]) == 1
        assert sess["results"][0]["scenario_id"] == "ATK-001"

    def test_get_missing_redteam_session(self, backend):
        assert backend.get_redteam_session("nonexistent") is None

    def test_list_redteam_sessions(self, backend):
        backend.save_redteam_result({"result": "detected"}, "s1")
        backend.save_redteam_result({"result": "bypass"}, "s2")
        sessions = backend.list_redteam_sessions()
        assert len(sessions) == 2

    def test_query_redteam_results_by_category(self, backend):
        backend.save_redteam_result({"category": "injection", "result": "detected"}, "s1")
        backend.save_redteam_result({"category": "jailbreak", "result": "bypass"}, "s1")
        results = backend.query_redteam_results(session_id="s1", category="injection")
        assert len(results) == 1

    def test_query_redteam_results_by_result_type(self, backend):
        backend.save_redteam_result({"result": "detected"}, "s1")
        backend.save_redteam_result({"result": "bypass"}, "s1")
        backend.save_redteam_result({"result": "detected"}, "s1")
        results = backend.query_redteam_results(session_id="s1", result_type="detected")
        assert len(results) == 2

    def test_get_redteam_statistics(self, backend):
        for i in range(5):
            backend.save_redteam_result(
                {"result": "detected", "confidence": 0.9, "execution_time_ms": 100},
                "s1",
            )
        for i in range(3):
            backend.save_redteam_result(
                {"result": "bypass", "confidence": 0.4, "execution_time_ms": 200},
                "s1",
            )
        stats = backend.get_redteam_statistics("s1")
        assert stats["total_tests"] == 8
        assert stats["detection_rate"] == pytest.approx(62.5)
        assert stats["bypass_rate"] == pytest.approx(37.5)

    def test_get_redteam_statistics_empty(self, backend):
        stats = backend.get_redteam_statistics()
        assert "error" in stats

    def test_delete_redteam_session(self, backend):
        backend.save_redteam_result({"result": "detected"}, "s1")
        assert backend.delete_redteam_session("s1") is True
        assert backend.get_redteam_session("s1") is None
        assert backend.delete_redteam_session("s1") is False

    def test_cleanup_old_redteam_sessions(self, backend):
        for i in range(15):
            backend.save_redteam_result({"result": "detected"}, f"s{i:03d}")
        deleted = backend.cleanup_old_redteam_sessions(keep_latest=10)
        assert deleted == 5
        remaining = backend.list_redteam_sessions()
        assert len(remaining) == 10

    def test_multiple_results_per_session(self, backend):
        backend.save_redteam_result({"scenario_id": "A", "result": "detected"}, "s1")
        backend.save_redteam_result({"scenario_id": "B", "result": "bypass"}, "s1")
        backend.save_redteam_result({"scenario_id": "C", "result": "detected"}, "s1")
        sess = backend.get_redteam_session("s1")
        assert sess["total_tests"] == 3
        assert len(sess["results"]) == 3


# ============================================================
# Scheduler CRUD Tests
# ============================================================


class TestSchedulerStorage:

    @pytest.fixture(params=["memory", "sqlite"])
    def backend(self, request, tmp_path):
        if request.param == "memory":
            return MemoryBackend()
        return SQLiteBackend(os.path.join(tmp_path, "sched.db"))

    def test_save_and_get_job(self, backend):
        backend.save_job({
            "job_id": "j1", "name": "Daily Scan", "cron": "0 0 * * *",
            "target_url": "http://localhost:5000/api/chat",
            "created_at": "2026-01-01T00:00:00",
        })
        job = backend.get_job("j1")
        assert job is not None
        assert job["name"] == "Daily Scan"

    def test_get_missing_job(self, backend):
        assert backend.get_job("nonexistent") is None

    def test_list_jobs(self, backend):
        backend.save_job({"job_id": "j1", "name": "A", "created_at": "2026-01-01"})
        backend.save_job({"job_id": "j2", "name": "B", "created_at": "2026-01-02"})
        jobs = backend.list_jobs()
        assert len(jobs) == 2

    def test_delete_job(self, backend):
        backend.save_job({"job_id": "j1", "name": "A", "created_at": "2026-01-01"})
        assert backend.delete_job("j1") is True
        assert backend.get_job("j1") is None
        assert backend.delete_job("j1") is False

    def test_save_and_get_run_history(self, backend):
        backend.save_run({"run_id": "r1", "job_id": "j1", "status": "completed"})
        backend.save_run({"run_id": "r2", "job_id": "j1", "status": "failed"})
        backend.save_run({"run_id": "r3", "job_id": "j2", "status": "completed"})

        all_runs = backend.get_run_history()
        assert len(all_runs) == 3

        j1_runs = backend.get_run_history(job_id="j1")
        assert len(j1_runs) == 2

    def test_run_history_limit(self, backend):
        for i in range(10):
            backend.save_run({"run_id": f"r{i}", "job_id": "j1", "status": "ok"})
        assert len(backend.get_run_history(limit=3)) == 3


# ============================================================
# Threat Intel IOC Tests
# ============================================================


class TestThreatIntelStorage:

    @pytest.fixture(params=["memory", "sqlite"])
    def backend(self, request, tmp_path):
        if request.param == "memory":
            return MemoryBackend()
        return SQLiteBackend(os.path.join(tmp_path, "ti.db"))

    def test_save_and_query_threat_ioc(self, backend):
        backend.save_threat_ioc({
            "id": "ioc-1", "type": "prompt_injection", "threat_type": "injection",
            "severity": "high", "payload_hash": "ph1", "ml_score": 0.95,
            "first_seen": "2026-01-01", "last_seen": "2026-01-01",
            "source": "detection_pipeline",
        })
        iocs = backend.query_threat_iocs()
        assert len(iocs) == 1
        assert iocs[0]["severity"] == "high"

    def test_threat_ioc_deduplication(self, backend):
        backend.save_threat_ioc({"id": "ioc-1", "payload_hash": "ph1", "ml_score": 0.5,
                                 "first_seen": "2026-01-01", "last_seen": "2026-01-01"})
        backend.save_threat_ioc({"id": "ioc-1", "payload_hash": "ph1", "ml_score": 0.9,
                                 "first_seen": "2026-01-02", "last_seen": "2026-01-02"})
        iocs = backend.query_threat_iocs()
        assert len(iocs) == 1

    def test_query_threat_iocs_by_severity(self, backend):
        backend.save_threat_ioc({"id": "1", "payload_hash": "a", "severity": "high"})
        backend.save_threat_ioc({"id": "2", "payload_hash": "b", "severity": "low"})
        high = backend.query_threat_iocs(severity="high")
        assert len(high) == 1

    def test_get_threat_ioc_by_hash(self, backend):
        backend.save_threat_ioc({"id": "ioc-1", "payload_hash": "test_hash", "severity": "critical"})
        ioc = backend.get_threat_ioc_by_hash("test_hash")
        assert ioc is not None
        assert ioc["severity"] == "critical"

    def test_get_missing_threat_ioc_by_hash(self, backend):
        assert backend.get_threat_ioc_by_hash("nonexistent") is None

    def test_get_threat_statistics(self, backend):
        backend.save_threat_ioc({"id": "1", "payload_hash": "a", "type": "injection",
                                 "severity": "high", "threat_type": "pi"})
        backend.save_threat_ioc({"id": "2", "payload_hash": "b", "type": "jailbreak",
                                 "severity": "critical", "threat_type": "jb"})
        stats = backend.get_threat_statistics()
        assert stats["total_iocs"] == 2
        assert "by_type" in stats
        assert "by_severity" in stats


# ============================================================
# MCP Event Tests
# ============================================================


class TestMCPEventStorage:

    @pytest.fixture(params=["memory", "sqlite"])
    def backend(self, request, tmp_path):
        if request.param == "memory":
            return MemoryBackend()
        return SQLiteBackend(os.path.join(tmp_path, "mcp.db"))

    def test_log_and_query_mcp_events(self, backend):
        backend.log_mcp_event({
            "tool_name": "execute_code", "allowed": False,
            "blocked_reason": "policy: denied", "severity": "high",
            "session_id": "s1", "source_ip": "10.0.0.1",
        })
        backend.log_mcp_event({
            "tool_name": "read_file", "allowed": True,
            "severity": "none", "session_id": "s1",
        })

        all_events = backend.query_mcp_events()
        assert len(all_events) == 2

    def test_query_mcp_events_by_tool(self, backend):
        backend.log_mcp_event({"tool_name": "a", "allowed": True})
        backend.log_mcp_event({"tool_name": "b", "allowed": False})
        results = backend.query_mcp_events(tool_name="a")
        assert len(results) == 1

    def test_query_mcp_events_by_allowed(self, backend):
        backend.log_mcp_event({"tool_name": "a", "allowed": True})
        backend.log_mcp_event({"tool_name": "b", "allowed": False})
        blocked = backend.query_mcp_events(allowed=False)
        assert len(blocked) == 1

    def test_mcp_event_with_findings(self, backend):
        backend.log_mcp_event({
            "tool_name": "exec", "allowed": False,
            "findings": [{"category": "injection", "severity": "critical"}],
            "honey_triggered": True,
        })
        events = backend.query_mcp_events()
        assert len(events) == 1


# ============================================================
# Schema Version Tests
# ============================================================


class TestSchemaVersion:

    def test_sqlite_schema_version(self, tmp_path):
        b = SQLiteBackend(os.path.join(tmp_path, "ver.db"))
        from sentinel.storage import _CURRENT_SCHEMA_VERSION
        assert b.get_schema_version() == _CURRENT_SCHEMA_VERSION
        b.close()

    def test_memory_schema_version(self):
        b = MemoryBackend()
        assert b.get_schema_version() == 0

    def test_all_ten_tables_exist(self, tmp_path):
        """Verify the unified schema creates all expected tables."""
        import sqlite3
        db_path = os.path.join(tmp_path, "tables.db")
        b = SQLiteBackend(db_path)
        conn = sqlite3.connect(db_path)
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        b.close()
        conn.close()

        expected = {
            "shield_sessions", "shield_detections", "shield_iocs",
            "redteam_sessions", "redteam_results",
            "scheduler_jobs", "scheduler_runs",
            "threat_intel_iocs", "mcp_events", "schema_version",
        }
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"


# ============================================================
# Cross-Component Tests
# ============================================================


class TestCrossComponent:

    def test_all_data_in_single_db_file(self, tmp_path):
        """Verify that all components write to the same DB file."""
        db_path = os.path.join(tmp_path, "unified.db")
        b = SQLiteBackend(db_path)

        # Shield
        b.save_session("s1", {"threat_count": 1})
        b.log_detection({"verdict": "MALICIOUS", "session_id": "s1"})
        b.save_ioc({"payload_hash": "ioc1"})

        # Red team
        b.save_redteam_result({"result": "detected"}, "rt-1")

        # Scheduler
        b.save_job({"job_id": "j1", "name": "test", "created_at": "2026-01-01"})
        b.save_run({"run_id": "r1", "job_id": "j1"})

        # Threat intel
        b.save_threat_ioc({"id": "ti-1", "payload_hash": "tip1", "severity": "high"})

        # MCP
        b.log_mcp_event({"tool_name": "exec", "allowed": False})

        # Verify all data is accessible
        assert b.load_session("s1") is not None
        assert len(b.query_detections()) == 1
        assert len(b.query_iocs()) == 1
        assert b.get_redteam_session("rt-1") is not None
        assert b.get_job("j1") is not None
        assert len(b.get_run_history()) == 1
        assert len(b.query_threat_iocs()) == 1
        assert len(b.query_mcp_events()) == 1
        b.close()

    def test_data_survives_restart(self, tmp_path):
        """Write data, close, reopen, verify all data present."""
        db_path = os.path.join(tmp_path, "restart.db")

        b1 = SQLiteBackend(db_path)
        b1.save_session("s1", {"threat_count": 5})
        b1.save_redteam_result({"result": "bypass"}, "rt-1")
        b1.save_threat_ioc({"id": "ti-1", "payload_hash": "tp1"})
        b1.log_mcp_event({"tool_name": "test", "allowed": True})
        b1.close()

        b2 = SQLiteBackend(db_path)
        assert b2.load_session("s1")["threat_count"] == 5
        assert b2.get_redteam_session("rt-1") is not None
        assert len(b2.query_threat_iocs()) == 1
        assert len(b2.query_mcp_events()) == 1
        b2.close()

    def test_abc_default_noop_methods(self):
        """Verify StorageBackend ABC default no-ops don't crash."""
        b = MemoryBackend()
        # These should all work without error even if not implemented
        assert b.get_schema_version() == 0
        # All extended methods have real implementations in MemoryBackend
        # Verify they return expected defaults for empty state
        assert b.get_redteam_session("x") is None
        assert b.list_redteam_sessions() == []
        assert b.get_job("x") is None
        assert b.list_jobs() == []
        assert b.get_threat_ioc_by_hash("x") is None
        assert b.query_mcp_events() == []


# ============================================================
# SessionManager + Storage Integration
# ============================================================


class TestSessionManagerWithStorage:

    def test_session_persisted_to_memory_backend(self):
        b = MemoryBackend()
        mgr = SessionManager(storage_backend=b)
        mgr.update("sess-1", "hello", "SAFE", None, "127.0.0.1")
        stored = b.load_session("sess-1")
        assert stored is not None
        assert stored["safe_count"] >= 1

    def test_session_rehydrated_from_backend(self):
        b = MemoryBackend()
        b.save_session("sess-1", {
            "interactions": [],
            "cumulative_risk_score": 1.5,
            "threat_count": 2,
            "safe_count": 0,
            "escalated": False,
            "source_ip": "10.0.0.1",
            "instruction_override_attempts": 0,
            "context_switch_attempts": 0,
            "persona_override_attempts": 0,
            "hypothetical_framing_count": 0,
            "dan_jailbreak_attempts": 0,
            "logic_trap_attempts": 0,
            "rapid_escalation_detected": False,
            "attack_patterns": [],
            "sanitization_events": 0,
            "sanitization_types": [],
        })

        mgr = SessionManager(storage_backend=b)
        session = mgr.get("sess-1")
        assert session["threat_count"] == 2
        assert session["cumulative_risk_score"] == 1.5

    def test_no_backend_works_normally(self):
        mgr = SessionManager()
        mgr.update("sess-1", "hello", "SAFE", None, "127.0.0.1")
        session = mgr.get("sess-1")
        assert session["safe_count"] >= 1

    def test_sqlite_session_persistence(self, tmp_path):
        db_path = os.path.join(tmp_path, "session_test.db")
        b1 = SQLiteBackend(db_path)
        mgr1 = SessionManager(storage_backend=b1)
        mgr1.update("s1", "test input", "SAFE", None, "127.0.0.1")
        b1.close()

        b2 = SQLiteBackend(db_path)
        mgr2 = SessionManager(storage_backend=b2)
        session = mgr2.get("s1")
        assert session is not None
        assert session["safe_count"] >= 1
        b2.close()


# ============================================================
# create_backend Factory
# ============================================================


class TestCreateBackend:

    def test_default_is_memory(self):
        b = create_backend()
        assert isinstance(b, MemoryBackend)

    def test_explicit_memory(self):
        b = create_backend("memory")
        assert isinstance(b, MemoryBackend)

    def test_explicit_sqlite(self, tmp_path):
        db_path = os.path.join(tmp_path, "factory.db")
        b = create_backend("sqlite", db_path)
        assert isinstance(b, SQLiteBackend)
        b.close()

    def test_env_var_sqlite(self, tmp_path, monkeypatch):
        db_path = os.path.join(tmp_path, "env.db")
        monkeypatch.setenv("SHIELD_STORAGE_BACKEND", "sqlite")
        monkeypatch.setenv("SHIELD_STORAGE_PATH", db_path)
        b = create_backend()
        assert isinstance(b, SQLiteBackend)
        b.close()


# ============================================================
# Package exports
# ============================================================


class TestStorageExports:

    def test_imports_from_package(self):
        from sentinel import (
            StorageBackend,
            MemoryBackend,
            SQLiteBackend,
            create_backend,
        )
        assert StorageBackend is not None
        assert MemoryBackend is not None
        assert SQLiteBackend is not None
        assert callable(create_backend)
