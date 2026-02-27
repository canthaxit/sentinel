"""
Sentinel - Threat Intelligence Module
v1.0.0

Provides IOC extraction, STIX 2.1 export, external feed ingestion,
and a threat intel dashboard for the Sentinel Platform.

Usage:
    from threat_intel import threat_intel_hook, get_threat_intel_blueprint

    # Register blueprint
    app.register_blueprint(get_threat_intel_blueprint(), url_prefix='/threat-intel')

    # Call after MALICIOUS verdicts
    threat_intel_hook(user_input, verdict, ml_result, session_id, source_ip)
"""

__version__ = "1.0.0"

import threading
import time
from typing import Optional, Dict

from .config import THREAT_INTEL_ENABLED, BACKGROUND_SCAN_INTERVAL
from .core import IOC, AIIndicatorType, ThreatIntelEntry, compute_payload_hash
from .storage import ThreatIntelDB, ThreatIntelSQLiteAdapter
from .ioc_extractor import IOCExtractor
from .stix_exporter import STIXExporter
from .mitre_mapper import MITREMapper

# Module-level singletons (lazy init)
_db = None
_extractor = None
_exporter = None
_mapper = None
_db_lock = threading.Lock()

# Optional unified storage backend (set by sentinel_app.py)
_unified_storage_backend = None


def set_unified_storage(backend):
    """Set a unified StorageBackend for threat intel IOC storage.

    When set, the ThreatIntelSQLiteAdapter is used instead of the
    JSON-shard-based ThreatIntelDB.
    """
    global _unified_storage_backend, _db
    _unified_storage_backend = backend
    # Reset the singleton so next _get_db() picks up the adapter
    with _db_lock:
        _db = None


def _get_db():
    global _db
    if _db is None:
        with _db_lock:
            if _db is None:
                if _unified_storage_backend is not None:
                    _db = ThreatIntelSQLiteAdapter(_unified_storage_backend)
                else:
                    _db = ThreatIntelDB()
    return _db


def _get_extractor() -> IOCExtractor:
    global _extractor
    if _extractor is None:
        _extractor = IOCExtractor()
    return _extractor


def _get_exporter() -> STIXExporter:
    global _exporter
    if _exporter is None:
        _exporter = STIXExporter()
    return _exporter


def _get_mapper() -> MITREMapper:
    global _mapper
    if _mapper is None:
        _mapper = MITREMapper()
    return _mapper


def threat_intel_hook(
    user_input: str,
    verdict: str,
    ml_result: Optional[Dict],
    session_id: Optional[str],
    source_ip: str,
    detection_method: str = "unknown",
    sanitizations: Optional[list] = None,
):
    """
    Hook called from sentinel_app.py after MALICIOUS verdicts.
    Runs IOC extraction in a background daemon thread.
    Never blocks the detection pipeline.
    """
    if not THREAT_INTEL_ENABLED:
        return

    def _process():
        try:
            extractor = _get_extractor()
            db = _get_db()

            # Build a log-like entry for the extractor
            entry = {
                "user_input": user_input,
                "verdict": verdict,
                "ml_anomaly_score": ml_result.get("score") if ml_result else None,
                "ml_threat_type": ml_result.get("threat_type") if ml_result else None,
                "detection_method": detection_method,
                "session_id": session_id,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "sanitizations_applied": sanitizations or [],
            }

            ioc = extractor.extract_from_log_entry(entry)
            if ioc:
                db.add_ioc(ioc)
                print(f"[THREAT-INTEL] IOC extracted: {ioc.threat_type} "
                      f"(score={ioc.ml_score}, hash={ioc.payload_hash[:16]}...)")
        except Exception as e:
            print(f"[THREAT-INTEL] Hook error: {e}")

    t = threading.Thread(target=_process, daemon=True)
    t.start()


def _background_scan_worker():
    """
    Background worker that periodically scans log file for new entries
    and updates the IOC database. Runs every BACKGROUND_SCAN_INTERVAL seconds.
    """
    last_scan_count = 0

    while True:
        time.sleep(BACKGROUND_SCAN_INTERVAL)

        if not THREAT_INTEL_ENABLED:
            continue

        try:
            import json
            from pathlib import Path

            log_file = Path(__file__).parent.parent / "sentinel_logs.json"
            if not log_file.exists():
                continue

            with open(log_file, "r", encoding="utf-8") as f:
                try:
                    entries = json.load(f)
                except json.JSONDecodeError:
                    continue

            # Only process new entries
            if len(entries) <= last_scan_count:
                continue

            new_entries = entries[last_scan_count:]
            last_scan_count = len(entries)

            extractor = _get_extractor()
            db = _get_db()
            new_iocs = 0

            for entry in new_entries:
                ioc = extractor.extract_from_log_entry(entry)
                if ioc:
                    db.add_ioc(ioc)
                    new_iocs += 1

            if new_iocs > 0:
                print(f"[THREAT-INTEL] Background scan: {new_iocs} new IOCs from {len(new_entries)} entries")

        except Exception as e:
            print(f"[THREAT-INTEL] Background scan error: {e}")


# Start background worker only if enabled
if THREAT_INTEL_ENABLED:
    _bg_worker = threading.Thread(target=_background_scan_worker, daemon=True)
    _bg_worker.start()


def get_threat_intel_blueprint():
    """Get the Flask Blueprint for threat intel endpoints."""
    from .api import threat_intel_bp
    return threat_intel_bp
