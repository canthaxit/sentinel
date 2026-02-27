"""
Threat Intelligence API Endpoints
Flask Blueprint with all threat intel routes.
"""

import json
import uuid
import functools
import hmac
import os
import threading
from datetime import datetime
from pathlib import Path

from flask import Blueprint, request, jsonify, render_template_string, Response

from .config import (
    THREAT_INTEL_ENABLED, ATTACK_CATEGORIES,
    REPORT_DIR, STIX_BUNDLE_DIR,
)
from .core import IOC
from .storage import ThreatIntelDB
from .ioc_extractor import IOCExtractor
from .stix_exporter import STIXExporter
from .mitre_mapper import MITREMapper
from .feed_manager import FeedManager
from .dashboard_views import THREAT_INTEL_DASHBOARD_HTML

threat_intel_bp = Blueprint("threat_intel", __name__)

# Lazy-init singletons (thread-safe)
_db = None
_extractor = None
_exporter = None
_mapper = None
_feed_manager = None
_init_lock = threading.Lock()


def _get_db():
    global _db
    if _db is None:
        with _init_lock:
            if _db is None:
                _db = ThreatIntelDB()
    return _db


def _get_extractor():
    global _extractor
    if _extractor is None:
        with _init_lock:
            if _extractor is None:
                _extractor = IOCExtractor()
    return _extractor


def _get_exporter():
    global _exporter
    if _exporter is None:
        with _init_lock:
            if _exporter is None:
                _exporter = STIXExporter()
    return _exporter


def _get_mapper():
    global _mapper
    if _mapper is None:
        with _init_lock:
            if _mapper is None:
                _mapper = MITREMapper()
    return _mapper


def _get_feed_manager():
    global _feed_manager
    if _feed_manager is None:
        with _init_lock:
            if _feed_manager is None:
                _feed_manager = FeedManager()
    return _feed_manager


def _require_api_key(f):
    """Reuse the same API key auth pattern from sentinel_app.py."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        api_key = os.getenv("SENTINEL_API_KEY", "")
        if not api_key:
            return f(*args, **kwargs)  # Auth disabled in dev mode
        key = request.headers.get("X-API-Key", "")
        if not key or not hmac.compare_digest(key.encode(), api_key.encode()):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# --- Dashboard ---

@threat_intel_bp.route("/dashboard")
@_require_api_key
def dashboard():
    """Threat Intelligence Dashboard."""
    if not THREAT_INTEL_ENABLED:
        return "<h1>Threat Intelligence disabled</h1>", 503

    db = _get_db()
    mapper = _get_mapper()
    exporter = _get_exporter()
    feed_manager = _get_feed_manager()

    stats = db.get_statistics()
    recent_iocs = db.query_iocs(limit=100)
    mitre_coverage = mapper.get_coverage()
    feeds = feed_manager.get_feed_status()

    # Get escalated sessions as "campaigns"
    # Import SESSION_STATE from main app if available
    campaigns = []
    try:
        import sys
        main_module = sys.modules.get("sentinel_app") or sys.modules.get("__main__")
        if main_module and hasattr(main_module, "SESSION_STATE"):
            session_state = main_module.SESSION_STATE
            campaigns = [
                {"session_id": sid, **{k: v for k, v in s.items() if k != "interactions"}}
                for sid, s in session_state.items()
                if s.get("escalated")
            ]
    except Exception:
        pass

    nav_html = ""

    return render_template_string(
        THREAT_INTEL_DASHBOARD_HTML,
        stats=stats,
        recent_iocs=recent_iocs,
        mitre_coverage=mitre_coverage,
        feeds=feeds,
        campaigns=campaigns,
        categories=ATTACK_CATEGORIES,
        stix_available=exporter.available,
        version="3.4.1",
        nav_html=nav_html,
    )


# --- IOC Endpoints ---

@threat_intel_bp.route("/api/iocs")
@_require_api_key
def list_iocs():
    """List IOCs with optional filters."""
    db = _get_db()

    ioc_type = request.args.get("type")
    severity = request.args.get("severity")
    threat_type = request.args.get("threat_type")
    source = request.args.get("source")
    since = request.args.get("since")
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
        offset = max(int(request.args.get("offset", 0)), 0)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid limit or offset parameter"}), 400

    iocs = db.query_iocs(
        ioc_type=ioc_type,
        severity=severity,
        threat_type=threat_type,
        source=source,
        since=since,
        limit=limit,
        offset=offset,
    )

    return jsonify({
        "iocs": [ioc.to_dict() for ioc in iocs],
        "count": len(iocs),
        "limit": limit,
        "offset": offset,
    })


@threat_intel_bp.route("/api/iocs/<ioc_id>")
@_require_api_key
def get_ioc(ioc_id):
    """Get a single IOC by ID."""
    db = _get_db()
    ioc = db.get_ioc(ioc_id)
    if not ioc:
        return jsonify({"error": "IOC not found"}), 404

    # Enrich with feed data
    feed_manager = _get_feed_manager()
    enrichment = feed_manager.correlate_ioc(ioc)

    return jsonify({
        "ioc": ioc.to_dict(),
        "enrichment": enrichment,
    })


@threat_intel_bp.route("/api/iocs/extract", methods=["GET", "POST"])
@_require_api_key
def extract_iocs():
    """Trigger IOC extraction from log file."""
    extractor = _get_extractor()
    db = _get_db()

    log_file = str(Path(__file__).parent.parent / "sentinel_logs.json")
    since = request.args.get("since")

    iocs = extractor.extract_from_log_file(log_file, since=since)

    added = 0
    updated = 0
    for ioc in iocs:
        existing = db.get_ioc_by_hash(ioc.payload_hash)
        db.add_ioc(ioc)
        if existing:
            updated += 1
        else:
            added += 1

    return jsonify({
        "extracted": len(iocs),
        "added": added,
        "updated": updated,
        "total_in_db": db.get_statistics()["total_iocs"],
    })


# --- STIX Endpoints ---

@threat_intel_bp.route("/api/stix/bundle")
@_require_api_key
def stix_bundle():
    """Generate and return a STIX 2.1 bundle."""
    db = _get_db()
    exporter = _get_exporter()
    mapper = _get_mapper()

    since = request.args.get("since")
    iocs = db.get_all_iocs()

    # Get scenarios from mapper
    scenarios = []
    all_scenarios = mapper.get_all_scenarios()
    for sid, meta in all_scenarios.items():
        scenarios.append({
            "id": sid,
            "name": meta.get("name", ""),
            "category": meta.get("category", ""),
            "description": meta.get("name", ""),
            "success_rate": meta.get("success_rate", ""),
            "severity": meta.get("severity", "medium"),
            "mitre_mapping": mapper.get_techniques_for_scenario(sid),
            "owasp_mapping": mapper.get_owasp_for_scenario(sid),
        })

    # Get escalated sessions
    sessions = []
    try:
        import sys
        main_module = sys.modules.get("sentinel_app") or sys.modules.get("__main__")
        if main_module and hasattr(main_module, "SESSION_STATE"):
            for sid, s in main_module.SESSION_STATE.items():
                if s.get("escalated"):
                    sessions.append({"session_id": sid, **s})
    except Exception:
        pass

    bundle = exporter.generate_bundle(
        iocs=iocs,
        sessions=sessions,
        scenarios=scenarios,
        since=since,
    )

    return jsonify(bundle)


@threat_intel_bp.route("/api/stix/indicators")
@_require_api_key
def stix_indicators():
    """STIX Indicators only."""
    db = _get_db()
    exporter = _get_exporter()

    since = request.args.get("since")
    iocs = db.get_all_iocs()
    indicators = exporter.generate_indicators_only(iocs, since=since)

    return jsonify({"indicators": indicators, "count": len(indicators)})


@threat_intel_bp.route("/api/stix/attack-patterns")
@_require_api_key
def stix_attack_patterns():
    """STIX Attack Patterns from scenarios."""
    mapper = _get_mapper()
    exporter = _get_exporter()

    scenarios = []
    all_scenarios = mapper.get_all_scenarios()
    for sid, meta in all_scenarios.items():
        scenarios.append({
            "id": sid,
            "name": meta.get("name", ""),
            "category": meta.get("category", ""),
            "description": meta.get("name", ""),
            "success_rate": meta.get("success_rate", ""),
            "severity": meta.get("severity", "medium"),
            "mitre_mapping": mapper.get_techniques_for_scenario(sid),
            "owasp_mapping": mapper.get_owasp_for_scenario(sid),
        })

    patterns = exporter.generate_attack_patterns(scenarios)
    return jsonify({"attack_patterns": patterns, "count": len(patterns)})


@threat_intel_bp.route("/api/stix/import", methods=["POST"])
@_require_api_key
def stix_import():
    """Import an external STIX bundle."""
    # Limit request size (10MB max)
    if request.content_length and request.content_length > 10 * 1024 * 1024:
        return jsonify({"error": "Request too large (10MB max)"}), 413

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    # Validate basic STIX structure
    if not isinstance(data.get("objects"), list):
        return jsonify({"error": "Invalid STIX bundle: missing objects array"}), 400
    if len(data.get("objects", [])) > 10000:
        return jsonify({"error": "Too many objects (10000 max)"}), 400

    feed_manager = _get_feed_manager()
    result = feed_manager.import_stix_bundle(data)

    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)


# --- Feed Endpoints ---

@threat_intel_bp.route("/api/feeds")
@_require_api_key
def feed_status():
    """Get status of all feeds."""
    feed_manager = _get_feed_manager()
    return jsonify({"feeds": feed_manager.get_feed_status()})


@threat_intel_bp.route("/api/feeds/<name>/refresh", methods=["POST"])
@_require_api_key
def refresh_feed(name):
    """Trigger a feed refresh."""
    feed_manager = _get_feed_manager()
    result = feed_manager.refresh_feed(name)
    if result is None:
        return jsonify({"error": f"Feed '{name}' not found"}), 404
    return jsonify({"feed": name, "result": result})


# --- MITRE Coverage ---

@threat_intel_bp.route("/api/mitre/coverage")
@_require_api_key
def mitre_coverage():
    """MITRE ATT&CK/ATLAS coverage map."""
    mapper = _get_mapper()
    coverage = mapper.get_coverage()
    return jsonify(coverage)


# --- Statistics ---

@threat_intel_bp.route("/api/stats")
@_require_api_key
def stats():
    """Overall threat intel statistics."""
    db = _get_db()
    mapper = _get_mapper()
    feed_manager = _get_feed_manager()

    ioc_stats = db.get_statistics()
    mitre = mapper.get_coverage()
    feeds = feed_manager.get_feed_status()

    return jsonify({
        "iocs": ioc_stats,
        "mitre_coverage_percent": mitre["coverage_percent"],
        "total_scenarios": len(mapper.get_all_scenarios()),
        "feeds": feeds,
    })


# --- Export ---

@threat_intel_bp.route("/api/export/csv")
@_require_api_key
def export_csv():
    """Export IOCs as CSV."""
    db = _get_db()
    csv_data = db.export_csv()
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinel_iocs.csv"},
    )


# --- Reports ---

@threat_intel_bp.route("/api/reports/generate", methods=["POST"])
@_require_api_key
def generate_report():
    """Generate a threat intel report."""
    db = _get_db()
    mapper = _get_mapper()
    exporter = _get_exporter()

    stats = db.get_statistics()
    mitre = mapper.get_coverage()
    iocs = db.get_all_iocs()

    report_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = {
        "id": report_id,
        "generated_at": timestamp,
        "title": f"Sentinel Threat Intelligence Report - {timestamp[:10]}",
        "summary": {
            "total_iocs": stats["total_iocs"],
            "total_sightings": stats["total_sightings"],
            "unique_payloads": stats["unique_payload_hashes"],
            "mitre_coverage": f"{mitre['coverage_percent']:.0f}%",
        },
        "severity_breakdown": stats.get("by_severity", {}),
        "threat_type_breakdown": stats.get("by_threat_type", {}),
        "detection_method_breakdown": stats.get("by_detection_method", {}),
        "mitre_coverage": mitre,
        "top_iocs": [ioc.to_dict() for ioc in iocs[:20]],
    }

    # Save report (with limit enforcement)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # Enforce max 50 reports - delete oldest if exceeded
    existing = sorted(REPORT_DIR.glob("report_*.json"), key=lambda p: p.stat().st_mtime)
    while len(existing) >= 50:
        existing[0].unlink()
        existing.pop(0)

    report_file = REPORT_DIR / f"report_{report_id}.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    return jsonify({"report_id": report_id, "url": f"/threat-intel/api/reports/{report_id}"})


@threat_intel_bp.route("/api/reports/<report_id>")
@_require_api_key
def get_report(report_id):
    """Download a generated report."""
    # Validate report_id format (alphanumeric only)
    if not report_id.replace("-", "").isalnum():
        return jsonify({"error": "Invalid report ID"}), 400

    report_file = REPORT_DIR / f"report_{report_id}.json"
    if not report_file.exists():
        return jsonify({"error": "Report not found"}), 404

    with open(report_file, "r", encoding="utf-8") as f:
        report = json.load(f)

    return jsonify(report)


@threat_intel_bp.route("/api/reports/pdf", methods=["POST", "GET"])
@_require_api_key
def export_pdf():
    """Generate a PDF threat intelligence report."""
    try:
        from report_generator import ReportGenerator
    except ImportError:
        return jsonify({"error": "PDF generation not available (pip install fpdf2)"}), 503

    db = _get_db()
    mapper = _get_mapper()

    stats = db.get_statistics()
    iocs = db.query_iocs(limit=200)
    mitre_coverage = mapper.get_coverage()

    gen = ReportGenerator()
    pdf_bytes = gen.threat_intel_report(
        stats=stats,
        iocs=iocs,
        mitre_coverage=mitre_coverage,
    )

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="sentinel_threat_intel.pdf"',
        },
    )
