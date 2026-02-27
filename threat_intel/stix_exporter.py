"""
STIX 2.1 Bundle Generation
Converts honeypot data into STIX 2.1 objects for threat intelligence sharing.
"""

import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Optional
from pathlib import Path

try:
    import stix2
    HAS_STIX2 = True
except ImportError:
    HAS_STIX2 = False

from .config import (
    SENTINEL_IDENTITY_NAME, SENTINEL_IDENTITY_ID,
    STIX_BUNDLE_DIR, MITRE_ATLAS_TECHNIQUES, OWASP_LLM_TOP10,
)
from .core import IOC


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse a timestamp string into a timezone-aware datetime for STIX."""
    if not ts_str:
        return datetime.now(timezone.utc)

    # Try ISO format first (2026-02-07T10:00:00.123456)
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    # If already has timezone info, try direct parse
    if ts_str.endswith("Z"):
        try:
            dt = datetime.strptime(ts_str.rstrip("Z"), "%Y-%m-%dT%H:%M:%S.%f")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    return datetime.now(timezone.utc)


class STIXExporter:
    """Generates STIX 2.1 bundles from Sentinel honeypot data."""

    def __init__(self):
        self._identity = None

    @property
    def available(self) -> bool:
        return HAS_STIX2

    def _get_identity(self):
        """Get or create the Sentinel platform Identity object."""
        if self._identity is None and HAS_STIX2:
            self._identity = stix2.Identity(
                id=SENTINEL_IDENTITY_ID,
                name=SENTINEL_IDENTITY_NAME,
                identity_class="system",
                description="AI Security Honeypot for detecting prompt injection attacks",
                sectors=["government-national", "defence"],
                created=datetime(2026, 2, 1, tzinfo=timezone.utc),
                modified=datetime(2026, 2, 1, tzinfo=timezone.utc),
                allow_custom=True,
            )
        return self._identity

    def ioc_to_indicator(self, ioc: IOC) -> Optional[object]:
        """Convert an IOC to a STIX 2.1 Indicator."""
        if not HAS_STIX2:
            return None

        # Build STIX pattern from payload hash
        pattern = f"[file:hashes.'SHA-256' = '{ioc.payload_hash}']"

        # Build external references
        external_refs = []
        for tid in ioc.mitre_techniques:
            tech_info = MITRE_ATLAS_TECHNIQUES.get(tid, {})
            external_refs.append(stix2.ExternalReference(
                source_name="mitre-atlas",
                external_id=tid,
                description=tech_info.get("name", tid),
            ))

        for oid in ioc.owasp_mappings:
            external_refs.append(stix2.ExternalReference(
                source_name="owasp-llm-top10",
                external_id=oid,
                description=OWASP_LLM_TOP10.get(oid, oid),
            ))

        indicator = stix2.Indicator(
            name=f"AI Attack Payload: {ioc.threat_type}",
            description=f"Prompt injection payload detected by {ioc.detection_method}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=_parse_timestamp(ioc.first_seen),
            created_by_ref=self._get_identity().id,
            labels=["malicious-activity", "ai-attack"],
            external_references=external_refs if external_refs else None,
            allow_custom=True,
            x_sentinel_ai_attack_category=ioc.attack_category or ioc.threat_type,
            x_sentinel_ml_anomaly_score=ioc.ml_score,
            x_sentinel_detection_method=ioc.detection_method,
            x_sentinel_prompt_payload=ioc.value[:500] if ioc.value else None,
            x_sentinel_sighting_count=ioc.sighting_count,
        )
        return indicator

    def attack_scenario_to_attack_pattern(self, scenario: Dict) -> Optional[object]:
        """Convert an attack scenario to a STIX 2.1 Attack Pattern."""
        if not HAS_STIX2:
            return None

        sid = scenario.get("id", "")
        name = scenario.get("name", "Unknown")
        category = scenario.get("category", "")
        description = scenario.get("description", "")
        success_rate = scenario.get("success_rate", "")
        severity = scenario.get("severity", "medium")

        external_refs = []
        for tid in scenario.get("mitre_mapping", []):
            tech_info = MITRE_ATLAS_TECHNIQUES.get(tid, {})
            external_refs.append(stix2.ExternalReference(
                source_name="mitre-atlas",
                external_id=tid,
                description=tech_info.get("name", tid),
            ))

        for oid in scenario.get("owasp_mapping", []):
            external_refs.append(stix2.ExternalReference(
                source_name="owasp-llm-top10",
                external_id=oid,
                description=OWASP_LLM_TOP10.get(oid, oid),
            ))

        # Deterministic ID based on scenario ID
        det_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_URL, f'sentinel/{sid}')}"

        attack_pattern = stix2.AttackPattern(
            id=det_id,
            name=f"{sid}: {name}",
            description=f"{description}\nCategory: {category}\nSuccess Rate: {success_rate}",
            created_by_ref=self._get_identity().id,
            external_references=external_refs if external_refs else None,
            labels=[category, severity],
            allow_custom=True,
            x_sentinel_ai_attack_category=category,
            x_sentinel_success_rate=success_rate,
            x_sentinel_owasp_llm_mapping=scenario.get("owasp_mapping", []),
            x_sentinel_mitre_atlas_mapping=scenario.get("mitre_mapping", []),
        )
        return attack_pattern

    def session_to_campaign(self, session_data: Dict) -> Optional[object]:
        """Convert an escalated session to a STIX 2.1 Campaign."""
        if not HAS_STIX2:
            return None

        session_id = session_data.get("session_id", str(uuid.uuid4()))
        attack_patterns = session_data.get("attack_patterns", [])
        threat_count = session_data.get("threat_count", 0)
        escalation_reason = session_data.get("escalation_reason", "")

        campaign = stix2.Campaign(
            name=f"AI Attack Session {session_id[:8]}",
            description=(
                f"Escalated attack session with {threat_count} threats. "
                f"Patterns: {', '.join(attack_patterns)}. "
                f"Escalation: {escalation_reason}"
            ),
            created_by_ref=self._get_identity().id,
            labels=["ai-attack-campaign"],
            allow_custom=True,
            x_sentinel_ai_attack_category="multi-turn",
            x_sentinel_detection_method="session_tracking",
        )
        return campaign

    def create_course_of_action(self, detection_method: str, description: str) -> Optional[object]:
        """Create a STIX Course of Action for a detection capability."""
        if not HAS_STIX2:
            return None

        det_id = f"course-of-action--{uuid.uuid5(uuid.NAMESPACE_URL, f'sentinel/coa/{detection_method}')}"

        coa = stix2.CourseOfAction(
            id=det_id,
            name=f"Sentinel: {detection_method}",
            description=description,
            created_by_ref=self._get_identity().id,
            labels=["ai-defense"],
            allow_custom=True,
        )
        return coa

    def generate_bundle(
        self,
        iocs: Optional[List[IOC]] = None,
        sessions: Optional[List[Dict]] = None,
        scenarios: Optional[List[Dict]] = None,
        since: Optional[str] = None,
    ) -> Dict:
        """
        Generate a STIX 2.1 bundle from honeypot data.

        Returns dict representation (JSON-serializable) even if stix2 is not installed.
        """
        if not HAS_STIX2:
            return self._generate_bundle_fallback(iocs, sessions, scenarios, since)

        objects = [self._get_identity()]

        # Convert IOCs to Indicators
        if iocs:
            for ioc in iocs:
                if since and ioc.first_seen < since:
                    continue
                indicator = self.ioc_to_indicator(ioc)
                if indicator:
                    objects.append(indicator)

        # Convert sessions to Campaigns
        if sessions:
            for session in sessions:
                if session.get("escalated"):
                    campaign = self.session_to_campaign(session)
                    if campaign:
                        objects.append(campaign)

        # Convert scenarios to Attack Patterns
        if scenarios:
            for scenario in scenarios:
                ap = self.attack_scenario_to_attack_pattern(scenario)
                if ap:
                    objects.append(ap)

        # Add detection capabilities as Course of Action
        detection_methods = [
            ("pre_filter", "Pre-LLM pattern matching blocks obvious attacks in <10ms"),
            ("ml_classifier", "TF-IDF + LogisticRegression ML model (F1=0.98, <2ms)"),
            ("llm_judge", "LLM-based security classifier for ambiguous cases"),
            ("session_tracking", "Multi-turn attack detection with session state"),
            ("input_sanitization", "9-type input sanitization pipeline"),
        ]
        for method, desc in detection_methods:
            coa = self.create_course_of_action(method, desc)
            if coa:
                objects.append(coa)

        bundle = stix2.Bundle(objects=objects, allow_custom=True)
        return json.loads(bundle.serialize())

    def _generate_bundle_fallback(self, iocs, sessions, scenarios, since) -> Dict:
        """Generate STIX-like JSON when stix2 library is not installed."""
        objects = [{
            "type": "identity",
            "spec_version": "2.1",
            "id": SENTINEL_IDENTITY_ID,
            "name": SENTINEL_IDENTITY_NAME,
            "identity_class": "system",
        }]

        if iocs:
            for ioc in iocs:
                if since and ioc.first_seen < since:
                    continue
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "name": f"AI Attack Payload: {ioc.threat_type}",
                    "pattern": f"[file:hashes.'SHA-256' = '{ioc.payload_hash}']",
                    "pattern_type": "stix",
                    "valid_from": ioc.first_seen,
                    "created_by_ref": SENTINEL_IDENTITY_ID,
                    "x_sentinel_ai_attack_category": ioc.attack_category or ioc.threat_type,
                    "x_sentinel_ml_anomaly_score": ioc.ml_score,
                    "x_sentinel_detection_method": ioc.detection_method,
                    "x_sentinel_prompt_payload": ioc.value[:500] if ioc.value else None,
                })

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

    def save_bundle(self, bundle: Dict, filename: Optional[str] = None) -> str:
        """Save a STIX bundle to disk."""
        STIX_BUNDLE_DIR.mkdir(parents=True, exist_ok=True)

        if filename is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"stix_bundle_{ts}.json"

        filepath = STIX_BUNDLE_DIR / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, default=str)

        return str(filepath)

    def generate_indicators_only(self, iocs: List[IOC], since: Optional[str] = None) -> List[Dict]:
        """Generate STIX Indicator objects only (no bundle wrapper)."""
        indicators = []
        for ioc in iocs:
            if since and ioc.first_seen < since:
                continue
            if HAS_STIX2:
                indicator = self.ioc_to_indicator(ioc)
                if indicator:
                    indicators.append(json.loads(indicator.serialize()))
            else:
                indicators.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "name": f"AI Attack Payload: {ioc.threat_type}",
                    "pattern": f"[file:hashes.'SHA-256' = '{ioc.payload_hash}']",
                    "pattern_type": "stix",
                    "valid_from": ioc.first_seen,
                    "x_sentinel_ai_attack_category": ioc.attack_category or ioc.threat_type,
                    "x_sentinel_ml_anomaly_score": ioc.ml_score,
                })
        return indicators

    def generate_attack_patterns(self, scenarios: List[Dict]) -> List[Dict]:
        """Generate STIX Attack Pattern objects from scenarios."""
        patterns = []
        for scenario in scenarios:
            if HAS_STIX2:
                ap = self.attack_scenario_to_attack_pattern(scenario)
                if ap:
                    patterns.append(json.loads(ap.serialize()))
            else:
                patterns.append({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_URL, 'sentinel/' + scenario.get('id', ''))}",
                    "name": f"{scenario.get('id', '')}: {scenario.get('name', '')}",
                    "description": scenario.get("description", ""),
                    "x_sentinel_ai_attack_category": scenario.get("category", ""),
                    "x_sentinel_success_rate": scenario.get("success_rate", ""),
                })
        return patterns
