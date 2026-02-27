"""
IOC Extraction from Honeypot Data
Extracts indicators from log files, session state, and red team results.
"""

import json
import hashlib
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

from .core import IOC, AIIndicatorType, Severity, compute_payload_hash
from .config import ATTACK_CATEGORIES


class IOCExtractor:
    """Extracts IOCs from various honeypot data sources."""

    # Threat type to severity mapping
    THREAT_SEVERITY = {
        "injection": Severity.HIGH.value,
        "jailbreak": Severity.CRITICAL.value,
        "credential_theft": Severity.CRITICAL.value,
        "system_probe": Severity.HIGH.value,
        "social_engineering": Severity.MEDIUM.value,
        "encoding_attack": Severity.HIGH.value,
        "logic_trap": Severity.HIGH.value,
        "unknown": Severity.MEDIUM.value,
        "none": Severity.LOW.value,
    }

    # Detection method to MITRE technique mapping
    DETECTION_TO_MITRE = {
        "pre_filter": ["T0030", "T0061"],
        "ml_only": ["T0030"],
        "llm_only": ["T0030"],
        "ensemble": ["T0030"],
        "escalation": ["T0030", "T0061"],
    }

    # Threat type to OWASP mapping
    THREAT_TO_OWASP = {
        "injection": ["LLM01:2025"],
        "jailbreak": ["LLM01:2025"],
        "credential_theft": ["LLM02:2025"],
        "system_probe": ["LLM07:2025"],
        "social_engineering": ["LLM01:2025"],
        "encoding_attack": ["LLM01:2025"],
        "logic_trap": ["LLM01:2025"],
    }

    def extract_from_log_entry(self, entry: Dict) -> Optional[IOC]:
        """
        Extract IOC from a single log file entry.

        Args:
            entry: Dict from sentinel_logs.json

        Returns:
            IOC or None if entry is not malicious
        """
        verdict = entry.get("verdict", "")
        if verdict not in ("MALICIOUS", "SAFE_REVIEW", "CRITICAL_COMPROMISE"):
            return None

        user_input = entry.get("user_input", "")
        if not user_input or user_input == "CLICKED_LINK":
            return None

        threat_type = entry.get("ml_threat_type", "unknown") or "unknown"
        ml_score = entry.get("ml_anomaly_score")
        detection_method = entry.get("detection_method", "unknown")
        session_id = entry.get("session_id")
        timestamp = entry.get("timestamp", datetime.now().isoformat())

        # Determine severity
        severity = self.THREAT_SEVERITY.get(threat_type, Severity.MEDIUM.value)
        if ml_score and ml_score >= 0.95:
            severity = Severity.CRITICAL.value
        elif ml_score and ml_score >= 0.85:
            severity = Severity.HIGH.value

        # Map to MITRE/OWASP
        mitre = self.DETECTION_TO_MITRE.get(detection_method, ["T0030"])
        owasp = self.THREAT_TO_OWASP.get(threat_type, ["LLM01:2025"])

        # Classify attack category from sanitizations
        sanitizations = entry.get("sanitizations_applied", [])
        attack_category = self._classify_attack_category(user_input, threat_type, sanitizations)

        ioc = IOC(
            type=AIIndicatorType.PROMPT_PAYLOAD.value,
            value=user_input,
            threat_type=threat_type,
            severity=severity,
            ml_score=ml_score,
            detection_method=detection_method,
            first_seen=timestamp,
            last_seen=timestamp,
            sighting_count=1,
            mitre_techniques=mitre,
            owasp_mappings=owasp,
            source="log",
            session_id=session_id,
            attack_category=attack_category,
            tags=sanitizations,
        )
        return ioc

    def extract_from_session(self, session_id: str, session_data: Dict) -> List[IOC]:
        """
        Extract IOCs from an escalated session.

        Args:
            session_id: Session identifier
            session_data: Session state dict

        Returns:
            List of IOCs extracted from session
        """
        iocs = []

        if not session_data.get("escalated"):
            return iocs

        # Session behavior IOC
        attack_patterns = session_data.get("attack_patterns", [])
        escalation_reason = session_data.get("escalation_reason", "")

        session_ioc = IOC(
            type=AIIndicatorType.SESSION_BEHAVIOR.value,
            value=f"Escalated session: {', '.join(attack_patterns)}",
            threat_type="multi_turn_attack",
            severity=Severity.HIGH.value,
            detection_method="session_tracking",
            source="session",
            session_id=session_id,
            attack_category="multi_turn",
            mitre_techniques=["T0030", "T0061"],
            owasp_mappings=["LLM01:2025"],
            tags=attack_patterns,
        )
        iocs.append(session_ioc)

        # Source IP IOC
        source_ip = session_data.get("source_ip")
        if source_ip and source_ip != "127.0.0.1":
            ip_ioc = IOC(
                type=AIIndicatorType.SOURCE_IP.value,
                value=source_ip,
                threat_type="attack_source",
                severity=Severity.MEDIUM.value,
                detection_method="session_tracking",
                source="session",
                session_id=session_id,
                tags=["escalated_session"],
            )
            iocs.append(ip_ioc)

        return iocs

    def extract_from_redteam_result(self, result: Dict) -> Optional[IOC]:
        """
        Extract IOC from a red team test result (bypass scenarios).

        Args:
            result: Dict from redteam_results

        Returns:
            IOC or None if result was detected (not a bypass)
        """
        if result.get("result") != "bypass":
            return None

        scenario_id = result.get("scenario_id", "")
        category = result.get("category", "unknown")
        prompt = result.get("prompt", "")
        confidence = result.get("confidence", 0.0)
        difficulty = result.get("difficulty", "medium")

        # Bypassed attacks are high severity (they worked)
        severity = Severity.CRITICAL.value if difficulty in ("hard", "advanced") else Severity.HIGH.value

        ioc = IOC(
            type=AIIndicatorType.ATTACK_TECHNIQUE.value,
            value=prompt,
            threat_type=category,
            severity=severity,
            ml_score=1.0 - confidence,  # Inverse: low confidence = high evasion
            detection_method="redteam",
            source="redteam",
            scenario_id=scenario_id,
            attack_category=category,
            tags=[f"bypass_{scenario_id}", difficulty],
        )
        return ioc

    def extract_from_log_file(self, log_file: str, since: Optional[str] = None) -> List[IOC]:
        """
        Batch extract IOCs from the full log file.

        Args:
            log_file: Path to sentinel_logs.json
            since: Only extract entries after this timestamp

        Returns:
            List of extracted IOCs
        """
        log_path = Path(log_file)
        if not log_path.exists():
            return []

        with open(log_path, "r", encoding="utf-8") as f:
            try:
                entries = json.load(f)
            except json.JSONDecodeError:
                return []

        iocs = []
        for entry in entries:
            if since and entry.get("timestamp", "") <= since:
                continue
            ioc = self.extract_from_log_entry(entry)
            if ioc:
                iocs.append(ioc)

        return iocs

    def _classify_attack_category(
        self, text: str, threat_type: str, sanitizations: List[str]
    ) -> str:
        """Classify the attack category based on input content."""
        text_lower = text.lower()

        if any(kw in text_lower for kw in ["jailbreak", "dan ", "unrestricted", "fictional universe"]):
            return "jailbreak"
        if any(kw in text_lower for kw in ["ignore", "disregard", "forget", "override"]):
            return "prompt_injection"
        if any(kw in text_lower for kw in ["password", "credential", "api key", "secret"]):
            return "information_extraction"
        if any(kw in text_lower for kw in ["it support", "security audit", "authorized"]):
            return "social_engineering"
        if any(kw in text_lower for kw in ["base64", "decode", "encode"]):
            return "prompt_injection"
        if any(kw in text_lower for kw in ["you must answer", "obligated", "biased"]):
            return "jailbreak"
        if sanitizations:
            return "prompt_injection"

        return threat_type if threat_type != "unknown" else "prompt_injection"
