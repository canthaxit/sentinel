"""
Sentinel - Compliance Framework Mappings
=================================================
Canonical location for all compliance/regulatory framework data.

Covers:
- CWE (Common Weakness Enumeration)
- OWASP LLM Top 10 (2025)
- OWASP Agentic AI Top 15 (2025)
- MITRE ATLAS
- NIST CSF 2.0
- CVSS Base Scores
- Detection-to-framework mapping tables
- OWASP COMPASS export utilities
"""

# ---------------------------------------------------------------------------
# CWE Mappings - attack category -> CWE IDs
# ---------------------------------------------------------------------------
CWE_MAPPINGS = {
    "prompt_injection": ["CWE-1427", "CWE-77"],
    "jailbreak": ["CWE-707", "CWE-693"],
    "information_extraction": ["CWE-200", "CWE-209"],
    "social_engineering": ["CWE-451"],
    "context_manipulation": ["CWE-74"],
    "model_exploitation": ["CWE-327"],
    "resource_abuse": ["CWE-400", "CWE-770"],
    "tool_exploitation": ["CWE-269", "CWE-284"],
    "compliance_testing": ["CWE-693"],
}

# ---------------------------------------------------------------------------
# OWASP LLM Top 10 (2025)
# ---------------------------------------------------------------------------
OWASP_LLM_TOP10 = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain Vulnerabilities",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

# ---------------------------------------------------------------------------
# OWASP Agentic AI Top 15 (2025)
# ---------------------------------------------------------------------------
OWASP_AGENTIC_TOP15 = {
    "AGENTIC-01": "Excessive Agency and Privilege Escalation",
    "AGENTIC-02": "Uncontrolled Tool and Function Execution",
    "AGENTIC-03": "Memory Poisoning and Context Manipulation",
    "AGENTIC-04": "Cascading Hallucination in Multi-Agent Chains",
    "AGENTIC-05": "Cross-Agent Data Leakage",
    "AGENTIC-06": "Malicious Agent Impersonation",
    "AGENTIC-07": "Indirect Prompt Injection via Retrieval",
    "AGENTIC-08": "Goal Misalignment and Reward Hacking",
    "AGENTIC-09": "Unsafe Action Execution Without Confirmation",
    "AGENTIC-10": "Lack of Agent Activity Monitoring",
    "AGENTIC-11": "Unrestricted Multi-Agent Delegation",
    "AGENTIC-12": "Insufficient Agent Authentication",
    "AGENTIC-13": "Resource Exhaustion through Agent Loops",
    "AGENTIC-14": "Sensitive Data Exposure in Agent Communication",
    "AGENTIC-15": "Failure to Isolate Agent Execution Environments",
}

# ---------------------------------------------------------------------------
# MITRE ATLAS Technique Mappings
# ---------------------------------------------------------------------------
MITRE_ATLAS_TECHNIQUES = {
    "T0002": {"name": "Social Engineering", "tactic": "initial-access"},
    "T0011": {"name": "Supply Chain Compromise", "tactic": "initial-access"},
    "T0030": {"name": "Prompt Injection", "tactic": "initial-access"},
    "T0041": {"name": "Poison Training Data", "tactic": "ml-attack-staging"},
    "T0042": {"name": "Manipulate Training Data", "tactic": "ml-attack-staging"},
    "T0050": {"name": "Abuse of Excessive Agency", "tactic": "ml-attack-staging"},
    "T0060": {"name": "Input Data Evasion", "tactic": "evasion"},
    "T0061": {"name": "LLM Jailbreak", "tactic": "evasion"},
    "T0070": {"name": "Inference API Access", "tactic": "collection"},
    "T0071": {"name": "System Prompt Extraction", "tactic": "collection"},
    "T0072": {"name": "Credential Extraction", "tactic": "collection"},
    "T0120": {"name": "Output Manipulation", "tactic": "impact"},
    "T0122": {"name": "Resource Exhaustion", "tactic": "impact"},
}

# ---------------------------------------------------------------------------
# NIST CSF 2.0 Subcategory Mapping
# Maps CSF subcategory IDs to Sentinel capabilities
# ---------------------------------------------------------------------------
NIST_CSF_MAPPING = {
    "ID.AM-08": {
        "name": "Asset Management - Systems and assets inventory",
        "sentinel": "Session tracking enumerates active LLM consumers",
    },
    "PR.DS-01": {
        "name": "Data Security - Data-at-rest protection",
        "sentinel": "Honey tokens protect stored secrets; sanitizer strips sensitive data",
    },
    "PR.DS-02": {
        "name": "Data Security - Data-in-transit protection",
        "sentinel": "Input/output scanners detect secrets, PII, credentials in transit",
    },
    "PR.AC-01": {
        "name": "Access Control - Identities and credentials managed",
        "sentinel": "API key authentication, rate limiting per IP",
    },
    "PR.IP-01": {
        "name": "Information Protection - Baseline configuration",
        "sentinel": "Shield config: ML thresholds, LLM provider, rate limits",
    },
    "DE.CM-01": {
        "name": "Continuous Monitoring - Network monitoring",
        "sentinel": "Real-time analysis of all LLM API traffic",
    },
    "DE.CM-06": {
        "name": "Continuous Monitoring - External service provider activity",
        "sentinel": "LLM provider response monitoring, output scanning",
    },
    "DE.AE-01": {
        "name": "Anomaly and Event Detection - Baseline established",
        "sentinel": "ML classifier trained on known attack/benign distributions",
    },
    "DE.AE-03": {
        "name": "Anomaly and Event Detection - Event data aggregated",
        "sentinel": "CEF logger aggregates detection events for SIEM",
    },
    "DE.DP-04": {
        "name": "Detection Processes - Event detection communicated",
        "sentinel": "Webhook notifications (Slack, Teams, PagerDuty)",
    },
    "RS.AN-01": {
        "name": "Analysis - Notifications investigated",
        "sentinel": "Threat intelligence IOC extraction and STIX 2.1 export",
    },
    "RS.MI-02": {
        "name": "Mitigation - Incidents contained",
        "sentinel": "Pre-filter blocking, session escalation, rate limiting",
    },
}

# ---------------------------------------------------------------------------
# CVSS Base Scores by severity tier
# ---------------------------------------------------------------------------
CVSS_BASE_SCORES = {
    "critical": 9.8,
    "high": 7.5,
    "medium": 5.3,
    "low": 2.0,
    "none": 0.0,
}

# ---------------------------------------------------------------------------
# Detection method -> OWASP LLM Top 10 mapping
# Maps pre-filter block reasons and ML threat types to framework IDs
# ---------------------------------------------------------------------------
DETECTION_TO_OWASP = {
    # Pre-filter block reasons
    "PRE_BLOCKED_CRITICAL_KEYWORDS": ["LLM01:2025"],
    "PRE_BLOCKED_INSTRUCTION_OVERRIDE": ["LLM01:2025"],
    "PRE_BLOCKED_PERSONA_OVERRIDE": ["LLM01:2025"],
    "PRE_BLOCKED_DAN_JAILBREAK": ["LLM01:2025"],
    "PRE_BLOCKED_HYPOTHETICAL": ["LLM01:2025"],
    "PRE_BLOCKED_LOGIC_TRAP": ["LLM01:2025"],
    "PRE_BLOCKED_PROMPT_EXTRACTION": ["LLM07:2025"],
    "PRE_BLOCKED_CONTEXT_SWITCH": ["LLM01:2025"],
    "PRE_BLOCKED_JAILBREAK": ["LLM01:2025"],
    "PRE_BLOCKED_FICTIONAL": ["LLM01:2025"],
    "PRE_BLOCKED_ROLEPLAY": ["LLM01:2025"],
    # Dynamic pre-filter block reasons (exact matches from pre_filter.py)
    "PRE_BLOCKED_HEAVY_SANITIZATION": ["LLM01:2025"],
    "PRE_BLOCKED_SESSION_ESCALATED": ["LLM01:2025"],
    "PRE_BLOCKED_MULTIPLE_PATTERNS": ["LLM01:2025"],
    "PRE_BLOCKED_REPEATED_SANITIZATION": ["LLM01:2025"],
    "PRE_BLOCKED_ROLEPLAY_JAILBREAK_ATK006": ["LLM01:2025"],
    # ML threat types
    "injection": ["LLM01:2025"],
    "jailbreak": ["LLM01:2025"],
    "extraction": ["LLM02:2025", "LLM07:2025"],
    "social_engineering": ["LLM01:2025"],
    "manipulation": ["LLM08:2025"],
    "exploitation": ["LLM05:2025"],
    "resource_abuse": ["LLM10:2025"],
    "tool_abuse": ["LLM06:2025"],
    # Sanitization detections
    "sanitization_rejection": ["LLM01:2025"],
    # Escalation
    "escalation": ["LLM01:2025"],
    # MCP tool call detections
    "mcp_command_injection": ["LLM01:2025", "LLM06:2025"],
    "mcp_path_traversal": ["LLM06:2025"],
    "mcp_ssrf": ["LLM06:2025"],
    "mcp_credential_leak": ["LLM02:2025"],
    "mcp_prompt_injection": ["LLM01:2025"],
    "mcp_encoding_attack": ["LLM01:2025"],
    "mcp_honey_triggered": ["LLM06:2025"],
    "mcp_policy_denied": ["LLM06:2025"],
}

# ---------------------------------------------------------------------------
# Detection method -> MITRE ATLAS technique mapping
# ---------------------------------------------------------------------------
DETECTION_TO_MITRE = {
    # Pre-filter block reasons
    "PRE_BLOCKED_CRITICAL_KEYWORDS": ["T0030"],
    "PRE_BLOCKED_INSTRUCTION_OVERRIDE": ["T0030"],
    "PRE_BLOCKED_PERSONA_OVERRIDE": ["T0030"],
    "PRE_BLOCKED_DAN_JAILBREAK": ["T0061"],
    "PRE_BLOCKED_HYPOTHETICAL": ["T0061"],
    "PRE_BLOCKED_LOGIC_TRAP": ["T0061"],
    "PRE_BLOCKED_PROMPT_EXTRACTION": ["T0071"],
    "PRE_BLOCKED_CONTEXT_SWITCH": ["T0030"],
    "PRE_BLOCKED_JAILBREAK": ["T0061"],
    "PRE_BLOCKED_FICTIONAL": ["T0061"],
    "PRE_BLOCKED_ROLEPLAY": ["T0061"],
    "PRE_BLOCKED_HEAVY_SANITIZATION": ["T0060"],
    "PRE_BLOCKED_SESSION_ESCALATED": ["T0030"],
    "PRE_BLOCKED_MULTIPLE_PATTERNS": ["T0030"],
    "PRE_BLOCKED_REPEATED_SANITIZATION": ["T0060"],
    "PRE_BLOCKED_ROLEPLAY_JAILBREAK_ATK006": ["T0061"],
    # ML threat types
    "injection": ["T0030"],
    "jailbreak": ["T0061"],
    "extraction": ["T0071"],
    "social_engineering": ["T0002"],
    "manipulation": ["T0042"],
    "exploitation": ["T0120"],
    "resource_abuse": ["T0122"],
    "tool_abuse": ["T0050"],
    # Sanitization
    "sanitization_rejection": ["T0060"],
    "escalation": ["T0030"],
    # MCP tool call detections
    "mcp_command_injection": ["T0030", "T0050"],
    "mcp_path_traversal": ["T0050", "T0070"],
    "mcp_ssrf": ["T0050", "T0070"],
    "mcp_credential_leak": ["T0072"],
    "mcp_prompt_injection": ["T0030"],
    "mcp_encoding_attack": ["T0060"],
    "mcp_honey_triggered": ["T0050"],
    "mcp_policy_denied": ["T0050"],
}

# ---------------------------------------------------------------------------
# Detection method -> CWE mapping
# ---------------------------------------------------------------------------
DETECTION_TO_CWE = {
    # Pre-filter block reasons
    "PRE_BLOCKED_CRITICAL_KEYWORDS": ["CWE-1427", "CWE-77"],
    "PRE_BLOCKED_INSTRUCTION_OVERRIDE": ["CWE-1427", "CWE-77"],
    "PRE_BLOCKED_PERSONA_OVERRIDE": ["CWE-1427"],
    "PRE_BLOCKED_DAN_JAILBREAK": ["CWE-707", "CWE-693"],
    "PRE_BLOCKED_HYPOTHETICAL": ["CWE-707"],
    "PRE_BLOCKED_LOGIC_TRAP": ["CWE-707"],
    "PRE_BLOCKED_PROMPT_EXTRACTION": ["CWE-200", "CWE-209"],
    "PRE_BLOCKED_CONTEXT_SWITCH": ["CWE-74"],
    "PRE_BLOCKED_JAILBREAK": ["CWE-707", "CWE-693"],
    "PRE_BLOCKED_FICTIONAL": ["CWE-707"],
    "PRE_BLOCKED_ROLEPLAY": ["CWE-707"],
    "PRE_BLOCKED_HEAVY_SANITIZATION": ["CWE-74"],
    "PRE_BLOCKED_SESSION_ESCALATED": ["CWE-1427"],
    "PRE_BLOCKED_MULTIPLE_PATTERNS": ["CWE-1427", "CWE-77"],
    "PRE_BLOCKED_REPEATED_SANITIZATION": ["CWE-74"],
    "PRE_BLOCKED_ROLEPLAY_JAILBREAK_ATK006": ["CWE-707", "CWE-693"],
    # ML threat types
    "injection": ["CWE-1427", "CWE-77"],
    "jailbreak": ["CWE-707", "CWE-693"],
    "extraction": ["CWE-200", "CWE-209"],
    "social_engineering": ["CWE-451"],
    "manipulation": ["CWE-74"],
    "exploitation": ["CWE-327"],
    "resource_abuse": ["CWE-400", "CWE-770"],
    "tool_abuse": ["CWE-269", "CWE-284"],
    # Sanitization
    "sanitization_rejection": ["CWE-74"],
    "escalation": ["CWE-1427"],
    # MCP tool call detections
    "mcp_command_injection": ["CWE-78", "CWE-77"],
    "mcp_path_traversal": ["CWE-22", "CWE-73"],
    "mcp_ssrf": ["CWE-918"],
    "mcp_credential_leak": ["CWE-200", "CWE-522"],
    "mcp_prompt_injection": ["CWE-1427", "CWE-77"],
    "mcp_encoding_attack": ["CWE-116", "CWE-838"],
    "mcp_honey_triggered": ["CWE-269", "CWE-284"],
    "mcp_policy_denied": ["CWE-269", "CWE-284"],
}

# ---------------------------------------------------------------------------
# Attack category -> NIST CSF subcategories
# ---------------------------------------------------------------------------
CATEGORY_TO_NIST_CSF = {
    "prompt_injection": ["DE.CM-01", "RS.MI-02", "DE.AE-01"],
    "jailbreak": ["DE.CM-01", "RS.MI-02", "DE.AE-01"],
    "information_extraction": ["PR.DS-01", "PR.DS-02", "DE.CM-01"],
    "social_engineering": ["DE.CM-01", "DE.AE-01"],
    "context_manipulation": ["DE.CM-01", "DE.AE-03"],
    "model_exploitation": ["DE.CM-06", "DE.AE-01"],
    "resource_abuse": ["RS.MI-02", "DE.CM-01"],
    "tool_exploitation": ["PR.AC-01", "DE.CM-06"],
    "compliance_testing": ["PR.IP-01", "DE.DP-04"],
}


# ---------------------------------------------------------------------------
# NIST SP 800-53 Rev 5 Control Mapping
# Maps 800-53 control IDs to Sentinel capabilities
# ---------------------------------------------------------------------------
NIST_800_53_MAPPING = {
    "SI-10": {
        "name": "Information Input Validation",
        "family": "System and Information Integrity",
        "sentinel": "Input sanitization (9 types), pre-filter pattern matching, ML classifier scoring",
    },
    "SI-4": {
        "name": "System Monitoring",
        "family": "System and Information Integrity",
        "sentinel": "Real-time analysis of all LLM traffic; drift monitor tracks distribution shifts",
    },
    "AU-3": {
        "name": "Content of Audit Records",
        "family": "Audit and Accountability",
        "sentinel": "CEF logger captures verdict, ML score, detection method, source IP, session ID",
    },
    "AU-6": {
        "name": "Audit Record Review, Analysis, and Reporting",
        "family": "Audit and Accountability",
        "sentinel": "Threat intelligence IOC extraction, STIX 2.1 export, SIEM integration",
    },
    "IR-4": {
        "name": "Incident Handling",
        "family": "Incident Response",
        "sentinel": "Webhook notifications (Slack, Teams, PagerDuty); session escalation triggers",
    },
    "IR-5": {
        "name": "Incident Monitoring",
        "family": "Incident Response",
        "sentinel": "Dashboard with real-time detection metrics; drift alerts; hourly statistics",
    },
    "AC-4": {
        "name": "Information Flow Enforcement",
        "family": "Access Control",
        "sentinel": "Pre-filter blocks malicious inputs; output scanner blocks credential/PII leakage",
    },
    "SC-7": {
        "name": "Boundary Protection",
        "family": "System and Communications Protection",
        "sentinel": "Shield acts as RASP boundary between user input and LLM; rate limiting per IP",
    },
    "CA-7": {
        "name": "Continuous Monitoring",
        "family": "Assessment, Authorization, and Monitoring",
        "sentinel": "ML drift monitor (KS test, PSI, OOV rate); hourly metric aggregation",
    },
}

# ---------------------------------------------------------------------------
# MCP detection -> OWASP Agentic AI mapping
# ---------------------------------------------------------------------------
DETECTION_TO_OWASP_AGENTIC = {
    "mcp_command_injection": ["AGENTIC-02", "AGENTIC-09"],
    "mcp_path_traversal": ["AGENTIC-02", "AGENTIC-15"],
    "mcp_ssrf": ["AGENTIC-02", "AGENTIC-09"],
    "mcp_credential_leak": ["AGENTIC-05", "AGENTIC-14"],
    "mcp_prompt_injection": ["AGENTIC-07", "AGENTIC-02"],
    "mcp_encoding_attack": ["AGENTIC-02"],
    "mcp_honey_triggered": ["AGENTIC-02", "AGENTIC-06"],
    "mcp_policy_denied": ["AGENTIC-01", "AGENTIC-02"],
    "mcp_rate_limited": ["AGENTIC-13"],
    "tool_abuse": ["AGENTIC-02", "AGENTIC-09"],
}

# Attack category -> NIST 800-53 controls
CATEGORY_TO_NIST_800_53 = {
    "prompt_injection": ["SI-10", "SI-4", "AC-4"],
    "jailbreak": ["SI-10", "SI-4", "AC-4"],
    "information_extraction": ["AC-4", "SC-7", "AU-3"],
    "social_engineering": ["SI-4", "IR-5"],
    "context_manipulation": ["SI-10", "SI-4", "AU-6"],
    "model_exploitation": ["SI-4", "CA-7"],
    "resource_abuse": ["SC-7", "IR-4"],
    "tool_exploitation": ["AC-4", "SI-10"],
    "compliance_testing": ["CA-7", "AU-6"],
}


# ---------------------------------------------------------------------------
# Threat mapping builder
# ---------------------------------------------------------------------------

def _match_pre_blocked(mapping, verdict):
    """Find the best matching PRE_BLOCKED key in a mapping dict.

    Pre-filter reasons are dynamic (e.g., PRE_BLOCKED_DANGEROUS_PATTERN_XXX).
    This finds the longest matching prefix key in the mapping.
    """
    # Exact match first
    if verdict in mapping:
        return mapping[verdict]
    # Try progressively shorter prefixes (e.g., PRE_BLOCKED_DANGEROUS_PATTERN -> PRE_BLOCKED_CRITICAL_KEYWORDS)
    # Map dynamic block reasons to canonical keys
    _CANONICAL = {
        "DANGEROUS_PATTERN": "CRITICAL_KEYWORDS",
        "DAN_JAILBREAK": "DAN_JAILBREAK",
        "JAILBREAK_WITH_RESTRICTED": "JAILBREAK",
        "ROLEPLAY_JAILBREAK": "ROLEPLAY",
        "HEAVY_SANITIZATION": "CRITICAL_KEYWORDS",
        "MULTIPLE_PATTERNS": "CRITICAL_KEYWORDS",
        "REPEATED_SANITIZATION": "CRITICAL_KEYWORDS",
        "SESSION_ESCALATED": "CRITICAL_KEYWORDS",
    }
    # Strip PRE_BLOCKED_ prefix to get the reason
    reason = verdict.replace("PRE_BLOCKED_", "", 1) if verdict.startswith("PRE_BLOCKED_") else verdict
    for prefix, canonical in _CANONICAL.items():
        if reason.startswith(prefix):
            key = f"PRE_BLOCKED_{canonical}"
            if key in mapping:
                return mapping[key]
    # Fallback: any PRE_BLOCKED maps to prompt injection
    return mapping.get("PRE_BLOCKED_CRITICAL_KEYWORDS", [])


def build_threat_mapping(detection_method, ml_result=None, llm_verdict=None,
                         category=None):
    """Build a threat mapping dict from detection results.

    Args:
        detection_method: How the threat was detected (pre_filter, ml_only, etc.)
        ml_result: ML classifier result dict (score, threat_type, severity, ...)
        llm_verdict: LLM judge verdict string (may start with PRE_BLOCKED_*)
        category: Attack category string if known

    Returns:
        Dict with owasp_llm, owasp_agentic, mitre_atlas, cwe, cvss_base,
        nist_csf keys.
    """
    owasp_ids = set()
    mitre_ids = set()
    cwe_ids = set()
    nist_ids = set()
    cvss = 0.0

    # Map from pre-filter block reason (handles dynamic PRE_BLOCKED_* strings)
    if llm_verdict and llm_verdict.startswith("PRE_BLOCKED"):
        owasp_ids.update(_match_pre_blocked(DETECTION_TO_OWASP, llm_verdict))
        mitre_ids.update(_match_pre_blocked(DETECTION_TO_MITRE, llm_verdict))
        cwe_ids.update(_match_pre_blocked(DETECTION_TO_CWE, llm_verdict))

    # Map from ML threat type
    if ml_result:
        threat_type = ml_result.get("threat_type", "")
        if threat_type:
            owasp_ids.update(DETECTION_TO_OWASP.get(threat_type, []))
            mitre_ids.update(DETECTION_TO_MITRE.get(threat_type, []))
            cwe_ids.update(DETECTION_TO_CWE.get(threat_type, []))

        severity = ml_result.get("severity", "none")
        cvss = max(cvss, CVSS_BASE_SCORES.get(severity, 0.0))

    # Map from detection method fallback
    if detection_method:
        owasp_ids.update(DETECTION_TO_OWASP.get(detection_method, []))
        mitre_ids.update(DETECTION_TO_MITRE.get(detection_method, []))
        cwe_ids.update(DETECTION_TO_CWE.get(detection_method, []))

    # Map from category to CWE, NIST CSF, and NIST 800-53
    nist_800_53_ids = set()
    if category:
        cwe_ids.update(CWE_MAPPINGS.get(category, []))
        nist_ids.update(CATEGORY_TO_NIST_CSF.get(category, []))
        nist_800_53_ids.update(CATEGORY_TO_NIST_800_53.get(category, []))

    # OWASP Agentic AI mappings (populated for MCP/tool detections)
    agentic_ids = set()
    if detection_method:
        agentic_ids.update(DETECTION_TO_OWASP_AGENTIC.get(detection_method, []))
    if category:
        agentic_ids.update(DETECTION_TO_OWASP_AGENTIC.get(category, []))

    return {
        "owasp_llm": sorted(owasp_ids),
        "owasp_agentic": sorted(agentic_ids),
        "mitre_atlas": sorted(mitre_ids),
        "cwe": sorted(cwe_ids),
        "cvss_base": cvss,
        "nist_csf": sorted(nist_ids),
        "nist_800_53": sorted(nist_800_53_ids),
    }


# ---------------------------------------------------------------------------
# OWASP COMPASS Export (Tab 3f format)
# ---------------------------------------------------------------------------

def _confidence_to_5pt(confidence):
    """Map 0.0-1.0 ML confidence to COMPASS 1-5 scale."""
    if confidence >= 0.9:
        return 5
    if confidence >= 0.7:
        return 4
    if confidence >= 0.5:
        return 3
    if confidence >= 0.3:
        return 2
    return 1


_REMEDIATION_BY_CATEGORY = {
    "prompt_injection": "Implement input validation, pre-filter rules, and LLM-based classification",
    "jailbreak": "Deploy jailbreak pattern detection and session-level escalation tracking",
    "information_extraction": "Block system prompt extraction, credential requests; apply output scanning",
    "social_engineering": "Detect authority/urgency patterns; enforce multi-turn tracking",
    "context_manipulation": "Monitor for context injection; validate embedding integrity",
    "model_exploitation": "Scan outputs for manipulation indicators; enforce output constraints",
    "resource_abuse": "Apply rate limiting and token budget enforcement",
    "tool_exploitation": "Restrict tool/function access; audit execution permissions",
    "compliance_testing": "Ensure policy adherence through automated evaluation harness",
}


def compass_export(results):
    """Convert Shield detection results to OWASP COMPASS Tab 3f format.

    Args:
        results: List of ShieldResult.to_dict() dicts (must include
                 threat_mapping key).

    Returns:
        List of COMPASS-formatted dicts.
    """
    rows = []
    for r in results:
        tm = r.get("threat_mapping", {})
        category = r.get("ml_threat_type") or "prompt_injection"
        ml_score = r.get("ml_score") or 0.0

        rows.append({
            "threat_name": r.get("detection_method", "unknown"),
            "owasp_id": ", ".join(tm.get("owasp_llm", [])),
            "impact_score": _confidence_to_5pt(ml_score),
            "likelihood_score": _confidence_to_5pt(ml_score),
            "cwe": ", ".join(tm.get("cwe", [])),
            "mitre_atlas": ", ".join(tm.get("mitre_atlas", [])),
            "cvss_base": tm.get("cvss_base", 0.0),
            "nist_csf": ", ".join(tm.get("nist_csf", [])),
            "remediation": _REMEDIATION_BY_CATEGORY.get(category, ""),
        })
    return rows
