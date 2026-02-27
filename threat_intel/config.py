"""
Threat Intelligence Configuration
Constants, paths, and environment variable configuration.

NOTE: Framework-level constants (MITRE_ATLAS_TECHNIQUES, OWASP_LLM_TOP10,
CWE_MAPPINGS, etc.) are now canonically defined in sentinel.frameworks
and re-exported here for backward compatibility.
"""

import os
from pathlib import Path

# Re-export canonical framework data from sentinel.frameworks
try:
    from sentinel.frameworks import (  # noqa: F401
        MITRE_ATLAS_TECHNIQUES as _MITRE,
        OWASP_LLM_TOP10 as _OWASP,
        CWE_MAPPINGS as _CWE,
    )
    _FRAMEWORKS_AVAILABLE = True
except ImportError:
    _FRAMEWORKS_AVAILABLE = False

# --- Feature toggle ---
THREAT_INTEL_ENABLED = os.getenv("THREAT_INTEL_ENABLED", "true").lower() == "true"

# --- Data directories ---
THREAT_INTEL_DATA_DIR = Path(os.getenv(
    "THREAT_INTEL_DATA_DIR",
    str(Path(__file__).parent.parent / "threat_intel_data")
))
IOC_STORAGE_DIR = THREAT_INTEL_DATA_DIR / "iocs"
STIX_BUNDLE_DIR = THREAT_INTEL_DATA_DIR / "stix_bundles"
FEED_CACHE_DIR = THREAT_INTEL_DATA_DIR / "feeds"
REPORT_DIR = THREAT_INTEL_DATA_DIR / "reports"

# --- Timing ---
BACKGROUND_SCAN_INTERVAL = 300  # 5 minutes
FEED_REFRESH_INTERVAL = 3600   # 1 hour
FEED_STALE_THRESHOLD = 86400   # 24 hours

# --- Limits ---
MAX_IOCS_PER_QUERY = 500
MAX_STIX_BUNDLE_SIZE = 10000  # max objects per bundle

# --- External feed API keys (optional) ---
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# --- STIX Identity for Sentinel ---
SENTINEL_IDENTITY_NAME = "Sentinel Platform"
SENTINEL_IDENTITY_ID = "identity--a1b2c3d4-0001-4000-8000-000000000001"

# --- MITRE ATLAS Technique Mappings ---
# Canonical source: sentinel.frameworks.MITRE_ATLAS_TECHNIQUES
if _FRAMEWORKS_AVAILABLE:
    MITRE_ATLAS_TECHNIQUES = _MITRE
else:
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

# --- OWASP LLM Top 10 (2025) Mappings ---
# Canonical source: sentinel.frameworks.OWASP_LLM_TOP10
if _FRAMEWORKS_AVAILABLE:
    OWASP_LLM_TOP10 = _OWASP
else:
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

# --- Attack Category Taxonomy ---
ATTACK_CATEGORIES = {
    "prompt_injection": {"label": "Prompt Injection", "severity": "high"},
    "jailbreak": {"label": "Jailbreak", "severity": "critical"},
    "information_extraction": {"label": "Information Extraction", "severity": "high"},
    "social_engineering": {"label": "Social Engineering", "severity": "medium"},
    "context_manipulation": {"label": "Context Manipulation", "severity": "medium"},
    "model_exploitation": {"label": "Model Exploitation", "severity": "high"},
    "resource_abuse": {"label": "Resource Abuse", "severity": "medium"},
    "tool_exploitation": {"label": "Tool/Plugin Exploitation", "severity": "critical"},
}
