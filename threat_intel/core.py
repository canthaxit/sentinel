"""
Threat Intelligence Core Data Models
IOC, AIIndicatorType, ThreatIntelEntry dataclasses.
"""

import uuid
import hashlib
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
from datetime import datetime


class AIIndicatorType(str, Enum):
    """Types of AI-specific indicators of compromise."""
    PROMPT_PAYLOAD = "prompt_payload"
    ATTACK_SIGNATURE = "attack_signature"
    SESSION_BEHAVIOR = "session_behavior"
    SOURCE_IP = "source_ip"
    PAYLOAD_HASH = "payload_hash"
    ATTACK_TECHNIQUE = "attack_technique"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IOC:
    """Indicator of Compromise extracted from honeypot data."""
    id: str = field(default_factory=lambda: f"ioc--{uuid.uuid4()}")
    type: str = AIIndicatorType.PROMPT_PAYLOAD.value
    value: str = ""
    threat_type: str = "unknown"
    severity: str = Severity.MEDIUM.value
    ml_score: Optional[float] = None
    detection_method: str = "unknown"
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    sighting_count: int = 1
    payload_hash: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    owasp_mappings: List[str] = field(default_factory=list)
    source: str = "log"  # log, session, redteam
    session_id: Optional[str] = None
    attack_category: Optional[str] = None
    scenario_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.value and not self.payload_hash:
            self.payload_hash = hashlib.sha256(
                self.value.strip().lower().encode("utf-8")
            ).hexdigest()

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "IOC":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ThreatIntelEntry:
    """Wraps IOC with enrichment data from external feeds."""
    ioc: IOC = field(default_factory=IOC)
    feed_matches: List[Dict] = field(default_factory=list)
    enrichment_data: Dict = field(default_factory=dict)
    confidence_boost: float = 0.0
    last_enriched: Optional[str] = None

    def to_dict(self) -> Dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: Dict) -> "ThreatIntelEntry":
        ioc_data = data.get("ioc", {})
        ioc = IOC.from_dict(ioc_data) if ioc_data else IOC()
        return cls(
            ioc=ioc,
            feed_matches=data.get("feed_matches", []),
            enrichment_data=data.get("enrichment_data", {}),
            confidence_boost=data.get("confidence_boost", 0.0),
            last_enriched=data.get("last_enriched"),
        )


def compute_payload_hash(payload: str) -> str:
    """Compute SHA-256 hash of normalized payload for deduplication."""
    return hashlib.sha256(payload.strip().lower().encode("utf-8")).hexdigest()
