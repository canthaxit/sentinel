"""
External Feed Ingestion and IOC Enrichment
Manages external threat intelligence feeds for IOC correlation.
"""

import json
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from .config import (
    FEED_CACHE_DIR, FEED_REFRESH_INTERVAL, FEED_STALE_THRESHOLD,
    ABUSEIPDB_API_KEY, MITRE_ATLAS_TECHNIQUES, OWASP_LLM_TOP10,
)
from .core import IOC

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class FeedSource:
    """Base class for threat intel feed sources."""

    def __init__(self, name: str, url: str = "", refresh_interval: int = FEED_REFRESH_INTERVAL):
        self.name = name
        self.url = url
        self.refresh_interval = refresh_interval
        self.last_refresh = None
        self.status = "idle"
        self.error = None
        self._cache = {}

    def fetch(self) -> Dict:
        """Fetch feed data. Override in subclasses."""
        raise NotImplementedError

    def is_stale(self) -> bool:
        if self.last_refresh is None:
            return True
        elapsed = time.time() - self.last_refresh
        return elapsed > self.refresh_interval

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "url": self.url,
            "status": self.status,
            "last_refresh": datetime.fromtimestamp(self.last_refresh).isoformat() if self.last_refresh else None,
            "stale": self.is_stale(),
            "error": bool(self.error),  # Don't expose internal error details
            "cached_items": len(self._cache),
        }


class MITREAtlasFeed(FeedSource):
    """Local MITRE ATLAS technique data (from config, no external fetch needed)."""

    def __init__(self):
        super().__init__("mitre_atlas", "local://config")
        self.refresh_interval = 86400 * 7  # Weekly

    def fetch(self) -> Dict:
        self.status = "active"
        self._cache = dict(MITRE_ATLAS_TECHNIQUES)
        self.last_refresh = time.time()
        self.error = None
        return {"techniques": len(self._cache), "source": "local_config"}

    def get_technique(self, tid: str) -> Optional[Dict]:
        return self._cache.get(tid)


class OWASPLLMFeed(FeedSource):
    """Local OWASP LLM Top 10 data (from config)."""

    def __init__(self):
        super().__init__("owasp_llm_top10", "local://config")
        self.refresh_interval = 86400 * 7

    def fetch(self) -> Dict:
        self.status = "active"
        self._cache = dict(OWASP_LLM_TOP10)
        self.last_refresh = time.time()
        self.error = None
        return {"categories": len(self._cache), "source": "local_config"}

    def get_category(self, oid: str) -> Optional[str]:
        return self._cache.get(oid)


class LocalSTIXFeed(FeedSource):
    """Import STIX bundles from local feed directory."""

    def __init__(self):
        super().__init__("local_stix", "local://feeds")
        self.refresh_interval = 300  # 5 minutes

    def fetch(self) -> Dict:
        FEED_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        stix_files = list(FEED_CACHE_DIR.glob("*.json"))
        self._cache = {}

        for f in stix_files:
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    bundle = json.load(fh)
                if bundle.get("type") == "bundle":
                    for obj in bundle.get("objects", []):
                        obj_id = obj.get("id", "")
                        if obj_id:
                            self._cache[obj_id] = obj
            except (json.JSONDecodeError, OSError):
                continue

        self.status = "active"
        self.last_refresh = time.time()
        self.error = None
        return {"objects": len(self._cache), "files": len(stix_files)}


class AbuseIPDBFeed(FeedSource):
    """AbuseIPDB IP reputation feed (requires API key)."""

    def __init__(self):
        super().__init__("abuseipdb", "https://api.abuseipdb.com/api/v2/check")
        self.refresh_interval = 3600
        self._ip_cache = {}

    def fetch(self) -> Dict:
        if not ABUSEIPDB_API_KEY:
            self.status = "disabled"
            self.error = "No API key configured"
            return {"status": "disabled"}

        self.status = "active"
        self.last_refresh = time.time()
        return {"status": "ready", "cached_ips": len(self._ip_cache)}

    def check_ip(self, ip: str) -> Optional[Dict]:
        """Check IP reputation against AbuseIPDB."""
        if not ABUSEIPDB_API_KEY or not HAS_REQUESTS:
            return None

        # Check cache first
        if ip in self._ip_cache:
            cached = self._ip_cache[ip]
            if time.time() - cached.get("_cached_at", 0) < FEED_STALE_THRESHOLD:
                return cached

        try:
            headers = {
                "Accept": "application/json",
                "Key": ABUSEIPDB_API_KEY,
            }
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            resp = requests.get(self.url, headers=headers, params=params, timeout=5)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                data["_cached_at"] = time.time()
                self._ip_cache[ip] = data
                return data
        except Exception as e:
            self.error = str(e)

        return None


class FeedManager:
    """Orchestrates feed refresh, caching, and IOC correlation."""

    def __init__(self):
        self.feeds: Dict[str, FeedSource] = {
            "mitre_atlas": MITREAtlasFeed(),
            "owasp_llm_top10": OWASPLLMFeed(),
            "local_stix": LocalSTIXFeed(),
            "abuseipdb": AbuseIPDBFeed(),
        }
        self._lock = threading.Lock()

        # Initial feed load
        self._refresh_all()

    def _refresh_all(self):
        """Refresh all feeds that are stale."""
        for name, feed in self.feeds.items():
            if feed.is_stale():
                try:
                    feed.fetch()
                except Exception as e:
                    feed.status = "error"
                    feed.error = str(e)

    def refresh_feed(self, name: str) -> Optional[Dict]:
        """Refresh a specific feed."""
        with self._lock:
            feed = self.feeds.get(name)
            if not feed:
                return None
            try:
                result = feed.fetch()
                return result
            except Exception as e:
                feed.status = "error"
                feed.error = str(e)  # Internal logging only
                return {"error": "Feed refresh failed"}

    def get_feed_status(self) -> List[Dict]:
        """Get status of all feeds."""
        return [feed.to_dict() for feed in self.feeds.values()]

    def correlate_ioc(self, ioc: IOC) -> Dict:
        """
        Correlate an IOC against external feeds.
        Returns enrichment data.
        """
        enrichment = {
            "mitre_details": [],
            "owasp_details": [],
            "ip_reputation": None,
            "stix_matches": [],
            "confidence_boost": 0.0,
        }

        # MITRE enrichment
        mitre_feed = self.feeds.get("mitre_atlas")
        if mitre_feed and isinstance(mitre_feed, MITREAtlasFeed):
            for tid in ioc.mitre_techniques:
                tech = mitre_feed.get_technique(tid)
                if tech:
                    enrichment["mitre_details"].append({
                        "technique_id": tid,
                        **tech,
                    })
                    enrichment["confidence_boost"] += 0.05

        # OWASP enrichment
        owasp_feed = self.feeds.get("owasp_llm_top10")
        if owasp_feed and isinstance(owasp_feed, OWASPLLMFeed):
            for oid in ioc.owasp_mappings:
                cat = owasp_feed.get_category(oid)
                if cat:
                    enrichment["owasp_details"].append({
                        "id": oid,
                        "name": cat,
                    })

        # IP reputation (for source_ip IOCs)
        if ioc.type == "source_ip" and ioc.value:
            abuseipdb = self.feeds.get("abuseipdb")
            if abuseipdb and isinstance(abuseipdb, AbuseIPDBFeed):
                ip_data = abuseipdb.check_ip(ioc.value)
                if ip_data:
                    enrichment["ip_reputation"] = {
                        "abuse_confidence_score": ip_data.get("abuseConfidenceScore", 0),
                        "total_reports": ip_data.get("totalReports", 0),
                        "country_code": ip_data.get("countryCode", ""),
                    }
                    if ip_data.get("abuseConfidenceScore", 0) > 50:
                        enrichment["confidence_boost"] += 0.15

        # Local STIX match
        local_stix = self.feeds.get("local_stix")
        if local_stix and isinstance(local_stix, LocalSTIXFeed):
            # Check for matching indicators by hash
            for obj_id, obj in local_stix._cache.items():
                if obj.get("type") == "indicator" and ioc.payload_hash:
                    if ioc.payload_hash in str(obj.get("pattern", "")):
                        enrichment["stix_matches"].append(obj_id)
                        enrichment["confidence_boost"] += 0.1

        return enrichment

    def import_stix_bundle(self, bundle_data: Dict) -> Dict:
        """Import an external STIX bundle into the local feed cache."""
        if bundle_data.get("type") != "bundle":
            return {"error": "Invalid STIX bundle: missing type=bundle"}

        FEED_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"imported_{ts}.json"
        filepath = FEED_CACHE_DIR / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(bundle_data, f, indent=2)

        # Refresh local STIX feed
        self.refresh_feed("local_stix")

        objects = bundle_data.get("objects", [])
        return {
            "imported": True,
            "filename": filename,
            "objects_count": len(objects),
            "types": list(set(o.get("type", "") for o in objects)),
        }
