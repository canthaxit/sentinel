"""
Threat Intelligence Storage
JSON file-based persistence for IOCs with monthly sharding.
Thread-safe with RLock.
"""

import json
import threading
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

from .config import IOC_STORAGE_DIR, MAX_IOCS_PER_QUERY
from .core import IOC, ThreatIntelEntry, compute_payload_hash


class ThreatIntelDB:
    """JSON file-based IOC storage with monthly shards."""

    def __init__(self, db_dir: Optional[str] = None):
        self.db_dir = Path(db_dir) if db_dir else IOC_STORAGE_DIR
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._hash_index = {}  # payload_hash -> (shard, ioc_id)
        self._build_index()

    def _shard_name(self, dt: Optional[datetime] = None) -> str:
        """Get shard filename for a given datetime."""
        if dt is None:
            dt = datetime.now()
        return f"iocs_{dt.strftime('%Y_%m')}.json"

    def _shard_path(self, shard_name: str) -> Path:
        return self.db_dir / shard_name

    def _load_shard(self, shard_name: str) -> List[Dict]:
        """Load IOCs from a shard file."""
        path = self._shard_path(shard_name)
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_shard(self, shard_name: str, iocs: List[Dict]):
        """Save IOCs to a shard file."""
        path = self._shard_path(shard_name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(iocs, f, indent=2, default=str)

    def _build_index(self):
        """Build in-memory hash index from all shards."""
        with self._lock:
            self._hash_index.clear()
            for shard_file in sorted(self.db_dir.glob("iocs_*.json")):
                shard_name = shard_file.name
                iocs = self._load_shard(shard_name)
                for ioc_data in iocs:
                    ph = ioc_data.get("payload_hash", "")
                    if ph:
                        self._hash_index[ph] = (shard_name, ioc_data.get("id", ""))

    def add_ioc(self, ioc: IOC) -> IOC:
        """
        Add or update an IOC. Deduplicates by payload_hash.
        Returns the IOC (updated if duplicate found).
        """
        with self._lock:
            # Check for duplicate via hash index
            if ioc.payload_hash in self._hash_index:
                shard_name, existing_id = self._hash_index[ioc.payload_hash]
                return self._update_sighting(shard_name, existing_id, ioc)

            # New IOC - add to current month shard
            shard_name = self._shard_name()
            iocs = self._load_shard(shard_name)
            ioc_dict = ioc.to_dict()
            iocs.append(ioc_dict)
            self._save_shard(shard_name, iocs)
            self._hash_index[ioc.payload_hash] = (shard_name, ioc.id)
            return ioc

    def _update_sighting(self, shard_name: str, ioc_id: str, new_ioc: IOC) -> IOC:
        """Update sighting count and last_seen for an existing IOC."""
        iocs = self._load_shard(shard_name)
        for i, ioc_data in enumerate(iocs):
            if ioc_data.get("id") == ioc_id:
                ioc_data["sighting_count"] = ioc_data.get("sighting_count", 1) + 1
                ioc_data["last_seen"] = datetime.now().isoformat()
                # Update ML score if new one is higher
                if new_ioc.ml_score and (
                    not ioc_data.get("ml_score") or new_ioc.ml_score > ioc_data["ml_score"]
                ):
                    ioc_data["ml_score"] = new_ioc.ml_score
                iocs[i] = ioc_data
                self._save_shard(shard_name, iocs)
                return IOC.from_dict(ioc_data)
        return new_ioc

    def get_ioc(self, ioc_id: str) -> Optional[IOC]:
        """Get a single IOC by ID."""
        with self._lock:
            for shard_file in self.db_dir.glob("iocs_*.json"):
                iocs = self._load_shard(shard_file.name)
                for ioc_data in iocs:
                    if ioc_data.get("id") == ioc_id:
                        return IOC.from_dict(ioc_data)
        return None

    def get_ioc_by_hash(self, payload_hash: str) -> Optional[IOC]:
        """Get an IOC by payload hash."""
        with self._lock:
            if payload_hash not in self._hash_index:
                return None
            shard_name, ioc_id = self._hash_index[payload_hash]
            iocs = self._load_shard(shard_name)
            for ioc_data in iocs:
                if ioc_data.get("id") == ioc_id:
                    return IOC.from_dict(ioc_data)
        return None

    def query_iocs(
        self,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
        source: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = MAX_IOCS_PER_QUERY,
        offset: int = 0,
    ) -> List[IOC]:
        """Query IOCs with optional filters."""
        results = []

        with self._lock:
            for shard_file in sorted(self.db_dir.glob("iocs_*.json"), reverse=True):
                iocs = self._load_shard(shard_file.name)
                for ioc_data in iocs:
                    if ioc_type and ioc_data.get("type") != ioc_type:
                        continue
                    if severity and ioc_data.get("severity") != severity:
                        continue
                    if threat_type and ioc_data.get("threat_type") != threat_type:
                        continue
                    if source and ioc_data.get("source") != source:
                        continue
                    if since and ioc_data.get("first_seen", "") < since:
                        continue
                    results.append(IOC.from_dict(ioc_data))

        # Sort by last_seen descending
        results.sort(key=lambda x: x.last_seen, reverse=True)

        return results[offset:offset + limit]

    def get_all_iocs(self) -> List[IOC]:
        """Get all IOCs across all shards."""
        return self.query_iocs(limit=999999)

    def get_statistics(self) -> Dict:
        """Calculate IOC statistics."""
        all_iocs = self.get_all_iocs()

        stats = {
            "total_iocs": len(all_iocs),
            "by_type": {},
            "by_severity": {},
            "by_threat_type": {},
            "by_source": {},
            "by_detection_method": {},
            "total_sightings": 0,
            "unique_payload_hashes": len(set(i.payload_hash for i in all_iocs if i.payload_hash)),
        }

        for ioc in all_iocs:
            stats["by_type"][ioc.type] = stats["by_type"].get(ioc.type, 0) + 1
            stats["by_severity"][ioc.severity] = stats["by_severity"].get(ioc.severity, 0) + 1
            stats["by_threat_type"][ioc.threat_type] = stats["by_threat_type"].get(ioc.threat_type, 0) + 1
            stats["by_source"][ioc.source] = stats["by_source"].get(ioc.source, 0) + 1
            stats["by_detection_method"][ioc.detection_method] = stats["by_detection_method"].get(ioc.detection_method, 0) + 1
            stats["total_sightings"] += ioc.sighting_count

        return stats

    def close(self):
        """No-op for compatibility with SQLite adapter pattern."""
        pass


class ThreatIntelSQLiteAdapter:
    """Drop-in replacement for ThreatIntelDB backed by unified SQLite.

    Wraps a StorageBackend and implements the same interface as
    ThreatIntelDB, so existing code that uses ``_get_db().add_ioc(...)``
    keeps working without changes.

    Args:
        backend: A StorageBackend instance (typically SQLiteBackend).
    """

    def __init__(self, backend):
        self._backend = backend

    def add_ioc(self, ioc) -> "IOC":
        """Add or update an IOC.  Accepts an IOC dataclass or dict."""
        if hasattr(ioc, "to_dict"):
            ioc_dict = ioc.to_dict()
        elif hasattr(ioc, "__dict__"):
            ioc_dict = vars(ioc)
        else:
            ioc_dict = dict(ioc)

        self._backend.save_threat_ioc(ioc_dict)

        # Return an IOC object for callers that expect one
        return IOC.from_dict(ioc_dict) if hasattr(IOC, "from_dict") else ioc

    def get_ioc(self, ioc_id: str):
        """Get a single IOC by ID."""
        # Query all and filter -- the unified backend indexes by payload_hash
        results = self._backend.query_threat_iocs(limit=10000)
        for r in results:
            if r.get("id") == ioc_id:
                return IOC.from_dict(r) if hasattr(IOC, "from_dict") else r
        return None

    def get_ioc_by_hash(self, payload_hash: str):
        """Get an IOC by payload hash."""
        result = self._backend.get_threat_ioc_by_hash(payload_hash)
        if result is None:
            return None
        return IOC.from_dict(result) if hasattr(IOC, "from_dict") else result

    def query_iocs(
        self,
        ioc_type=None,
        severity=None,
        threat_type=None,
        source=None,
        since=None,
        limit=100,
        offset=0,
    ):
        """Query IOCs with optional filters."""
        results = self._backend.query_threat_iocs(
            ioc_type=ioc_type,
            severity=severity,
            threat_type=threat_type,
            source=source,
            limit=limit + offset,  # over-fetch then slice
        )
        ioc_dicts = results[offset:offset + limit]
        if hasattr(IOC, "from_dict"):
            return [IOC.from_dict(d) for d in ioc_dicts]
        return ioc_dicts

    def get_all_iocs(self):
        """Get all IOCs."""
        return self.query_iocs(limit=999999)

    def get_statistics(self) -> Dict:
        """Calculate IOC statistics."""
        return self._backend.get_threat_statistics()

    def close(self):
        """No-op; the backend lifecycle is managed by the main app."""
        pass

    def export_csv(self) -> str:
        """Export all IOCs as CSV string."""
        import io
        import csv

        all_iocs = self.get_all_iocs()
        fieldnames = [
            "id", "type", "threat_type", "severity", "ml_score",
            "detection_method", "first_seen", "last_seen", "sighting_count", "payload_hash",
        ]

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for ioc in all_iocs:
            row = {}
            for f in fieldnames:
                row[f] = getattr(ioc, f, "") if hasattr(ioc, f) else ioc.get(f, "")
            writer.writerow(row)

        return output.getvalue()
