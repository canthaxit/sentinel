"""
Sentinel - Multi-Tenancy
Thread-safe tenant management with API key authentication and per-tenant isolation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Tenant:
    """Represents a tenant in the multi-tenant Shield deployment."""

    tenant_id: str
    name: str
    api_key_hash: str = ""
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    config_overrides: Dict[str, Any] = field(default_factory=dict)
    rate_limit: Optional[int] = None
    tags: List[str] = field(default_factory=list)


def _hash_key(api_key: str) -> str:
    """SHA-256 hash of an API key."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class TenantManager:
    """
    Manages tenants with API key authentication and per-tenant isolation.

    Thread-safe with RLock on all shared state.

    Usage::

        mgr = TenantManager()
        tenant, key = mgr.create_tenant("acme", "Acme Corp")
        resolved = mgr.resolve_by_api_key(key)
        assert resolved.tenant_id == "acme"
    """

    def __init__(self):
        self._tenants: Dict[str, Tenant] = {}
        self._key_index: Dict[str, str] = {}  # api_key_hash -> tenant_id
        self._lock = threading.RLock()

    # ---- CRUD ----

    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        config_overrides: Optional[Dict[str, Any]] = None,
        rate_limit: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> tuple:
        """Create a tenant and return (Tenant, plaintext_api_key).

        The plaintext key is returned exactly once.  Only the hash is stored.
        """
        api_key = secrets.token_urlsafe(32)
        key_hash = _hash_key(api_key)

        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            api_key_hash=key_hash,
            config_overrides=config_overrides or {},
            rate_limit=rate_limit,
            tags=tags or [],
        )

        with self._lock:
            if tenant_id in self._tenants:
                raise ValueError(f"Tenant {tenant_id!r} already exists")
            self._tenants[tenant_id] = tenant
            self._key_index[key_hash] = tenant_id

        return tenant, api_key

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get a tenant by ID.  Returns None if not found."""
        with self._lock:
            return self._tenants.get(tenant_id)

    def list_tenants(self) -> List[Tenant]:
        """Return a list of all tenants."""
        with self._lock:
            return list(self._tenants.values())

    def update_tenant(self, tenant_id: str, **fields) -> Tenant:
        """Update tenant fields.  Returns the updated tenant."""
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if tenant is None:
                raise KeyError(f"Tenant {tenant_id!r} not found")
            for k, v in fields.items():
                if k == "config_overrides" and isinstance(v, dict):
                    tenant.config_overrides.update(v)
                elif hasattr(tenant, k) and k not in ("tenant_id", "api_key_hash", "created_at"):
                    setattr(tenant, k, v)
            return tenant

    def delete_tenant(self, tenant_id: str) -> bool:
        """Delete a tenant.  Returns True if deleted, False if not found."""
        with self._lock:
            tenant = self._tenants.pop(tenant_id, None)
            if tenant is None:
                return False
            self._key_index.pop(tenant.api_key_hash, None)
            return True

    # ---- API key operations ----

    def rotate_api_key(self, tenant_id: str) -> str:
        """Generate a new API key for a tenant.  Returns the new plaintext key."""
        new_key = secrets.token_urlsafe(32)
        new_hash = _hash_key(new_key)

        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if tenant is None:
                raise KeyError(f"Tenant {tenant_id!r} not found")
            # Remove old index entry
            self._key_index.pop(tenant.api_key_hash, None)
            # Update
            tenant.api_key_hash = new_hash
            self._key_index[new_hash] = tenant_id

        return new_key

    def resolve_by_api_key(self, api_key: str) -> Optional[Tenant]:
        """Resolve a tenant from a plaintext API key.

        Uses timing-safe comparison to prevent timing attacks.
        Returns None if no match or tenant is disabled.
        """
        incoming_hash = _hash_key(api_key)

        with self._lock:
            # Timing-safe scan: compare against every stored hash
            # to prevent timing-based enumeration of valid keys.
            # Iterate ALL entries to prevent timing-based key position leaks
            matched_id = None
            for stored_hash, tid in self._key_index.items():
                if hmac.compare_digest(incoming_hash, stored_hash):
                    matched_id = tid

            if matched_id is None:
                return None

            tenant = self._tenants.get(matched_id)
            if tenant is None or not tenant.enabled:
                return None
            return tenant

    # ---- Per-tenant config ----

    def get_effective_config(self, tenant_id: str, base_config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge tenant overrides on top of base config.

        Returns a new dict; does not mutate *base_config*.
        """
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if tenant is None:
                return dict(base_config)
            merged = dict(base_config)
            merged.update(tenant.config_overrides)
            if tenant.rate_limit is not None:
                merged["rate_limit"] = tenant.rate_limit
            return merged
