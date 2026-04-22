"""
Allama SOAR adapter for Sentinel.

Bridges Shield detection events into Allama's workflow orchestration
(FastAPI + Temporal + PydanticAI).  Two components:

1. ``AllamaNotifier`` -- ``WebhookNotifier`` subclass for use with
   ``WebhookManager``.  Sends structured alert JSON to Allama's
   webhook trigger endpoint (``POST /webhooks/{workflow_id}/{secret}``).

2. ``AllamaClient`` -- Standalone REST client for richer SOAR
   interactions: case CRUD, workflow triggering, health checks.

Usage with WebhookManager::

    from sentinel.allama import AllamaNotifier
    from sentinel.webhooks import WebhookManager

    notifier = AllamaNotifier(
        base_url="https://allama.example.com",
        workflow_id="shield-alert",
        webhook_secret="s3cr3t",
    )
    mgr = WebhookManager(notifiers=[notifier])

Usage as standalone client::

    from sentinel.allama import AllamaClient

    with AllamaClient("https://allama.example.com", api_key="key") as client:
        client.health_check()
        case = client.create_case(title="Prompt injection from 10.0.0.1")
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any

import requests

from .webhooks import WebhookNotifier

log = logging.getLogger(__name__)

# ---- severity / priority mapping ----

_SEVERITY_MAP = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
}

_OCSF_CATEGORY = {
    "pre_filter": "pattern_match",
    "ml_only": "ml_classification",
    "llm_only": "llm_analysis",
    "ensemble": "ensemble_analysis",
    "escalation": "session_escalation",
}


# ---- AllamaNotifier (WebhookNotifier subclass) ----


class AllamaNotifier(WebhookNotifier):
    """Send Shield events to an Allama SOAR webhook endpoint.

    Follows the same drop-in pattern as ``SlackNotifier``,
    ``TeamsNotifier``, and ``PagerDutyNotifier``.

    Config can be passed directly or read from environment variables:

    ============== ======================== =============================
    Param          Env var                  Default
    ============== ======================== =============================
    base_url       ALLAMA_BASE_URL          (required)
    workflow_id    ALLAMA_WORKFLOW_ID       ``shield-alert``
    webhook_secret ALLAMA_WEBHOOK_SECRET    (required)
    api_key        ALLAMA_API_KEY           ``""``
    timeout        ALLAMA_TIMEOUT           ``10``
    verify_ssl     ALLAMA_VERIFY_SSL        ``true``
    tags           --                       ``[]``
    ============== ======================== =============================
    """

    def __init__(
        self,
        base_url: str | None = None,
        workflow_id: str | None = None,
        webhook_secret: str | None = None,
        api_key: str | None = None,
        timeout: int | None = None,
        verify_ssl: bool | None = None,
        tags: list[str] | None = None,
    ):
        self.base_url = (base_url or os.getenv("ALLAMA_BASE_URL", "")).rstrip("/")
        self.workflow_id = workflow_id or os.getenv("ALLAMA_WORKFLOW_ID", "shield-alert")
        self.webhook_secret = webhook_secret or os.getenv("ALLAMA_WEBHOOK_SECRET", "")
        self.api_key = api_key or os.getenv("ALLAMA_API_KEY", "")
        self.tags = tags or []

        if timeout is not None:
            self.timeout = timeout
        else:
            self.timeout = int(os.getenv("ALLAMA_TIMEOUT", "10"))

        if verify_ssl is not None:
            self.verify_ssl = verify_ssl
        else:
            self.verify_ssl = os.getenv("ALLAMA_VERIFY_SSL", "true").lower() in ("true", "1", "yes")

    @property
    def configured(self) -> bool:
        """Return True if the minimum required settings are present."""
        return bool(self.base_url and self.webhook_secret)

    @property
    def webhook_url(self) -> str:
        """Build the full webhook trigger URL."""
        return f"{self.base_url}/webhooks/{self.workflow_id}/{self.webhook_secret}"

    # ---- payload construction ----

    @staticmethod
    def _dedup_key(event: dict[str, Any]) -> str:
        """SHA-256 dedup key from session_id:event_type:verdict."""
        session_id = event.get("session_id", "unknown")
        event_type = event.get("event_type", "detection")
        verdict = event.get("verdict", "UNKNOWN")
        raw = f"{session_id}:{event_type}:{verdict}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _build_alert_payload(self, event: dict[str, Any]) -> dict[str, Any]:
        """Map a Shield event dict to an OCSF-aligned alert payload."""
        severity = event.get("severity", "medium")
        event_type = event.get("event_type", "detection")
        detection_method = event.get("detection_method", "unknown")

        payload: dict[str, Any] = {
            "alert_id": self._dedup_key(event),
            "source": "sentinel",
            "event_type": event_type,
            "timestamp": event.get("timestamp", time.time()),
            "severity": severity,
            "priority": _SEVERITY_MAP.get(severity, 3),
            "category": _OCSF_CATEGORY.get(detection_method, detection_method),
            "detection": {
                "verdict": event.get("verdict", "UNKNOWN"),
                "detection_method": detection_method,
                "ml_score": event.get("ml_score"),
                "message_preview": (event.get("message_preview", "") or "")[:500],
            },
            "session": {
                "session_id": event.get("session_id", ""),
                "source_ip": event.get("source_ip", ""),
            },
            "raw_event": event,
        }

        # Escalation-specific fields
        if event_type == "escalation":
            payload["escalation"] = {
                "reason": event.get("escalation_reason", ""),
                "threat_count": event.get("threat_count", 0),
            }

        # Extra tags
        if self.tags:
            payload["tags"] = list(self.tags)

        return payload

    # ---- notify (WebhookNotifier interface) ----

    def notify(self, event: dict[str, Any]) -> bool:
        """Send *event* to the Allama webhook endpoint.

        Returns True on success, False on failure.  Never raises.
        """
        if not self.configured:
            log.warning("AllamaNotifier not configured (missing base_url or webhook_secret)")
            return False

        payload = self._build_alert_payload(event)
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            r = requests.post(
                self.webhook_url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            r.raise_for_status()
            return True
        except Exception:
            log.exception("Allama webhook failed")
            return False


# ---- AllamaClient (standalone REST client) ----


class AllamaClient:
    """REST client for the Allama SOAR API.

    Supports case CRUD, workflow triggering, and health checks.
    Uses ``requests.Session`` with connection pooling.

    Usage::

        client = AllamaClient("https://allama.example.com", api_key="key")
        client.health_check()
        case = client.create_case(title="Injection from 10.0.0.1")
        client.close()

    Or as a context manager::

        with AllamaClient("https://allama.example.com") as client:
            client.create_case(title="...")
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: int = 10,
        verify_ssl: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"
        self._session.headers["Content-Type"] = "application/json"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        """Close the underlying requests session."""
        self._session.close()

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Send an HTTP request and return the response."""
        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        resp = self._session.request(method, url, **kwargs)
        resp.raise_for_status()
        return resp

    # ---- health ----

    def health_check(self) -> dict[str, Any]:
        """Check Allama platform health (``GET /health``)."""
        return self._request("GET", "/health").json()

    # ---- cases ----

    def create_case(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new SOAR case (``POST /api/cases``)."""
        body = {
            "title": title,
            "description": description,
            "severity": severity,
            "tags": tags or [],
            "source": "sentinel",
        }
        return self._request("POST", "/api/cases", json=body).json()

    def create_case_from_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Convenience: create a case pre-populated from a Shield event."""
        verdict = event.get("verdict", "UNKNOWN")
        source_ip = event.get("source_ip", "n/a")
        event_type = event.get("event_type", "detection")
        severity = event.get("severity", "medium")
        session_id = event.get("session_id", "unknown")

        title = f"Shield {event_type}: {verdict} from {source_ip}"
        lines = [
            f"Session: {session_id}",
            f"Detection method: {event.get('detection_method', 'n/a')}",
        ]
        ml_score = event.get("ml_score")
        if ml_score is not None:
            lines.append(f"ML score: {ml_score:.2f}")
        preview = event.get("message_preview", "")
        if preview:
            lines.append(f"Preview: {preview[:200]}")
        reason = event.get("escalation_reason", "")
        if reason:
            lines.append(f"Escalation reason: {reason}")

        return self.create_case(
            title=title,
            description="\n".join(lines),
            severity=severity,
            tags=["sentinel", event_type],
        )

    def update_case(self, case_id: str, **fields) -> dict[str, Any]:
        """Update an existing case (``PATCH /api/cases/{case_id}``)."""
        from urllib.parse import quote

        safe_id = quote(case_id, safe="")
        return self._request("PATCH", f"/api/cases/{safe_id}", json=fields).json()

    def add_comment(self, case_id: str, comment: str) -> dict[str, Any]:
        """Add a comment to a case (``POST /api/cases/{case_id}/comments``)."""
        from urllib.parse import quote

        safe_id = quote(case_id, safe="")
        return self._request(
            "POST",
            f"/api/cases/{safe_id}/comments",
            json={"comment": comment, "source": "sentinel"},
        ).json()

    # ---- workflows ----

    def trigger_workflow(
        self,
        workflow_id: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Trigger a named workflow (``POST /api/workflows/{workflow_id}/trigger``)."""
        return self._request(
            "POST",
            f"/api/workflows/{workflow_id}/trigger",
            json=payload or {},
        ).json()
