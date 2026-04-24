"""
Webhook alerting for Sentinel.

Dispatches detection and escalation events to Slack, Microsoft Teams,
and PagerDuty.  No extra dependencies -- uses ``requests`` (already a
core dep).

Usage::

    from sentinel.webhooks import WebhookManager, SlackNotifier

    mgr = WebhookManager(
        notifiers=[SlackNotifier("https://hooks.slack.com/services/...")],
        severity_threshold="medium",
    )
    shield = Shield(webhook_manager=mgr)
"""

from __future__ import annotations

import hashlib
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

log = logging.getLogger(__name__)

# ---- severity helpers ----

_SEVERITY_LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def determine_severity(result_dict: dict[str, Any]) -> str:
    """Map a ShieldResult dict to a severity string."""
    ml_score = result_dict.get("ml_score") or 0
    escalated = result_dict.get("session_escalated", False)
    method = result_dict.get("detection_method", "")

    if escalated or ml_score >= 0.95:
        return "critical"
    if ml_score >= 0.80 or method == "pre_filter":
        return "high"
    if ml_score >= 0.50:
        return "medium"
    return "low"


# ---- base class ----


class WebhookNotifier:
    """Base notifier -- subclasses implement ``notify()``."""

    def notify(self, event: dict[str, Any]) -> bool:
        """Send *event* to the external service.  Return True on success."""
        raise NotImplementedError


# ---- Slack ----


class SlackNotifier(WebhookNotifier):
    """Post Block Kit messages to a Slack Incoming Webhook URL."""

    def __init__(self, webhook_url: str, channel: str | None = None):
        self.webhook_url = webhook_url
        self.channel = channel

    def notify(self, event: dict[str, Any]) -> bool:
        severity = event.get("severity", "unknown")
        verdict = event.get("verdict", "UNKNOWN")
        event_type = event.get("event_type", "detection")
        session_id = event.get("session_id", "n/a")
        source_ip = event.get("source_ip", "n/a")
        method = event.get("detection_method", "n/a")
        ml_score = event.get("ml_score")
        preview = event.get("message_preview", "")[:120]
        reason = event.get("escalation_reason", "")

        color = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "medium": "#FFCC00",
            "low": "#00CC00",
        }.get(severity, "#808080")

        fields = [
            {"type": "mrkdwn", "text": f"*Verdict:* {verdict}"},
            {"type": "mrkdwn", "text": f"*Severity:* {severity.upper()}"},
            {"type": "mrkdwn", "text": f"*Method:* {method}"},
            {"type": "mrkdwn", "text": f"*Session:* `{session_id[:12]}`"},
            {"type": "mrkdwn", "text": f"*Source IP:* {source_ip}"},
        ]
        if ml_score is not None:
            fields.append({"type": "mrkdwn", "text": f"*ML Score:* {ml_score:.2f}"})
        if reason:
            fields.append({"type": "mrkdwn", "text": f"*Escalation:* {reason}"})

        title = (
            "Sentinel -- Escalation Alert"
            if event_type == "escalation"
            else "Sentinel -- Detection Alert"
        )

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": title}},
            {"type": "section", "fields": fields},
        ]
        if preview:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Preview:* ```{preview}```"},
                }
            )

        payload: dict[str, Any] = {"blocks": blocks}
        if self.channel:
            payload["channel"] = self.channel

        # Slack also supports top-level "attachments" for the colour bar
        payload["attachments"] = [{"color": color, "blocks": []}]

        try:
            r = requests.post(self.webhook_url, json=payload, timeout=10)
            r.raise_for_status()
            return True
        except Exception:
            log.exception("Slack webhook failed")
            return False


# ---- Microsoft Teams ----


class TeamsNotifier(WebhookNotifier):
    """Post Adaptive Card messages to a Teams Incoming Webhook."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def notify(self, event: dict[str, Any]) -> bool:
        severity = event.get("severity", "unknown")
        verdict = event.get("verdict", "UNKNOWN")
        event_type = event.get("event_type", "detection")
        session_id = event.get("session_id", "n/a")
        source_ip = event.get("source_ip", "n/a")
        method = event.get("detection_method", "n/a")
        ml_score = event.get("ml_score")
        preview = event.get("message_preview", "")[:120]
        reason = event.get("escalation_reason", "")

        accent = {
            "critical": "attention",
            "high": "warning",
            "medium": "accent",
            "low": "good",
        }.get(severity, "default")

        title = "Escalation Alert" if event_type == "escalation" else "Detection Alert"

        facts = [
            {"title": "Verdict", "value": verdict},
            {"title": "Severity", "value": severity.upper()},
            {"title": "Method", "value": method},
            {"title": "Session", "value": session_id[:12]},
            {"title": "Source IP", "value": source_ip},
        ]
        if ml_score is not None:
            facts.append({"title": "ML Score", "value": f"{ml_score:.2f}"})
        if reason:
            facts.append({"title": "Escalation", "value": reason})

        body: list[Any] = [
            {
                "type": "TextBlock",
                "text": f"Sentinel -- {title}",
                "weight": "bolder",
                "size": "medium",
                "color": accent,
            },
            {"type": "FactSet", "facts": facts},
        ]
        if preview:
            body.append(
                {"type": "TextBlock", "text": f"Preview: {preview}", "wrap": True, "isSubtle": True}
            )

        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body,
                    },
                }
            ],
        }

        try:
            r = requests.post(self.webhook_url, json=card, timeout=10)
            r.raise_for_status()
            return True
        except Exception:
            log.exception("Teams webhook failed")
            return False


# ---- PagerDuty ----


class PagerDutyNotifier(WebhookNotifier):
    """Send events via the PagerDuty Events API v2."""

    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str):
        self.routing_key = routing_key

    def notify(self, event: dict[str, Any]) -> bool:
        severity = event.get("severity", "warning")
        pd_severity = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
        }.get(severity, "warning")

        session_id = event.get("session_id", "unknown")
        event_type = event.get("event_type", "detection")
        # Dedup key: same session + event_type = same incident
        dedup = hashlib.sha256(f"{session_id}:{event_type}".encode()).hexdigest()[:32]

        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": dedup,
            "payload": {
                "summary": (
                    f"Sentinel {event_type}: "
                    f"{event.get('verdict', 'UNKNOWN')} from "
                    f"{event.get('source_ip', 'n/a')}"
                ),
                "severity": pd_severity,
                "source": f"sentinel:{session_id[:12]}",
                "custom_details": {k: v for k, v in event.items() if k not in ("routing_key",)},
            },
        }

        try:
            r = requests.post(self.EVENTS_URL, json=payload, timeout=10)
            r.raise_for_status()
            return True
        except Exception:
            log.exception("PagerDuty webhook failed")
            return False


# ---- WebhookManager ----


class WebhookManager:
    """Dispatch events to multiple notifiers in daemon threads.

    Args:
        notifiers: List of WebhookNotifier instances.
        severity_threshold: Minimum severity to fire (low/medium/high/critical).
        max_concurrent: Semaphore limit for outbound webhook calls.
    """

    def __init__(
        self,
        notifiers: list[WebhookNotifier] | None = None,
        severity_threshold: str = "high",
        max_concurrent: int = 4,
    ):
        self.notifiers: list[WebhookNotifier] = notifiers or []
        self.severity_threshold = severity_threshold
        self._executor = ThreadPoolExecutor(
            max_workers=max_concurrent,
            thread_name_prefix="webhook",
        )

    def _should_notify(self, severity: str) -> bool:
        threshold = _SEVERITY_LEVELS.get(self.severity_threshold, 2)
        actual = _SEVERITY_LEVELS.get(severity, 0)
        return actual >= threshold

    def _dispatch(self, event: dict[str, Any]) -> None:
        """Fire each notifier via bounded thread pool."""
        for notifier in self.notifiers:
            self._executor.submit(self._safe_notify, notifier, event)

    def _safe_notify(self, notifier: WebhookNotifier, event: dict[str, Any]) -> None:
        try:
            notifier.notify(event)
        except Exception:
            log.exception("Notifier %s failed", type(notifier).__name__)

    def _build_event(self, event_type: str, **kwargs) -> dict[str, Any]:
        event = {"event_type": event_type, "timestamp": time.time()}
        event.update(kwargs)
        return event

    def notify_detection(
        self,
        result_dict: dict[str, Any],
        session_id: str = "",
        source_ip: str = "",
        user_input: str = "",
    ) -> None:
        """Called by Shield after a MALICIOUS / SAFE_REVIEW verdict."""
        severity = determine_severity(result_dict)
        if not self._should_notify(severity):
            return

        event = self._build_event(
            event_type="detection",
            verdict=result_dict.get("verdict", "UNKNOWN"),
            severity=severity,
            session_id=session_id,
            source_ip=source_ip,
            detection_method=result_dict.get("detection_method", ""),
            ml_score=result_dict.get("ml_score"),
            message_preview=user_input[:200] if user_input else "",
        )
        self._dispatch(event)

    def notify_escalation(
        self,
        session_id: str,
        source_ip: str,
        reason: str,
        threat_count: int = 0,
    ) -> None:
        """Called when a session flips to escalated."""
        event = self._build_event(
            event_type="escalation",
            severity="critical",
            session_id=session_id,
            source_ip=source_ip,
            escalation_reason=reason,
            threat_count=threat_count,
            verdict="ESCALATED",
        )
        self._dispatch(event)
