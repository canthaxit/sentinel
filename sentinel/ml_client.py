"""
Sentinel - ML Anomaly Detection Client
Calls the Anomaly Detection API for ML-based scoring.
"""

import datetime
import logging

import requests
from oubliette_sec_utils import validate_outbound_url

from . import config

log = logging.getLogger(__name__)


class MLClient:
    """
    Client for the Anomaly Detection API.
    Returns None on failure for graceful degradation to LLM-only mode.
    """

    def __init__(self, api_url=None, timeout=None):
        self.api_url = api_url or config.ANOMALY_API_URL
        self.timeout = timeout or config.ANOMALY_API_TIMEOUT
        self._session = requests.Session()
        self._validate_url()

    def _validate_url(self):
        """Validate that the ML API URL is not pointing at a dangerous target.

        Delegates to :func:`oubliette_sec_utils.validate_outbound_url` which
        blocks non-http(s) schemes, cloud metadata endpoints, private /
        loopback / link-local / reserved IPs, RFC 4193 ULAs including the
        Fly.io 6PN range, and hostnames whose DNS resolution points at any
        of the above.
        """
        if not self.api_url:
            return
        decision = validate_outbound_url(self.api_url)
        if not decision.safe:
            log.warning("ANOMALY_API_URL rejected (%s), disabling", decision.reason)
            self.api_url = ""

    def _check_resolved_ip(self):
        """Re-validate DNS resolution before each request to defend against
        DNS rebinding. Returns True iff every resolved A/AAAA is still safe."""
        if not self.api_url:
            return True
        decision = validate_outbound_url(self.api_url)
        if not decision.safe:
            log.warning("ANOMALY_API_URL pre-request check failed: %s", decision.reason)
            return False
        return True

    def score(self, user_input, session, source_ip):
        """
        Get ML anomaly score for a user message.

        Args:
            user_input: The user's message text
            session: Session state dict with 'interactions' list
            source_ip: Client IP address

        Returns:
            dict with score/threat_type/severity/processing_time_ms, or None on failure
        """
        if not self.api_url:
            return None

        if not self._check_resolved_ip():
            log.warning("Pre-request DNS validation failed, blocking request")
            return None

        try:
            context_events = session.get("interactions", [])[-20:]

            suspicious_keywords = [
                "password",
                "secret",
                "admin",
                "ignore",
                "instructions",
                "system prompt",
                "credentials",
                "token",
                "api key",
            ]
            action = (
                "failed"
                if any(kw in user_input.lower() for kw in suspicious_keywords)
                else "success"
            )

            current_event = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "user": "chat_user",
                "source_ip": source_ip,
                "dest_ip": "sentinel_server",
                "event_type": "chat",
                "action": action,
                "message": user_input,
                "severity": "low",
            }

            all_events = context_events + [current_event]

            response = self._session.post(
                f"{self.api_url}/analyze",
                json={"logs": all_events, "return_all_events": False},
                timeout=self.timeout,
            )

            if response.status_code != 200:
                return None

            data = response.json()

            if data.get("anomalies_detected", 0) > 0:
                for anomaly in data.get("anomalies", []):
                    if anomaly.get("message") == user_input:
                        return {
                            "score": anomaly.get("anomaly_score", 0.0),
                            "threat_type": anomaly.get("threat_type", "unknown"),
                            "severity": anomaly.get("severity", "low"),
                            "processing_time_ms": data.get("processing_time_ms", 0.0),
                        }

            return {
                "score": 0.0,
                "threat_type": "none",
                "severity": "low",
                "processing_time_ms": data.get("processing_time_ms", 0.0),
            }

        except requests.exceptions.Timeout:
            log.warning("ML API timeout after %ss", self.timeout)
            return None
        except Exception as e:
            log.warning("ML API error: %s", e)
            return None
