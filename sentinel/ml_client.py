"""
Sentinel - ML Anomaly Detection Client
Calls the Anomaly Detection API for ML-based scoring.
"""

import datetime
import ipaddress
import logging
import socket

import requests

from . import config

log = logging.getLogger(__name__)


class MLClient:
    """
    Client for the Anomaly Detection API.
    Returns None on failure for graceful degradation to LLM-only mode.
    """

    # Blocked URL patterns to prevent SSRF — cloud metadata endpoints
    _BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "[fd00::"}

    def __init__(self, api_url=None, timeout=None):
        self.api_url = api_url or config.ANOMALY_API_URL
        self.timeout = timeout or config.ANOMALY_API_TIMEOUT
        self._session = requests.Session()
        self._validate_url()

    @staticmethod
    def _is_dangerous_ip(addr_str):
        """Return True if *addr_str* is a loopback, private, reserved, or
        link-local IP address that should never be the target of an outbound
        request (SSRF protection)."""
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            return False
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified  # 0.0.0.0, ::
        )

    def _validate_url(self):
        """Validate that the ML API URL is not pointing at a dangerous target.

        Blocks:
        - Non-HTTP(S) schemes
        - Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
        - Private / loopback / link-local IPs (127.0.0.0/8, 10.0.0.0/8,
          172.16.0.0/12, 192.168.0.0/16, ::1, fd00::/8, 0.0.0.0)
        - Hostnames that DNS-resolve to any of the above
        """
        if not self.api_url:
            return
        from urllib.parse import urlparse

        parsed = urlparse(self.api_url)
        if parsed.scheme not in ("http", "https"):
            log.warning("ANOMALY_API_URL has invalid scheme %r, disabling", parsed.scheme)
            self.api_url = ""
            return
        host = parsed.hostname or ""

        # 1. Explicit blocklist (cloud metadata endpoints)
        if host in self._BLOCKED_HOSTS or host.startswith("169.254."):
            log.warning("ANOMALY_API_URL points to blocked host %r, disabling", host)
            self.api_url = ""
            return

        # 2. Direct IP check (covers literal IPs like 127.0.0.1, 10.0.0.1, ::1)
        if self._is_dangerous_ip(host):
            log.warning("ANOMALY_API_URL points to private/reserved IP %r, disabling", host)
            self.api_url = ""
            return

        # 3. DNS resolution check — a domain name could resolve to a private IP
        try:
            addrinfos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for _family, _type, _proto, _canonname, sockaddr in addrinfos:
                resolved_ip = sockaddr[0]
                if self._is_dangerous_ip(resolved_ip):
                    log.warning(
                        "ANOMALY_API_URL host %r resolves to private/reserved IP %s, disabling",
                        host,
                        resolved_ip,
                    )
                    self.api_url = ""
                    return
        except socket.gaierror:
            log.warning("ANOMALY_API_URL host %r cannot be resolved, disabling", host)
            self.api_url = ""
            return
        except OSError as exc:
            log.warning("ANOMALY_API_URL DNS check failed for %r: %s, disabling", host, exc)
            self.api_url = ""

    def _check_resolved_ip(self):
        """Re-validate DNS resolution before each request to prevent TOCTOU/rebinding."""
        if not self.api_url:
            return True
        from urllib.parse import urlparse

        parsed = urlparse(self.api_url)
        hostname = parsed.hostname or ""
        try:
            for _family, _, _, _, sockaddr in socket.getaddrinfo(hostname, parsed.port or 80):
                ip = ipaddress.ip_address(sockaddr[0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    log.warning("ANOMALY_API_URL DNS rebinding detected: %s -> %s", hostname, ip)
                    return False
        except (socket.gaierror, ValueError):
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
