"""
Sentinel - Network Honey Services
====================================
Deploys fake network services that look like real infrastructure.
Any connection to a honey service is a confirmed reconnaissance or
lateral-movement indicator.

Profiles:
    - "enterprise": HTTP admin panels, SMTP relays, LDAP directories
    - "ics_scada": Modbus gateways, OPC-UA endpoints, HMI web panels

Usage:
    from sentinel.honey_services import HoneyServiceRegistry

    registry = HoneyServiceRegistry()
    configs = registry.generate_topology("enterprise")
    for cfg in configs:
        registry.start_service(cfg)
"""

import datetime
import logging
import socketserver
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("sentinel.honey_services")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class HoneyServiceConfig:
    """Configuration for a single honey service.

    Attributes:
        name: Human-readable service identifier (e.g. "admin-panel-http").
        port: TCP port to listen on.
        protocol: Protocol identifier ("http", "smtp", "ldap", etc.).
        banner: Initial banner/greeting string sent on connection.
        responses: Mapping of request patterns to canned response bodies.
        bind_host: Interface to bind to. Defaults to loopback so an
            accidental deployment does not expose the honey on all
            interfaces; operators who want external reachability (typical
            deception deployment) must opt in explicitly via
            ``SENTINEL_HONEY_BIND`` env var or by setting ``bind_host``
            directly on the config.
    """

    name: str
    port: int
    protocol: str = "http"
    banner: str = ""
    responses: dict[str, str] = field(default_factory=dict)
    bind_host: str = ""  # Resolved at start; empty means "use env default".


# ---------------------------------------------------------------------------
# HTTP Honey Service
# ---------------------------------------------------------------------------


class _HoneyHTTPHandler(socketserver.BaseRequestHandler):
    """Minimal HTTP/1.1 handler that returns configurable responses.

    Shared state is stored in ``_handler_ctx`` (a dict) to avoid
    Python's descriptor protocol turning callables into unbound methods.
    """

    _handler_ctx: dict[str, Any] = {}

    @property
    def _service_config(self) -> HoneyServiceConfig | None:
        return self._handler_ctx.get("service_config")

    @property
    def _trigger_cb(self) -> Callable | None:
        return self._handler_ctx.get("trigger_callback")

    def handle(self):
        try:
            data = self.request.recv(4096)
            if not data:
                return

            request_text = data.decode("utf-8", errors="replace")
            # Parse the request line
            lines = request_text.split("\r\n")
            request_line = lines[0] if lines else "GET / HTTP/1.1"
            parts = request_line.split(" ", 2)
            method = parts[0] if len(parts) >= 1 else "GET"
            path = parts[1] if len(parts) >= 2 else "/"

            source_ip = self.client_address[0]
            source_port = self.client_address[1]

            cfg = self._service_config

            log.info(
                "[HONEY-HTTP] %s:%d -> %s %s (service=%s)",
                source_ip,
                source_port,
                method,
                path,
                cfg.name if cfg else "unknown",
            )

            # Fire trigger callback
            cb = self._trigger_cb
            if cb is not None:
                cb(
                    {
                        "service": cfg.name if cfg else "unknown",
                        "protocol": "http",
                        "source_ip": source_ip,
                        "source_port": source_port,
                        "method": method,
                        "path": path,
                        "raw_request": request_text[:1024],
                        "timestamp": datetime.datetime.now().isoformat(),
                    }
                )

            # Determine response body
            body = None
            if cfg and cfg.responses:
                # Check for exact path match first, then default
                body = cfg.responses.get(path)
                if body is None:
                    body = cfg.responses.get("default")
            if body is None:
                body = "<html><body><h1>Service Unavailable</h1></body></html>"

            # Build server header
            server_name = "Apache/2.4.54 (Ubuntu)"
            if cfg and cfg.banner:
                server_name = cfg.banner

            now = datetime.datetime.now(datetime.UTC)
            date_str = now.strftime("%a, %d %b %Y %H:%M:%S GMT")

            body_bytes = body.encode("utf-8")
            response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Server: {server_name}\r\n"
                f"Date: {date_str}\r\n"
                f"Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Connection: close\r\n"
                f"X-Powered-By: PHP/8.1.2\r\n"
                f"Cache-Control: no-store\r\n"
                f"\r\n"
            ).encode() + body_bytes

            self.request.sendall(response)

        except Exception as exc:
            log.debug("Honey HTTP handler error: %s", exc)
        finally:
            try:
                self.request.close()
            except Exception:
                pass


class HoneyHTTPService:
    """A minimal socket-based HTTP server for deception.

    Runs in a background daemon thread. Serves configurable responses
    and logs every connection.

    Args:
        config: Service configuration with port, banner, and responses.
        trigger_callback: Optional callable invoked on each connection.
    """

    def __init__(self, config: HoneyServiceConfig, trigger_callback: Callable | None = None):
        self.config = config
        self.trigger_callback = trigger_callback
        self._server: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the HTTP honey service in a background thread."""
        if self._server is not None:
            return  # Already running

        # Store config and callback in a dict to avoid Python descriptor
        # protocol issues with callable class attributes.
        ctx = {
            "service_config": self.config,
            "trigger_callback": self.trigger_callback,
        }

        class Handler(_HoneyHTTPHandler):
            _handler_ctx = ctx

        # HIGH F-02 fix (2026-04-22 audit): default bind is loopback. Prior
        # unconditional 0.0.0.0 bind exposed every honey to any interface on
        # multi-homed hosts -- a typical SRE deployment on a jump-box with a
        # public interface would have broadcast the ICS deception to the
        # internet. Operators who want external reachability set
        # ``SENTINEL_HONEY_BIND`` (e.g. the decoy VLAN interface IP) or pass
        # ``bind_host`` on the HoneyServiceConfig.
        import os

        bind_host = self.config.bind_host or os.getenv("SENTINEL_HONEY_BIND", "127.0.0.1")
        socketserver.TCPServer.allow_reuse_address = True
        self._server = socketserver.TCPServer((bind_host, self.config.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"honey-http-{self.config.name}",
            daemon=True,
        )
        self._thread.start()
        log.info(
            "Honey HTTP service '%s' listening on port %d",
            self.config.name,
            self.config.port,
        )

    def stop(self) -> None:
        """Stop the HTTP honey service."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None
            log.info("Honey HTTP service '%s' stopped", self.config.name)

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._thread is not None and self._thread.is_alive()


# ---------------------------------------------------------------------------
# Service Registry
# ---------------------------------------------------------------------------


class HoneyServiceRegistry:
    """Manages multiple honey services and records trigger events.

    Thread-safe. Each trigger is recorded with full connection metadata.

    Args:
        max_triggers: Maximum trigger events to retain (FIFO eviction).
    """

    _MAX_TRIGGERS = 50000

    def __init__(self, max_triggers: int = _MAX_TRIGGERS):
        self._lock = threading.RLock()
        self._services: dict[str, HoneyHTTPService] = {}
        self._configs: dict[str, HoneyServiceConfig] = {}
        self._triggers: deque = deque(maxlen=max_triggers)

    def _trigger_callback(self, event: dict) -> None:
        """Central callback for all honey service triggers."""
        with self._lock:
            self._triggers.append(event)
        log.warning(
            "[HONEY-TRIGGER] %s from %s on service '%s'",
            event.get("protocol", "?"),
            event.get("source_ip", "?"),
            event.get("service", "?"),
        )

    def start_service(self, config: HoneyServiceConfig) -> None:
        """Start a honey service from a config.

        Args:
            config: HoneyServiceConfig describing the service.
        """
        with self._lock:
            if config.name in self._services:
                raise ValueError(f"Service '{config.name}' already registered")
            self._configs[config.name] = config
            svc = HoneyHTTPService(config, trigger_callback=self._trigger_callback)
            self._services[config.name] = svc
        svc.start()

    def stop_service(self, name: str) -> bool:
        """Stop a running honey service. Returns True if it existed."""
        with self._lock:
            svc = self._services.pop(name, None)
            self._configs.pop(name, None)
        if svc is not None:
            svc.stop()
            return True
        return False

    def stop_all(self) -> None:
        """Stop all running honey services."""
        with self._lock:
            names = list(self._services.keys())
        for name in names:
            self.stop_service(name)

    def list_services(self) -> list[dict[str, Any]]:
        """Return metadata for all registered services."""
        with self._lock:
            return [
                {
                    "name": cfg.name,
                    "port": cfg.port,
                    "protocol": cfg.protocol,
                    "running": self._services.get(cfg.name, None) is not None
                    and self._services[cfg.name].is_running,
                }
                for cfg in self._configs.values()
            ]

    def get_triggers(self, limit: int = 100) -> list[dict]:
        """Return recent trigger events."""
        with self._lock:
            triggers = list(self._triggers)
            return triggers[-limit:] if limit < len(triggers) else triggers

    @property
    def trigger_count(self) -> int:
        with self._lock:
            return len(self._triggers)

    @property
    def service_count(self) -> int:
        with self._lock:
            return len(self._services)

    # ------------------------------------------------------------------
    # Topology Generators
    # ------------------------------------------------------------------

    @staticmethod
    def generate_topology(profile: str = "enterprise") -> list[HoneyServiceConfig]:
        """Generate a list of realistic honey service configs for a profile.

        Args:
            profile: Either ``"enterprise"`` or ``"ics_scada"``.

        Returns:
            List of HoneyServiceConfig instances ready to be started.
        """
        if profile == "enterprise":
            return _enterprise_topology()
        elif profile == "ics_scada":
            return _ics_scada_topology()
        else:
            raise ValueError(f"Unknown profile: {profile!r}. Use 'enterprise' or 'ics_scada'.")


# ---------------------------------------------------------------------------
# Topology templates
# ---------------------------------------------------------------------------


def _enterprise_topology() -> list[HoneyServiceConfig]:
    """Enterprise IT topology: admin panels, webmail, LDAP, SMB-like."""
    return [
        HoneyServiceConfig(
            name="admin-panel-http",
            port=8080,
            protocol="http",
            banner="Apache/2.4.54 (Ubuntu)",
            responses={
                "/": (
                    "<html><head><title>Admin Console - Login</title></head>"
                    "<body><h1>System Administration Console</h1>"
                    "<form method='POST' action='/login'>"
                    "<label>Username:</label><input name='user'><br>"
                    "<label>Password:</label><input type='password' name='pass'><br>"
                    "<button type='submit'>Login</button></form>"
                    "<p class='version'>v4.2.1-build.1847</p></body></html>"
                ),
                "/login": (
                    "<html><body><h2>Authentication Failed</h2>"
                    "<p>Invalid credentials. This attempt has been logged.</p>"
                    "<a href='/'>Back to Login</a></body></html>"
                ),
                "/api/v1/status": '{"status":"ok","uptime":483291,"version":"4.2.1"}',
                "default": "<html><body><h1>404 Not Found</h1></body></html>",
            },
        ),
        HoneyServiceConfig(
            name="webmail-http",
            port=8443,
            protocol="http",
            banner="nginx/1.24.0",
            responses={
                "/": (
                    "<html><head><title>Webmail - Secure Access</title></head>"
                    "<body><h1>Corporate Webmail Portal</h1>"
                    "<form method='POST' action='/auth'>"
                    "<input name='email' placeholder='Email'><br>"
                    "<input type='password' name='password' placeholder='Password'><br>"
                    "<button>Sign In</button></form></body></html>"
                ),
                "default": "<html><body><h1>Forbidden</h1></body></html>",
            },
        ),
        HoneyServiceConfig(
            name="ldap-directory",
            port=8389,
            protocol="http",
            banner="OpenLDAP/2.5.16",
            responses={
                "/": (
                    "<html><head><title>LDAP Browser</title></head>"
                    "<body><h1>Directory Services - Read Only</h1>"
                    "<p>Base DN: dc=corp,dc=internal</p>"
                    "<p>Status: Connected (TLS)</p></body></html>"
                ),
                "default": '{"error":"authentication required"}',
            },
        ),
        HoneyServiceConfig(
            name="file-share-smb",
            port=8445,
            protocol="http",
            banner="Microsoft-IIS/10.0",
            responses={
                "/": (
                    "<html><head><title>File Server</title></head>"
                    "<body><h1>Network File Browser</h1>"
                    "<ul><li>\\\\filesrv01\\shared$</li>"
                    "<li>\\\\filesrv01\\finance$</li>"
                    "<li>\\\\filesrv01\\hr-confidential$</li></ul>"
                    "<p>Authentication required for access.</p></body></html>"
                ),
                "default": "<html><body><h1>403 Forbidden</h1></body></html>",
            },
        ),
    ]


def _ics_scada_topology() -> list[HoneyServiceConfig]:
    """ICS/SCADA topology: HMI panels, engineering workstation, historian."""
    return [
        HoneyServiceConfig(
            name="hmi-web-panel",
            port=8080,
            protocol="http",
            banner="lighttpd/1.4.64",
            responses={
                "/": (
                    "<html><head><title>Process Control HMI</title></head>"
                    "<body><h1>Plant Overview - Unit 3</h1>"
                    "<table border='1'>"
                    "<tr><th>Tag</th><th>Value</th><th>Unit</th><th>Status</th></tr>"
                    "<tr><td>TT-301</td><td>72.4</td><td>degC</td><td>NORMAL</td></tr>"
                    "<tr><td>PT-302</td><td>14.7</td><td>PSI</td><td>NORMAL</td></tr>"
                    "<tr><td>FT-303</td><td>450.2</td><td>GPM</td><td>NORMAL</td></tr>"
                    "<tr><td>LT-304</td><td>68.1</td><td>%</td><td>NORMAL</td></tr>"
                    "</table>"
                    "<p>Last update: 2026-03-27 14:30:00 UTC</p></body></html>"
                ),
                "/api/tags": (
                    '{"tags":['
                    '{"name":"TT-301","value":72.4,"unit":"degC","alarm":false},'
                    '{"name":"PT-302","value":14.7,"unit":"PSI","alarm":false},'
                    '{"name":"FT-303","value":450.2,"unit":"GPM","alarm":false}'
                    "]}"
                ),
                "default": "<html><body><h1>Access Restricted</h1></body></html>",
            },
        ),
        HoneyServiceConfig(
            name="engineering-workstation",
            port=8443,
            protocol="http",
            banner="Apache/2.4.41",
            responses={
                "/": (
                    "<html><head><title>EWS - Engineering Workstation</title></head>"
                    "<body><h1>PLC Programming Interface</h1>"
                    "<p>Controller: Siemens S7-1500 (CPU 1516-3 PN/DP)</p>"
                    "<p>Firmware: V2.9.7</p>"
                    "<p>Project: WaterTreatment_Unit3_Rev12</p>"
                    "<p>Status: RUN</p>"
                    "<form><button disabled>Connect (Auth Required)</button></form></body></html>"
                ),
                "default": '{"error":"not authenticated"}',
            },
        ),
        HoneyServiceConfig(
            name="historian-database",
            port=8502,
            protocol="http",
            banner="OSIsoft PI Web API/2021",
            responses={
                "/": (
                    "<html><head><title>Process Historian</title></head>"
                    "<body><h1>PI Historian - Web Interface</h1>"
                    "<p>Data Points: 12,847 active tags</p>"
                    "<p>Archive: 2.3 TB (2019-present)</p>"
                    "<p>API: /piwebapi/</p></body></html>"
                ),
                "/piwebapi/": (
                    '{"Links":{"Self":"https://historian.plant.local/piwebapi/",'
                    '"AssetServers":"https://historian.plant.local/piwebapi/assetservers",'
                    '"DataServers":"https://historian.plant.local/piwebapi/dataservers"}}'
                ),
                "default": '{"Errors":["Unauthorized"]}',
            },
        ),
        HoneyServiceConfig(
            name="modbus-gateway-web",
            port=8503,
            protocol="http",
            banner="Moxa MGate/3.5",
            responses={
                "/": (
                    "<html><head><title>Modbus Gateway</title></head>"
                    "<body><h1>Moxa MGate MB3170</h1>"
                    "<p>Serial Port 1: RS-485, 9600 baud</p>"
                    "<p>Modbus TCP: Port 502 (active)</p>"
                    "<p>Connected Devices: 8</p>"
                    "<p>Firmware: V3.5.2</p></body></html>"
                ),
                "default": "<html><body><h1>Login Required</h1></body></html>",
            },
        ),
    ]
