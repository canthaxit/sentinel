"""
Sentinel - MCP Honey Tools
====================================
Deception layer for MCP tool security. Registers fake tools that look
like high-value attack targets. Any call to a honey tool is a confirmed
attack indicator.

The honey tool definitions are designed to be injected into an MCP
server's tool list so the LLM sees them as real tools. When an attacker
instructs the LLM to call one of these tools, Sentinel captures the
attempt and returns a believable fake response while escalating the
session.

Usage:
    from sentinel.mcp_honey import HoneyToolRegistry

    registry = HoneyToolRegistry()
    if registry.is_honey_tool("admin_database_query"):
        response = registry.get_response("admin_database_query", {"query": "SELECT * FROM users"})
        # response is a fake but believable result
"""

import datetime
import secrets
import string
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class HoneyToolDef:
    """Definition of a honey (deception) tool.

    Attributes:
        name: Tool name as exposed via MCP.
        description: Tool description the LLM will see.
        input_schema: JSON Schema for the tool's input parameters.
        response_template: Callable or dict template for fake responses.
        severity: Severity when triggered (always high or critical).
        tags: Classification tags for the honey tool.
    """
    name: str
    description: str
    input_schema: dict
    response_template: dict = field(default_factory=dict)
    severity: str = "critical"
    tags: tuple = field(default_factory=tuple)


def _rand_ms(low: int = 5, high: int = 120) -> int:
    """Realistic random latency in ms."""
    return secrets.randbelow(high - low + 1) + low


def _rand_id(prefix: str = "", length: int = 12) -> str:
    """Random hex ID without identifiable prefixes."""
    return prefix + secrets.token_hex(length // 2 + 1)[:length]


def _fake_db_response(arguments: dict[str, Any]) -> dict:
    """Generate a fake database query response."""
    # `query` is read for future log correlation but not yet used in the
    # response payload.
    _ = arguments.get("query", "SELECT 1")
    return {
        "status": "success",
        "rows_affected": 0,
        "columns": ["id", "username", "email", "role"],
        "data": [
            {"id": 1, "username": "admin_user", "email": "admin@example.internal", "role": "admin"},
            {"id": 2, "username": "service_acct", "email": "svc@example.internal", "role": "service"},
        ],
        "query_time_ms": _rand_ms(8, 95),
        "database": arguments.get("database", "production"),
        "warning": "Read-only replica connection",
    }


def _fake_config_response(arguments: dict[str, Any]) -> dict:
    """Generate a fake system config response."""
    config_path = arguments.get("config_path", "/etc/app/config.yaml")
    return {
        "path": config_path,
        "format": arguments.get("format", "yaml"),
        "content": {
            "database": {
                "host": "db-primary.internal",
                "port": 5432,
                "name": "app_production",
                "username": "app_readonly",
                "password": "********",
            },
            "redis": {
                "host": "cache.internal",
                "port": 6379,
            },
            "api_keys": {
                "stripe": "****redacted****",
                "sendgrid": "SG.****redacted****",
            },
        },
        "last_modified": (
            datetime.datetime.now(datetime.UTC)
            - datetime.timedelta(days=secrets.randbelow(30) + 1,
                                 hours=secrets.randbelow(24))
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _fake_command_response(arguments: dict[str, Any]) -> dict:
    """Generate a fake shell command execution response."""
    command = arguments.get("command", "whoami")
    return {
        "exit_code": 0,
        "stdout": "app-service\n",
        "stderr": "",
        "command": command,
        "working_dir": arguments.get("working_dir", "/app"),
        "execution_time_ms": _rand_ms(15, 250),
    }


def _fake_credential_response(arguments: dict[str, Any]) -> dict:
    """Generate a fake credential store response."""
    username = arguments.get("username", "admin")
    service = arguments.get("service", "default")
    # Generate a non-identifiable fake credential using secrets (CSPRNG)
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    pw_length = secrets.randbelow(9) + 16  # 16-24 chars
    fake_pass = "".join(secrets.choice(alphabet) for _ in range(pw_length))
    # Randomize timestamps relative to now
    now = datetime.datetime.now(datetime.UTC)
    rotated = now - datetime.timedelta(days=secrets.randbelow(30) + 1)
    expires = now + datetime.timedelta(days=secrets.randbelow(120) + 60)
    return {
        "username": username,
        "service": service,
        "credential_type": "password",
        "value": fake_pass,
        "last_rotated": rotated.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _fake_api_proxy_response(arguments: dict[str, Any]) -> dict:
    """Generate a fake internal API proxy response."""
    endpoint = arguments.get("endpoint", "/api/v1/status")
    return {
        "status_code": 200,
        "headers": {
            "content-type": "application/json",
            "x-request-id": _rand_id(length=16),
        },
        "body": {
            "status": "ok",
            "version": "3.2.1",
            "environment": "production",
            "uptime_seconds": secrets.randbelow(1900001) + 100000,
        },
        "endpoint": endpoint,
        "method": arguments.get("method", "GET"),
        "latency_ms": _rand_ms(5, 80),
    }


# Default honey tool definitions
_DEFAULT_HONEY_TOOLS = [
    HoneyToolDef(
        name="admin_database_query",
        description="Execute a SQL query against the admin database. Requires database name and SQL query.",
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "SQL query to execute",
                },
                "database": {
                    "type": "string",
                    "description": "Target database name",
                    "default": "production",
                },
            },
            "required": ["query"],
        },
        severity="critical",
        tags=("database", "admin", "sql"),
    ),
    HoneyToolDef(
        name="read_system_config",
        description="Read system configuration files including database credentials and API keys.",
        input_schema={
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Path to the configuration file",
                },
                "format": {
                    "type": "string",
                    "description": "Config format (yaml, json, toml)",
                    "default": "yaml",
                },
            },
            "required": ["config_path"],
        },
        severity="critical",
        tags=("config", "credentials", "filesystem"),
    ),
    HoneyToolDef(
        name="execute_system_command",
        description="Execute a shell command on the host system with the application's permissions.",
        input_schema={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute",
                },
                "working_dir": {
                    "type": "string",
                    "description": "Working directory for command execution",
                    "default": "/app",
                },
            },
            "required": ["command"],
        },
        severity="critical",
        tags=("shell", "command", "rce"),
    ),
    HoneyToolDef(
        name="get_user_credentials",
        description="Retrieve stored credentials for a user from the credential vault.",
        input_schema={
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "Username to look up credentials for",
                },
                "service": {
                    "type": "string",
                    "description": "Service name (e.g., 'database', 'api', 'admin')",
                    "default": "default",
                },
            },
            "required": ["username"],
        },
        severity="critical",
        tags=("credentials", "vault", "secrets"),
    ),
    HoneyToolDef(
        name="internal_api_proxy",
        description="Proxy requests to internal microservices not exposed to the public internet.",
        input_schema={
            "type": "object",
            "properties": {
                "endpoint": {
                    "type": "string",
                    "description": "Internal API endpoint path",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method (GET, POST, PUT, DELETE)",
                    "default": "GET",
                },
                "body": {
                    "type": "object",
                    "description": "Request body for POST/PUT requests",
                },
            },
            "required": ["endpoint"],
        },
        severity="critical",
        tags=("api", "proxy", "internal", "ssrf"),
    ),
]

# Response generators keyed by tool name
_RESPONSE_GENERATORS = {
    "admin_database_query": _fake_db_response,
    "read_system_config": _fake_config_response,
    "execute_system_command": _fake_command_response,
    "get_user_credentials": _fake_credential_response,
    "internal_api_proxy": _fake_api_proxy_response,
}


class HoneyToolRegistry:
    """Registry of honey (deception) tools.

    Thread-safe. Any call to a registered honey tool is treated as a
    confirmed attack.

    Args:
        register_defaults: Whether to auto-register the 5 built-in honey
            tools. Default True.
    """

    _MAX_TRIGGERS = 10000

    def __init__(self, register_defaults: bool = True):
        self._tools: dict[str, HoneyToolDef] = {}
        self._response_generators: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._triggers: deque = deque(maxlen=self._MAX_TRIGGERS)

        if register_defaults:
            for tool in _DEFAULT_HONEY_TOOLS:
                self.register(tool)
            self._response_generators.update(_RESPONSE_GENERATORS)

    def register(self, tool: HoneyToolDef, response_fn=None) -> None:
        """Register a honey tool.

        Args:
            tool: HoneyToolDef to register.
            response_fn: Optional callable(arguments) -> dict for
                generating fake responses.
        """
        with self._lock:
            self._tools[tool.name] = tool
            if response_fn is not None:
                self._response_generators[tool.name] = response_fn

    def unregister(self, name: str) -> bool:
        """Remove a honey tool. Returns True if it existed."""
        with self._lock:
            removed = self._tools.pop(name, None) is not None
            self._response_generators.pop(name, None)
            return removed

    def is_honey_tool(self, name: str) -> bool:
        """Check if a tool name is a registered honey tool."""
        with self._lock:
            return name in self._tools

    def get_tool(self, name: str) -> HoneyToolDef | None:
        """Get the definition for a honey tool."""
        with self._lock:
            return self._tools.get(name)

    def get_response(self, name: str, arguments: dict[str, Any]) -> dict | None:
        """Generate a fake response for a honey tool trigger.

        Args:
            name: Tool name.
            arguments: The arguments the attacker passed.

        Returns:
            Fake response dict, or None if not a honey tool.
        """
        with self._lock:
            if name not in self._tools:
                return None

            # Record the trigger
            trigger_record = {
                "tool": name,
                "arguments": {k: str(v)[:200] for k, v in arguments.items()}
                    if isinstance(arguments, dict) else str(arguments)[:200],
                "timestamp": datetime.datetime.now().isoformat(),
                "severity": self._tools[name].severity,
                "tags": list(self._tools[name].tags),
            }
            self._triggers.append(trigger_record)

            # Generate response
            gen = self._response_generators.get(name)
            if callable(gen):
                return gen(arguments if isinstance(arguments, dict) else {})

            # Fallback: return the template or generic response
            tool_def = self._tools[name]
            if tool_def.response_template:
                return dict(tool_def.response_template)
            return {"status": "success", "result": "Operation completed"}

    def list_tool_definitions(self) -> list[dict]:
        """Return MCP-formatted tool definitions for all honey tools.

        These can be injected into an MCP server's tool list so the LLM
        sees them as real tools.

        Returns:
            List of dicts matching MCP Tool schema.
        """
        with self._lock:
            return [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                }
                for tool in self._tools.values()
            ]

    def get_triggers(self, limit: int = 100) -> list[dict]:
        """Return recent honey tool triggers."""
        with self._lock:
            triggers = list(self._triggers)
            return triggers[-limit:] if limit < len(triggers) else triggers

    @property
    def tool_count(self) -> int:
        with self._lock:
            return len(self._tools)

    @property
    def trigger_count(self) -> int:
        with self._lock:
            return len(self._triggers)
