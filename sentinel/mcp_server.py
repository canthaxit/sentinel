"""
Sentinel - MCP Server
====================================
Stdio-based MCP server that exposes Sentinel's detection pipeline as tools
for LLM clients (Claude Desktop, Cursor, etc.).

Three tools are exposed:

    analyze_message  - run a message through the full Shield pipeline
    scan_output      - scan LLM output for secrets / PII / data leaks
    validate_tool_call - validate a tool call via MCPGuard

Start the server:

    python -m sentinel.mcp_server
    # or via console script:
    sentinel-mcp

Configure in Claude Desktop (claude_desktop_config.json):

    {
      "mcpServers": {
        "sentinel": {
          "command": "sentinel-mcp"
        }
      }
    }
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from typing import Optional

# ---- logging to stderr (stdout is reserved for MCP JSON-RPC) ----
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
log = logging.getLogger("sentinel.mcp_server")

# ---- lazy import of mcp SDK ----
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    raise ImportError(
        "The 'mcp' package is required for the MCP server. "
        "Install it with:  pip install 'sentinel[mcp]'"
    )

# ---- singletons ----
_shield = None
_guard = None
_init_lock = threading.Lock()


def _get_shield():
    """Return or create a singleton Shield(fail_open=False)."""
    global _shield
    if _shield is not None:
        return _shield
    with _init_lock:
        if _shield is not None:
            return _shield
        from sentinel import Shield
        _shield = Shield(fail_open=False)
        log.info("Shield singleton initialised (fail_open=False)")
        return _shield


def _get_guard():
    """Return or create a singleton MCPGuard sharing Shield's managers."""
    global _guard
    if _guard is not None:
        return _guard
    with _init_lock:
        if _guard is not None:
            return _guard
        from sentinel.mcp_guard import MCPGuard as _MCPGuard
        shield = _get_shield()
        _guard = _MCPGuard(
            session_manager=shield.session_manager,
            rate_limiter=shield.rate_limiter,
        )
        log.info("MCPGuard singleton initialised")
        return _guard


# ---- FastMCP server instance ----
mcp = FastMCP(
    "sentinel",
    instructions=(
        "Sentinel is an AI LLM firewall. Use these tools to check whether "
        "a message is a prompt-injection attack, scan LLM output for data "
        "leaks, or validate a tool call before executing it."
    ),
)


# ---- tools ----


_MCP_MAX_INPUT_LENGTH = 10000


@mcp.tool()
def analyze_message(message: str, session_id: str = "mcp_default") -> dict:
    """Analyze a user message for prompt injection, jailbreak, or adversarial attacks.

    Args:
        message: The user message to analyse.
        session_id: Optional session identifier for multi-turn tracking.

    Returns:
        dict with verdict, ml_score, detection_method, threat_mapping, etc.
    """
    if len(message) > _MCP_MAX_INPUT_LENGTH:
        return {
            "verdict": "MALICIOUS",
            "blocked": True,
            "detection_method": "input_length_exceeded",
            "error": f"Input exceeds {_MCP_MAX_INPUT_LENGTH} character limit",
        }
    shield = _get_shield()
    result = shield.analyze(message, session_id=session_id)
    return result.to_dict()


@mcp.tool()
def scan_output(text: str) -> dict:
    """Scan LLM output text for secrets, PII, or other data leaks.

    Args:
        text: The LLM-generated output to scan.

    Returns:
        dict with findings, blocked, block_reason, finding_count.
    """
    shield = _get_shield()
    result = shield.scan_output(text)
    return result.to_dict()


@mcp.tool()
def validate_tool_call(
    tool_name: str,
    arguments: str,
    session_id: str = "mcp_default",
) -> dict:
    """Validate a tool call for command injection, path traversal, SSRF, and other attacks.

    Args:
        tool_name: Name of the tool being called.
        arguments: JSON string of the tool arguments.
        session_id: Optional session identifier for multi-turn tracking.

    Returns:
        dict with allowed, findings, honey_triggered, severity.
    """
    guard = _get_guard()
    try:
        parsed_args = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        parsed_args = {"_raw": arguments}
    result = guard.intercept(tool_name, parsed_args, session_id=session_id)
    return result.to_dict()


# ---- entry point ----


def main():
    """Run the Sentinel MCP server over stdio."""
    log.info("Starting Sentinel MCP server (stdio)")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
