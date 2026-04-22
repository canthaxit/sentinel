"""
Sentinel - MCP Integration Layer
==========================================
Provides integration with MCP SDK servers and a standalone validation
function that works without any MCP dependency.

Usage (standalone, no MCP SDK needed):
    from sentinel.mcp_integration import validate_tool_call

    result = validate_tool_call("run_query", {"sql": "DROP TABLE users"})
    if not result.allowed:
        print(result.blocked_reason)

Usage (with MCP SDK):
    from mcp.server import Server
    from sentinel.mcp_integration import create_guarded_mcp_server

    server = Server("my-server")
    guarded = create_guarded_mcp_server(server, guard)
"""

import logging
import threading
from typing import Any

log = logging.getLogger(__name__)

_default_guard = None
_default_guard_lock = threading.Lock()


def _get_default_guard():
    """Lazy singleton for the default MCPGuard instance.

    Thread-safe initialization.
    """
    global _default_guard
    if _default_guard is not None:
        return _default_guard

    with _default_guard_lock:
        if _default_guard is not None:
            return _default_guard

        from .mcp_guard import MCPGuard
        from .rate_limiter import RateLimiter
        from .session import SessionManager

        _default_guard = MCPGuard(
            session_manager=SessionManager(),
            rate_limiter=RateLimiter(),
        )
        return _default_guard


def validate_tool_call(
    tool_name: str,
    arguments: Any,
    guard=None,
    session_id: str = "default",
    source_ip: str = "127.0.0.1",
    delegation_depth: int = 0,
    call_count: int = 0,
):
    """
    Validate an MCP tool call without requiring the MCP SDK.

    This is the primary entry point for standalone usage. Works with
    any MCP-compatible system, custom tool routers, or direct testing.

    Args:
        tool_name: Name of the tool being called.
        arguments: The tool arguments (dict, list, or primitive).
        guard: Optional MCPGuard instance. Uses singleton if not provided.
        session_id: Session identifier for tracking.
        source_ip: Client IP address.
        delegation_depth: Current delegation nesting depth.
        call_count: Number of tool calls made this turn.

    Returns:
        MCPGuardResult with allowed status and findings.
    """
    if guard is None:
        guard = _get_default_guard()

    return guard.intercept(
        tool_name=tool_name,
        arguments=arguments,
        session_id=session_id,
        source_ip=source_ip,
        delegation_depth=delegation_depth,
        call_count=call_count,
    )


def create_guarded_mcp_server(server, guard=None):
    """
    Wrap an MCP Server instance with Sentinel protection.

    Intercepts tool calls to validate them before execution and injects
    honey tool definitions into the server's tool list.

    Args:
        server: An mcp.server.Server instance.
        guard: Optional MCPGuard instance. Uses singleton if not provided.

    Returns:
        The same server instance, now guarded. Tool calls are intercepted
        before reaching their handlers.

    Raises:
        ImportError: If the mcp package is not installed.
    """
    if guard is None:
        guard = _get_default_guard()

    # Idempotency: don't double-wrap
    if getattr(server, "_sentinel_guarded", False):
        log.warning("Server already guarded, skipping duplicate wrapping")
        return server

    # Save original handlers
    _original_call_tool = getattr(server, "_call_tool_handler", None)
    _original_list_tools = getattr(server, "_list_tools_handler", None)

    async def _guarded_call_tool(name, arguments, **kwargs):
        """Intercept tool calls for validation."""
        session_id = kwargs.get("session_id", "mcp_default")
        source_ip = kwargs.get("source_ip", "127.0.0.1")

        result = guard.intercept(
            tool_name=name,
            arguments=arguments,
            session_id=session_id,
            source_ip=source_ip,
        )

        if not result.allowed:
            if result.honey_triggered and result.honey_response:
                # Return the fake response for honey tools
                return result.honey_response
            # Return a generic denial
            return {
                "error": "Tool call blocked by security policy",
                "reason": result.blocked_reason,
            }

        # Pass sanitized arguments to the real handler
        actual_args = result.sanitized_arguments or arguments
        if _original_call_tool is not None:
            return await _original_call_tool(name, actual_args, **kwargs)
        return {"error": f"No handler for tool '{name}'"}

    async def _guarded_list_tools(**kwargs):
        """Inject honey tools into the tool list."""
        tools = []
        if _original_list_tools is not None:
            tools = await _original_list_tools(**kwargs)
            if not isinstance(tools, list):
                tools = list(tools) if tools else []

        # Inject honey tool definitions
        if guard.honey_tools is not None:
            honey_defs = guard.honey_tools.list_tool_definitions()
            tools.extend(honey_defs)

        return tools

    # Replace handlers
    if _original_call_tool is not None:
        server._call_tool_handler = _guarded_call_tool
    if _original_list_tools is not None:
        server._list_tools_handler = _guarded_list_tools

    server._sentinel_guarded = True
    log.info("MCP server guarded with Sentinel")
    return server
