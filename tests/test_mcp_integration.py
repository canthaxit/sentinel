#!/usr/bin/env python3
"""
Tests for sentinel.mcp_integration - MCP integration layer.
"""

import threading
import pytest

from sentinel.mcp_integration import (
    validate_tool_call,
    _get_default_guard,
)
from sentinel.mcp_guard import MCPGuard, MCPGuardResult


class TestValidateToolCall:
    def test_benign_call_passes(self):
        result = validate_tool_call("search", {"query": "hello world"})
        assert result.allowed
        assert isinstance(result, MCPGuardResult)

    def test_malicious_call_blocked(self):
        result = validate_tool_call("execute", {"cmd": "rm -rf /"})
        assert not result.allowed

    def test_with_custom_guard(self):
        guard = MCPGuard()
        result = validate_tool_call(
            "search", {"query": "test"}, guard=guard,
        )
        assert result.allowed

    def test_session_id_passed(self):
        from sentinel.session import SessionManager
        sm = SessionManager()
        guard = MCPGuard(session_manager=sm)

        validate_tool_call(
            "search", {"query": "test"}, guard=guard,
            session_id="my_session",
        )

        session = sm.get("my_session")
        assert session["mcp_tool_calls"] == 1

    def test_honey_tool_detected(self):
        result = validate_tool_call(
            "admin_database_query",
            {"query": "SELECT * FROM users"},
        )
        assert not result.allowed
        assert result.honey_triggered

    def test_source_ip_passed(self):
        from sentinel.session import SessionManager
        sm = SessionManager()
        guard = MCPGuard(session_manager=sm)

        validate_tool_call(
            "search", {"query": "test"}, guard=guard,
            session_id="ip_test", source_ip="10.0.0.1",
        )

        session = sm.get("ip_test")
        assert session["source_ip"] == "10.0.0.1"


class TestDefaultGuardSingleton:
    def test_singleton_returns_same_instance(self):
        g1 = _get_default_guard()
        g2 = _get_default_guard()
        assert g1 is g2

    def test_singleton_is_mcpguard(self):
        guard = _get_default_guard()
        assert isinstance(guard, MCPGuard)

    def test_singleton_thread_safe(self):
        guards = []
        errors = []

        def worker():
            try:
                g = _get_default_guard()
                guards.append(g)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # All should be the same instance
        assert all(g is guards[0] for g in guards)


class TestGuardedMCPServer:
    """Test create_guarded_mcp_server with a mock server object."""

    def test_guarded_server_setup(self):
        """Test that guarding a mock server works without MCP SDK."""

        class MockServer:
            def __init__(self):
                self._call_tool_handler = self._default_call
                self._list_tools_handler = self._default_list

            async def _default_call(self, name, arguments, **kwargs):
                return {"result": f"executed {name}"}

            async def _default_list(self, **kwargs):
                return [{"name": "search", "description": "Search", "inputSchema": {}}]

        from sentinel.mcp_integration import create_guarded_mcp_server

        server = MockServer()
        guard = MCPGuard()
        guarded = create_guarded_mcp_server(server, guard)

        # Should return the same server object
        assert guarded is server
        # Handlers should be replaced
        assert server._call_tool_handler is not MockServer._default_call

    @pytest.mark.asyncio
    async def test_guarded_call_blocks_attack(self):
        """Test that guarded call_tool blocks attacks."""

        class MockServer:
            def __init__(self):
                self._call_tool_handler = self._default_call
                self._list_tools_handler = self._default_list

            async def _default_call(self, name, arguments, **kwargs):
                return {"result": f"executed {name}"}

            async def _default_list(self, **kwargs):
                return []

        from sentinel.mcp_integration import create_guarded_mcp_server

        server = MockServer()
        guard = MCPGuard()
        create_guarded_mcp_server(server, guard)

        result = await server._call_tool_handler("execute", {"cmd": "rm -rf /"})
        assert "error" in result or "blocked" in str(result).lower()

    @pytest.mark.asyncio
    async def test_guarded_list_includes_honey_tools(self):
        """Test that list_tools includes honey tool definitions."""

        class MockServer:
            def __init__(self):
                self._call_tool_handler = self._default_call
                self._list_tools_handler = self._default_list

            async def _default_call(self, name, arguments, **kwargs):
                return {"result": "ok"}

            async def _default_list(self, **kwargs):
                return [{"name": "search", "description": "Search", "inputSchema": {}}]

        from sentinel.mcp_integration import create_guarded_mcp_server

        server = MockServer()
        guard = MCPGuard()
        create_guarded_mcp_server(server, guard)

        tools = await server._list_tools_handler()
        tool_names = [t["name"] for t in tools]

        # Should include the original tool
        assert "search" in tool_names
        # Should include honey tools
        assert "admin_database_query" in tool_names
        assert "execute_system_command" in tool_names
