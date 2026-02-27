#!/usr/bin/env python3
"""
Tests for sentinel.mcp_honey - Honey tool deception layer.
"""

import pytest

from sentinel.mcp_honey import (
    HoneyToolDef,
    HoneyToolRegistry,
)


class TestHoneyToolDef:
    def test_frozen_dataclass(self):
        tool = HoneyToolDef(
            name="test_tool",
            description="A test tool",
            input_schema={"type": "object"},
            severity="critical",
            tags=("test",),
        )
        assert tool.name == "test_tool"
        assert tool.severity == "critical"
        # Should be frozen
        with pytest.raises(AttributeError):
            tool.name = "changed"


class TestHoneyToolRegistry:
    def test_defaults_registered(self):
        registry = HoneyToolRegistry()
        assert registry.tool_count == 5
        assert registry.is_honey_tool("admin_database_query")
        assert registry.is_honey_tool("read_system_config")
        assert registry.is_honey_tool("execute_system_command")
        assert registry.is_honey_tool("get_user_credentials")
        assert registry.is_honey_tool("internal_api_proxy")

    def test_no_defaults(self):
        registry = HoneyToolRegistry(register_defaults=False)
        assert registry.tool_count == 0

    def test_is_honey_tool_false_for_real_tools(self):
        registry = HoneyToolRegistry()
        assert not registry.is_honey_tool("search")
        assert not registry.is_honey_tool("calculator")
        assert not registry.is_honey_tool("send_email")

    def test_register_custom_tool(self):
        registry = HoneyToolRegistry(register_defaults=False)
        custom = HoneyToolDef(
            name="secret_admin_panel",
            description="Access the secret admin panel",
            input_schema={"type": "object", "properties": {"action": {"type": "string"}}},
            severity="critical",
            tags=("admin", "custom"),
        )
        registry.register(custom)
        assert registry.is_honey_tool("secret_admin_panel")
        assert registry.tool_count == 1

    def test_unregister(self):
        registry = HoneyToolRegistry()
        assert registry.is_honey_tool("admin_database_query")
        removed = registry.unregister("admin_database_query")
        assert removed is True
        assert not registry.is_honey_tool("admin_database_query")
        # Unregister non-existent
        assert registry.unregister("nonexistent") is False

    def test_get_tool(self):
        registry = HoneyToolRegistry()
        tool = registry.get_tool("admin_database_query")
        assert tool is not None
        assert tool.name == "admin_database_query"
        assert tool.severity == "critical"

    def test_get_tool_none_for_missing(self):
        registry = HoneyToolRegistry()
        assert registry.get_tool("nonexistent") is None


class TestHoneyToolResponses:
    def test_database_query_response(self):
        registry = HoneyToolRegistry()
        response = registry.get_response("admin_database_query", {"query": "SELECT * FROM users"})
        assert response is not None
        assert response["status"] == "success"
        assert "data" in response
        assert len(response["data"]) > 0

    def test_system_config_response(self):
        registry = HoneyToolRegistry()
        response = registry.get_response("read_system_config", {"config_path": "/etc/app.yaml"})
        assert response is not None
        assert "content" in response
        assert "database" in response["content"]

    def test_command_response(self):
        registry = HoneyToolRegistry()
        response = registry.get_response("execute_system_command", {"command": "whoami"})
        assert response is not None
        assert response["exit_code"] == 0
        assert "stdout" in response

    def test_credential_response(self):
        registry = HoneyToolRegistry()
        response = registry.get_response("get_user_credentials", {"username": "admin"})
        assert response is not None
        assert response["username"] == "admin"
        assert len(response["value"]) >= 16  # Random password, no identifiable prefix

    def test_api_proxy_response(self):
        registry = HoneyToolRegistry()
        response = registry.get_response("internal_api_proxy", {"endpoint": "/api/status"})
        assert response is not None
        assert response["status_code"] == 200

    def test_non_honey_returns_none(self):
        registry = HoneyToolRegistry()
        response = registry.get_response("real_search_tool", {"query": "test"})
        assert response is None

    def test_custom_response_generator(self):
        registry = HoneyToolRegistry(register_defaults=False)
        tool = HoneyToolDef(
            name="custom_tool",
            description="Custom",
            input_schema={"type": "object"},
        )
        registry.register(tool, response_fn=lambda args: {"custom": True, "arg": args.get("x")})
        response = registry.get_response("custom_tool", {"x": 42})
        assert response["custom"] is True
        assert response["arg"] == 42


class TestHoneyToolMCPFormat:
    def test_list_tool_definitions(self):
        registry = HoneyToolRegistry()
        defs = registry.list_tool_definitions()
        assert len(defs) == 5
        for d in defs:
            assert "name" in d
            assert "description" in d
            assert "inputSchema" in d

    def test_tool_definition_format(self):
        registry = HoneyToolRegistry()
        defs = registry.list_tool_definitions()
        db_tool = next(d for d in defs if d["name"] == "admin_database_query")
        assert "query" in db_tool["inputSchema"]["properties"]


class TestHoneyToolTriggers:
    def test_trigger_recorded(self):
        registry = HoneyToolRegistry()
        assert registry.trigger_count == 0

        registry.get_response("admin_database_query", {"query": "SELECT 1"})
        assert registry.trigger_count == 1

        triggers = registry.get_triggers()
        assert len(triggers) == 1
        assert triggers[0]["tool"] == "admin_database_query"
        assert "timestamp" in triggers[0]
        assert triggers[0]["severity"] == "critical"

    def test_multiple_triggers(self):
        registry = HoneyToolRegistry()
        registry.get_response("admin_database_query", {"query": "q1"})
        registry.get_response("execute_system_command", {"command": "whoami"})
        registry.get_response("get_user_credentials", {"username": "root"})

        assert registry.trigger_count == 3
        triggers = registry.get_triggers()
        tools = [t["tool"] for t in triggers]
        assert "admin_database_query" in tools
        assert "execute_system_command" in tools
        assert "get_user_credentials" in tools
