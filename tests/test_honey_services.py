#!/usr/bin/env python3
"""
Tests for sentinel.honey_services - Network honey service deception layer.
"""

import socket
import threading
import time

import pytest

from sentinel.honey_services import (
    HoneyHTTPService,
    HoneyServiceConfig,
    HoneyServiceRegistry,
)


class TestHoneyServiceConfig:
    def test_basic_creation(self):
        cfg = HoneyServiceConfig(
            name="test-http",
            port=19080,
            protocol="http",
            banner="TestServer/1.0",
            responses={"/": "<h1>Hello</h1>", "default": "404"},
        )
        assert cfg.name == "test-http"
        assert cfg.port == 19080
        assert cfg.protocol == "http"
        assert cfg.banner == "TestServer/1.0"
        assert "/" in cfg.responses

    def test_defaults(self):
        cfg = HoneyServiceConfig(name="minimal", port=19081)
        assert cfg.protocol == "http"
        assert cfg.banner == ""
        assert cfg.responses == {}


class TestHoneyHTTPService:
    def test_start_stop(self):
        cfg = HoneyServiceConfig(name="test-svc", port=19180)
        svc = HoneyHTTPService(cfg)
        assert not svc.is_running
        svc.start()
        time.sleep(0.2)
        assert svc.is_running
        svc.stop()
        time.sleep(0.1)
        assert not svc.is_running

    def test_serves_response(self):
        cfg = HoneyServiceConfig(
            name="test-serve",
            port=19181,
            banner="TestBanner/2.0",
            responses={"/": "<h1>Honey</h1>", "default": "Not Found"},
        )
        svc = HoneyHTTPService(cfg)
        svc.start()
        time.sleep(0.2)
        try:
            sock = socket.create_connection(("127.0.0.1", 19181), timeout=3)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()

            text = response.decode("utf-8", errors="replace")
            assert "200 OK" in text
            assert "<h1>Honey</h1>" in text
            assert "TestBanner/2.0" in text
        finally:
            svc.stop()

    def test_trigger_callback_fires(self):
        events = []
        cfg = HoneyServiceConfig(name="test-trigger", port=19182)
        svc = HoneyHTTPService(cfg, trigger_callback=lambda e: events.append(e))
        svc.start()
        time.sleep(0.2)
        try:
            sock = socket.create_connection(("127.0.0.1", 19182), timeout=3)
            sock.sendall(b"GET /probe HTTP/1.1\r\nHost: localhost\r\n\r\n")
            sock.recv(4096)
            sock.close()
            time.sleep(0.3)

            assert len(events) >= 1
            assert events[0]["service"] == "test-trigger"
            assert events[0]["path"] == "/probe"
            assert events[0]["source_ip"] == "127.0.0.1"
        finally:
            svc.stop()

    def test_double_start_is_noop(self):
        cfg = HoneyServiceConfig(name="test-double", port=19183)
        svc = HoneyHTTPService(cfg)
        svc.start()
        time.sleep(0.1)
        svc.start()  # Should not raise or start a second server
        assert svc.is_running
        svc.stop()


class TestHoneyServiceRegistry:
    def test_start_and_stop_service(self):
        registry = HoneyServiceRegistry()
        cfg = HoneyServiceConfig(name="reg-test", port=19280)
        registry.start_service(cfg)
        assert registry.service_count == 1
        time.sleep(0.2)

        services = registry.list_services()
        assert len(services) == 1
        assert services[0]["name"] == "reg-test"
        assert services[0]["running"] is True

        assert registry.stop_service("reg-test") is True
        assert registry.service_count == 0
        assert registry.stop_service("nonexistent") is False

    def test_duplicate_service_raises(self):
        registry = HoneyServiceRegistry()
        cfg = HoneyServiceConfig(name="dup-test", port=19281)
        registry.start_service(cfg)
        time.sleep(0.1)
        try:
            with pytest.raises(ValueError, match="already registered"):
                registry.start_service(cfg)
        finally:
            registry.stop_all()

    def test_trigger_recording(self):
        registry = HoneyServiceRegistry()
        cfg = HoneyServiceConfig(name="trig-rec", port=19282)
        registry.start_service(cfg)
        time.sleep(0.2)
        try:
            sock = socket.create_connection(("127.0.0.1", 19282), timeout=3)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            sock.recv(4096)
            sock.close()
            time.sleep(0.3)

            assert registry.trigger_count >= 1
            triggers = registry.get_triggers()
            assert triggers[0]["service"] == "trig-rec"
        finally:
            registry.stop_all()

    def test_stop_all(self):
        registry = HoneyServiceRegistry()
        for i in range(3):
            cfg = HoneyServiceConfig(name=f"bulk-{i}", port=19290 + i)
            registry.start_service(cfg)
        time.sleep(0.2)
        assert registry.service_count == 3
        registry.stop_all()
        assert registry.service_count == 0


class TestTopologyGeneration:
    def test_enterprise_topology(self):
        configs = HoneyServiceRegistry.generate_topology("enterprise")
        assert len(configs) >= 3
        names = [c.name for c in configs]
        assert "admin-panel-http" in names
        for cfg in configs:
            assert isinstance(cfg, HoneyServiceConfig)
            assert cfg.port > 0
            assert cfg.protocol == "http"
            assert len(cfg.responses) > 0

    def test_ics_scada_topology(self):
        configs = HoneyServiceRegistry.generate_topology("ics_scada")
        assert len(configs) >= 3
        names = [c.name for c in configs]
        assert "hmi-web-panel" in names
        for cfg in configs:
            assert isinstance(cfg, HoneyServiceConfig)
            assert cfg.port > 0

    def test_unknown_profile_raises(self):
        with pytest.raises(ValueError, match="Unknown profile"):
            HoneyServiceRegistry.generate_topology("nonexistent")
