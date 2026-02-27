"""
Sentinel - MCP Guard
==============================
Runtime interception and validation of MCP (Model Context Protocol) tool
calls.  Analogous to the Shield class but for tool calls rather than
chat messages.

The guard runs a 7-step pipeline on every tool call:

    1. Policy check   (reuses agent_policy.PolicyValidator)
    2. Honey tool check (mcp_honey.HoneyToolRegistry)
    3. Argument sanitization (reuses sanitizer.sanitize_input)
    4. Argument scanning (mcp_scanner.scan_mcp_arguments)
    5. Prompt injection check in args (config.py patterns via scanner)
    6. Session update  (session.SessionManager.update_mcp)
    7. Rate limit check (rate_limiter.RateLimiter)

Usage:
    from sentinel.mcp_guard import MCPGuard

    guard = MCPGuard()
    result = guard.intercept("execute_code", {"code": "rm -rf /"}, session_id="s1")
    if not result.allowed:
        print(result.blocked_reason)
"""

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import config
from .frameworks import build_threat_mapping, DETECTION_TO_OWASP_AGENTIC

log = logging.getLogger(__name__)


@dataclass
class MCPGuardResult:
    """Result of an MCPGuard interception."""
    allowed: bool
    tool_name: str
    blocked_reason: Optional[str] = None
    severity: str = "none"
    findings: list = field(default_factory=list)
    honey_triggered: bool = False
    honey_response: Optional[dict] = None
    sanitized_arguments: Optional[dict] = None
    threat_mapping: Optional[dict] = None
    message_path: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "tool_name": self.tool_name,
            "blocked_reason": self.blocked_reason,
            "severity": self.severity,
            "findings": [
                f.to_dict() if hasattr(f, "to_dict") else f
                for f in self.findings
            ],
            "honey_triggered": self.honey_triggered,
            "honey_response": self.honey_response,
            "sanitized_arguments": self.sanitized_arguments,
            "threat_mapping": self.threat_mapping,
            "message_path": self.message_path,
        }


class MCPGuard:
    """
    Runtime guard for MCP tool calls.

    Validates tool calls through a 7-step pipeline before they reach
    the actual tool implementation.

    All constructor arguments are optional.  When shared with a Shield
    instance (same session_manager, rate_limiter) the two layers can
    correlate chat-level and tool-level attacks for faster escalation.

    Args:
        policy_validator: PolicyValidator instance for allowlist/denylist.
        session_manager: SessionManager for cross-layer session state.
        rate_limiter: RateLimiter for per-session tool call limits.
        honey_tools: HoneyToolRegistry for deception tools.
        webhook_manager: WebhookManager for notifications.
        cef_logger: CEFLogger for SIEM integration.
    """

    def __init__(
        self,
        policy_validator=None,
        session_manager=None,
        rate_limiter=None,
        honey_tools=None,
        webhook_manager=None,
        cef_logger=None,
        storage_backend=None,
    ):
        self.policy_validator = policy_validator
        self.session_manager = session_manager
        self.rate_limiter = rate_limiter
        self.webhook_manager = webhook_manager
        self.cef_logger = cef_logger
        self.storage_backend = storage_backend

        # Lazily import honey tools to avoid circular imports
        if honey_tools is not None:
            self.honey_tools = honey_tools
        elif config.MCP_HONEY_TOOLS_ENABLED:
            from .mcp_honey import HoneyToolRegistry
            self.honey_tools = HoneyToolRegistry()
        else:
            self.honey_tools = None

        # Metrics
        self._metrics = {
            "total": 0,
            "allowed": 0,
            "blocked": 0,
            "honey_triggers": 0,
            "by_category": {},
        }
        self._metrics_lock = threading.Lock()

    def intercept(
        self,
        tool_name: str,
        arguments: Any,
        session_id: str = "default",
        source_ip: str = "127.0.0.1",
        delegation_depth: int = 0,
        call_count: int = 0,
    ) -> MCPGuardResult:
        """
        Intercept and validate an MCP tool call.

        Args:
            tool_name: Name of the tool being called.
            arguments: The tool arguments (dict, list, or primitive).
            session_id: Session identifier for tracking.
            source_ip: Client IP address.
            delegation_depth: Current delegation nesting depth.
            call_count: Number of tool calls made this turn.

        Returns:
            MCPGuardResult with allowed status and findings.
        """
        if not config.MCP_ENABLED:
            return MCPGuardResult(
                allowed=True,
                tool_name=tool_name,
                message_path=["mcp_disabled"],
            )

        message_path = ["mcp_guard"]
        findings = []

        # --- Step 1: Policy Check ---
        message_path.append("policy_check")
        if self.policy_validator is not None:
            allowed, reason = self.policy_validator.validate_tool_call(
                tool_name, depth=delegation_depth, call_count=call_count,
            )
            if not allowed:
                result = MCPGuardResult(
                    allowed=False,
                    tool_name=tool_name,
                    blocked_reason=f"policy: {reason}",
                    severity="high",
                    message_path=message_path,
                )
                self._post_intercept(
                    result, session_id, source_ip, arguments, findings,
                )
                return result

        # --- Step 2: Honey Tool Check ---
        message_path.append("honey_check")
        if self.honey_tools is not None and self.honey_tools.is_honey_tool(tool_name):
            honey_response = self.honey_tools.get_response(tool_name, arguments or {})
            tool_def = self.honey_tools.get_tool(tool_name)

            # Build threat mapping for honey trigger
            threat_mapping = self._build_mcp_threat_mapping("mcp_honey_triggered")

            result = MCPGuardResult(
                allowed=False,
                tool_name=tool_name,
                blocked_reason="honey_tool_triggered",
                severity="critical",
                honey_triggered=True,
                honey_response=honey_response,
                threat_mapping=threat_mapping,
                message_path=message_path,
            )
            self._post_intercept(
                result, session_id, source_ip, arguments, findings,
                honey_triggered=True,
            )
            return result

        # --- Step 3: Argument Scanning (on RAW arguments, before sanitization) ---
        # IMPORTANT: Scan raw arguments first so the sanitizer cannot
        # strip attack payloads before the scanner sees them.
        message_path.append("arg_scan")
        from .mcp_scanner import scan_mcp_arguments
        findings = scan_mcp_arguments(tool_name, arguments)

        # --- Step 4: Argument Sanitization (for pass-through to real tool) ---
        message_path.append("arg_sanitize")
        sanitized_arguments = self._sanitize_arguments(arguments)

        # --- Step 5: Prompt injection already covered by scanner ---
        # (scan_prompt_injection is called within scan_mcp_arguments)

        # --- Step 6: Session Update (delegated to _post_intercept) ---

        # --- Step 7: Rate Limit Check ---
        message_path.append("rate_limit")
        if self.rate_limiter is not None:
            # Use a tool-specific rate limit key
            rate_key = f"mcp:{session_id}"
            if not self.rate_limiter.check(rate_key):
                result = MCPGuardResult(
                    allowed=False,
                    tool_name=tool_name,
                    blocked_reason="rate_limit_exceeded",
                    severity="medium",
                    findings=[f.to_dict() for f in findings] if findings else [],
                    sanitized_arguments=sanitized_arguments,
                    message_path=message_path,
                )
                self._post_intercept(
                    result, session_id, source_ip, arguments, findings,
                )
                return result

        # --- Decision: block or allow based on finding severity ---
        max_severity = self._max_severity(findings)
        blocked = False
        blocked_reason = None

        if max_severity == "critical" and config.MCP_BLOCK_ON_CRITICAL:
            blocked = True
            blocked_reason = self._block_reason(findings, "critical")
        elif max_severity == "high" and config.MCP_BLOCK_ON_HIGH:
            blocked = True
            blocked_reason = self._block_reason(findings, "high")

        # Build threat mapping from findings
        threat_mapping = None
        if findings:
            primary_category = findings[0].category
            detection_key = f"mcp_{primary_category}"
            threat_mapping = self._build_mcp_threat_mapping(detection_key)

        result = MCPGuardResult(
            allowed=not blocked,
            tool_name=tool_name,
            blocked_reason=blocked_reason,
            severity=max_severity,
            findings=[f.to_dict() for f in findings],
            sanitized_arguments=sanitized_arguments if not blocked else None,
            threat_mapping=threat_mapping,
            message_path=message_path,
        )

        self._post_intercept(
            result, session_id, source_ip, arguments, findings,
        )
        return result

    def _sanitize_arguments(self, arguments: Any, _depth: int = 0) -> Any:
        """Recursively sanitize string values in arguments.

        Has a depth limit matching config.MCP_MAX_ARGUMENT_DEPTH to
        prevent stack overflow on deeply nested payloads.
        """
        if _depth > config.MCP_MAX_ARGUMENT_DEPTH:
            return arguments  # Stop recursing, return as-is

        from .sanitizer import sanitize_input

        if isinstance(arguments, dict):
            result = {}
            for k, v in arguments.items():
                result[k] = self._sanitize_arguments(v, _depth + 1)
            return result
        elif isinstance(arguments, (list, tuple)):
            return [self._sanitize_arguments(item, _depth + 1) for item in arguments]
        elif isinstance(arguments, str):
            sanitized, _ = sanitize_input(arguments)
            return sanitized
        return arguments

    def _max_severity(self, findings) -> str:
        """Return the highest severity among findings."""
        _ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        if not findings:
            return "none"
        max_sev = "none"
        for f in findings:
            sev = f.severity if hasattr(f, "severity") else f.get("severity", "none")
            if _ORDER.get(sev, 0) > _ORDER.get(max_sev, 0):
                max_sev = sev
        return max_sev

    def _block_reason(self, findings, min_severity: str) -> str:
        """Build a block reason string from findings at or above min_severity."""
        _ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        min_ord = _ORDER.get(min_severity, 0)
        reasons = []
        for f in findings:
            sev = f.severity if hasattr(f, "severity") else f.get("severity", "none")
            if _ORDER.get(sev, 0) >= min_ord:
                cat = f.category if hasattr(f, "category") else f.get("category", "unknown")
                msg = f.message if hasattr(f, "message") else f.get("message", "")
                reasons.append(f"{cat}: {msg}")
        return "; ".join(reasons[:3])  # Limit to 3 reasons

    def _build_mcp_threat_mapping(self, detection_key: str) -> dict:
        """Build threat mapping for an MCP finding category."""
        mapping = build_threat_mapping(
            detection_method=detection_key,
            category=detection_key,
        )
        # Ensure agentic mappings are populated
        agentic = DETECTION_TO_OWASP_AGENTIC.get(detection_key, [])
        if agentic:
            existing = set(mapping.get("owasp_agentic", []))
            existing.update(agentic)
            mapping["owasp_agentic"] = sorted(existing)
        return mapping

    def _post_intercept(
        self, result, session_id, source_ip, arguments, findings,
        honey_triggered=False,
    ):
        """Post-interception: storage, session update, CEF logging, webhooks, metrics."""
        # Persist MCP event to storage backend
        if self.storage_backend is not None:
            try:
                self.storage_backend.log_mcp_event({
                    "session_id": session_id,
                    "tool_name": result.tool_name,
                    "allowed": result.allowed,
                    "blocked_reason": result.blocked_reason,
                    "severity": result.severity,
                    "findings": [
                        f.to_dict() if hasattr(f, "to_dict") else f
                        for f in findings
                    ] if findings else [],
                    "honey_triggered": honey_triggered,
                    "source_ip": source_ip,
                })
            except Exception as e:
                log.warning("MCP storage logging failed: %s", e)

        # Session update
        if self.session_manager is not None:
            self.session_manager.update_mcp(
                session_id=session_id,
                tool_name=result.tool_name,
                blocked=not result.allowed,
                findings=findings,
                source_ip=source_ip,
                honey_triggered=honey_triggered,
            )

        # CEF logging
        if self.cef_logger is not None and (not result.allowed or findings):
            args_preview = str(arguments)[:200] if arguments else ""
            self.cef_logger.log_mcp_event(
                tool_name=result.tool_name,
                arguments_preview=args_preview,
                session_id=session_id,
                source_ip=source_ip,
                guard_result=result,
            )

        # Webhook notifications
        if self.webhook_manager is not None and not result.allowed:
            try:
                self.webhook_manager.notify_detection(
                    result.to_dict(),
                    session_id=session_id,
                    source_ip=source_ip,
                    user_input=f"[MCP:{result.tool_name}] {str(arguments)[:200]}",
                )
            except Exception as e:
                log.warning("MCP webhook notification failed: %s", e)

        # Update metrics
        with self._metrics_lock:
            self._metrics["total"] += 1
            if result.allowed:
                self._metrics["allowed"] += 1
            else:
                self._metrics["blocked"] += 1
            if honey_triggered:
                self._metrics["honey_triggers"] += 1
            for f in findings:
                cat = f.category if hasattr(f, "category") else f.get("category", "unknown")
                self._metrics["by_category"][cat] = (
                    self._metrics["by_category"].get(cat, 0) + 1
                )

    @property
    def metrics(self) -> dict:
        """Return a copy of current metrics."""
        with self._metrics_lock:
            return dict(self._metrics)
