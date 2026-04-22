"""
LiteLLM integration for Sentinel.

Provides a callback class that screens messages through the Shield
detection pipeline before they reach any LLM provider via LiteLLM.

Usage::

    import litellm
    from sentinel import Shield
    from sentinel.litellm import SentinelCallback

    shield = Shield()
    litellm.callbacks = [SentinelCallback(shield, mode="block")]

    # All litellm.completion() calls are now screened
    response = litellm.completion(model="gpt-4o-mini", messages=[...])

Requires ``litellm>=1.40.0`` (install with
``pip install sentinel[litellm]``).
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

# Conditional import -- gracefully degrade when litellm is absent.
try:
    from litellm.integrations.custom_logger import CustomLogger as _LiteLLMBase
except ImportError:
    _LiteLLMBase = object  # type: ignore[assignment,misc]


class ShieldBlockedError(Exception):
    """Raised when Shield blocks input in ``block`` mode."""

    def __init__(self, message: str, result: Any = None):
        super().__init__(message)
        self.result = result


class SentinelCallback(_LiteLLMBase):  # type: ignore[misc]
    """LiteLLM callback that screens messages via Sentinel.

    Implements both sync and async pre-call hooks so that every
    ``litellm.completion()`` and ``litellm.acompletion()`` call is screened.

    Args:
        shield: A ``Shield`` instance.
        mode: ``"block"`` to raise on malicious input, ``"monitor"`` to log only.
        session_id: Session identifier for multi-turn tracking.
        source_ip: Client IP forwarded to Shield.
    """

    def __init__(
        self,
        shield: Any,
        mode: str = "block",
        session_id: str = "default",
        source_ip: str = "127.0.0.1",
    ):
        self.shield = shield
        self.mode = mode
        self.session_id = session_id
        self.source_ip = source_ip
        self.last_result: Any | None = None

    def _screen(self, text: str) -> None:
        """Run *text* through Shield. Raise or log depending on mode."""
        if not text or not text.strip():
            return
        result = self.shield.analyze(
            text, session_id=self.session_id, source_ip=self.source_ip,
        )
        self.last_result = result
        if result.blocked:
            log.warning(
                "Shield blocked input (verdict=%s method=%s session=%s)",
                result.verdict, result.detection_method, self.session_id,
            )
            if self.mode == "block":
                raise ShieldBlockedError(
                    f"Blocked by Sentinel: {result.verdict}",
                    result=result,
                )

    def _screen_messages(self, messages: list[dict[str, Any]]) -> None:
        """Screen each user message in a LiteLLM messages list."""
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "user" and isinstance(content, str):
                self._screen(content)

    # ---- Sync hooks ----

    def log_pre_api_call(self, model: str, messages: Any,
                         kwargs: dict[str, Any]) -> None:
        """Called before each LiteLLM API call (sync path)."""
        if isinstance(messages, list):
            self._screen_messages(messages)

    # ---- Async hooks ----

    async def async_log_pre_api_call(self, model: str, messages: Any,
                                     kwargs: dict[str, Any]) -> None:
        """Called before each LiteLLM API call (async path)."""
        if isinstance(messages, list):
            self._screen_messages(messages)

    # ---- No-op stubs ----

    def log_success_event(self, kwargs: Any, response_obj: Any,
                          start_time: Any, end_time: Any) -> None:
        pass

    def log_failure_event(self, kwargs: Any, response_obj: Any,
                          start_time: Any, end_time: Any) -> None:
        pass

    async def async_log_success_event(self, kwargs: Any, response_obj: Any,
                                      start_time: Any, end_time: Any) -> None:
        pass

    async def async_log_failure_event(self, kwargs: Any, response_obj: Any,
                                      start_time: Any, end_time: Any) -> None:
        pass
