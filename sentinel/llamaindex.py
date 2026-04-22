"""
LlamaIndex integration for Sentinel.

Provides a callback handler that screens query and LLM events through the
Shield detection pipeline.

Usage::

    from sentinel import Shield
    from sentinel.llamaindex import SentinelCallbackHandler

    shield = Shield()
    handler = SentinelCallbackHandler(shield, mode="block")
    Settings.callback_manager.add_handler(handler)

Requires ``llama-index-core>=0.10.0`` (install with
``pip install sentinel[llamaindex]``).
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

# Conditional import -- gracefully degrade when llama-index-core is absent.
try:
    from llama_index.core.callbacks.base import BaseCallbackHandler as _LIBase
except ImportError:
    _LIBase = None  # type: ignore[assignment,misc]


class ShieldBlockedError(Exception):
    """Raised when Shield blocks input in ``block`` mode."""

    def __init__(self, message: str, result: Any = None):
        super().__init__(message)
        self.result = result


def _get_event_types():
    """Lazy-load CBEventType so the module can be imported without
    llama-index installed."""
    try:
        from llama_index.core.callbacks.schema import CBEventType

        return CBEventType
    except ImportError:
        return None


class SentinelCallbackHandler:
    """LlamaIndex callback handler that screens inputs via Sentinel.

    If ``llama-index-core`` is installed this class also inherits from
    ``BaseCallbackHandler`` so it works natively with LlamaIndex's
    callback manager.

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

        # LlamaIndex BaseCallbackHandler requires event_starts_to_ignore
        # and event_ends_to_ignore in __init__
        if _LIBase is not None:
            _LIBase.__init__(
                self,
                event_starts_to_ignore=[],
                event_ends_to_ignore=[],
            )

    # ---- core screening ----

    def _screen(self, text: str) -> None:
        """Run *text* through Shield.  Raise or log depending on mode."""
        if not text or not text.strip():
            return
        result = self.shield.analyze(
            text,
            session_id=self.session_id,
            source_ip=self.source_ip,
        )
        self.last_result = result
        if result.blocked:
            log.warning(
                "Shield blocked input (verdict=%s method=%s session=%s)",
                result.verdict,
                result.detection_method,
                self.session_id,
            )
            if self.mode == "block":
                raise ShieldBlockedError(
                    f"Blocked by Sentinel: {result.verdict}",
                    result=result,
                )

    # ---- LlamaIndex callback hooks ----

    def on_event_start(
        self,
        event_type: Any,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        """Screen QUERY and LLM events."""
        CBEventType = _get_event_types()
        if CBEventType is None or payload is None:
            return event_id

        if event_type == CBEventType.QUERY:
            query_str = payload.get("query_str", "")
            if query_str:
                self._screen(query_str)
        elif event_type == CBEventType.LLM:
            messages = payload.get("messages")
            if messages and len(messages) > 0:
                last = messages[-1]
                content = getattr(last, "content", str(last))
                self._screen(content)

        return event_id

    def on_event_end(
        self,
        event_type: Any,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        pass

    def start_trace(self, trace_id: str | None = None) -> None:
        pass

    def end_trace(
        self,
        trace_id: str | None = None,
        trace_map: dict[str, list[str]] | None = None,
    ) -> None:
        pass


# Dynamically make SentinelCallbackHandler inherit from _LIBase when
# llama-index-core is available, so it integrates natively.
if _LIBase is not None:
    SentinelCallbackHandler = type(
        "SentinelCallbackHandler",
        (_LIBase, SentinelCallbackHandler),
        dict(SentinelCallbackHandler.__dict__),
    )
