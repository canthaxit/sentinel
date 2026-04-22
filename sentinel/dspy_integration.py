"""
DSPy integration for Sentinel.

Provides assertion helpers and a module wrapper that screen inputs through
the Shield detection pipeline.

Usage::

    import dspy
    from sentinel import Shield
    from sentinel.dspy_integration import (
        shield_assert, shield_suggest, ShieldModule,
    )

    shield = Shield()

    # Option 1: Hard constraint -- raises dspy.Assert on blocked input
    shield_assert(shield, user_text)

    # Option 2: Soft constraint -- raises dspy.Suggest on blocked input
    shield_suggest(shield, user_text)

    # Option 3: Wrap any dspy.Module with automatic screening
    class MyModule(dspy.Module):
        def forward(self, text):
            return dspy.Prediction(output=text)

    safe_module = ShieldModule(MyModule(), shield, mode="block")
    result = safe_module(text="some input")

Requires ``dspy-ai>=2.5.0`` (install with
``pip install sentinel[dspy]``).
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

# Conditional import -- gracefully degrade when dspy is absent.
_dspy = None
try:
    import dspy as _dspy
except ImportError:
    pass


class ShieldBlockedError(Exception):
    """Raised when Shield blocks input in ``block`` mode (standalone use)."""

    def __init__(self, message: str, result: Any = None):
        super().__init__(message)
        self.result = result


def _analyze(
    shield: Any, text: str, session_id: str = "default", source_ip: str = "127.0.0.1"
) -> Any:
    """Run text through Shield and return the result."""
    if not text or not text.strip():
        return None
    return shield.analyze(text, session_id=session_id, source_ip=source_ip)


def shield_assert(
    shield: Any,
    text: str,
    session_id: str = "default",
    source_ip: str = "127.0.0.1",
    message: str = "Input blocked by Sentinel",
) -> Any:
    """Hard constraint: raise ``dspy.Assert`` if Shield blocks the input.

    If DSPy is not installed, raises ``ShieldBlockedError`` instead.

    Args:
        shield: A ``Shield`` instance.
        text: The text to screen.
        session_id: Session identifier for multi-turn tracking.
        source_ip: Client IP forwarded to Shield.
        message: Error message for the assertion.

    Returns:
        The ``ShieldResult`` if input is safe, or ``None`` for empty input.
    """
    result = _analyze(shield, text, session_id, source_ip)
    if result is not None and result.blocked:
        log.warning(
            "shield_assert blocked (verdict=%s method=%s session=%s)",
            result.verdict,
            result.detection_method,
            session_id,
        )
        detail = f"{message}: {result.verdict}"
        if _dspy is not None and hasattr(_dspy, "Assert"):
            raise _dspy.Assert(False, detail)
        raise ShieldBlockedError(detail, result=result)
    return result


def shield_suggest(
    shield: Any,
    text: str,
    session_id: str = "default",
    source_ip: str = "127.0.0.1",
    message: str = "Input flagged by Sentinel",
) -> Any:
    """Soft constraint: raise ``dspy.Suggest`` if Shield blocks the input.

    Unlike ``shield_assert``, this is a soft hint that the optimizer may
    choose to ignore. If DSPy is not installed, logs a warning instead.

    Args:
        shield: A ``Shield`` instance.
        text: The text to screen.
        session_id: Session identifier for multi-turn tracking.
        source_ip: Client IP forwarded to Shield.
        message: Error message for the suggestion.

    Returns:
        The ``ShieldResult`` if input is safe, or ``None`` for empty input.
    """
    result = _analyze(shield, text, session_id, source_ip)
    if result is not None and result.blocked:
        detail = f"{message}: {result.verdict}"
        if _dspy is not None and hasattr(_dspy, "Suggest"):
            raise _dspy.Suggest(False, detail)
        log.warning("shield_suggest flagged: %s", detail)
    return result


class ShieldModule:
    """Wrapper that screens inputs to any ``dspy.Module`` through Shield.

    The wrapper intercepts the ``text`` keyword argument (or the first
    positional string argument) and screens it before forwarding to the
    inner module.

    Args:
        inner: The ``dspy.Module`` to wrap.
        shield: A ``Shield`` instance.
        mode: ``"block"`` to use ``shield_assert``, ``"monitor"`` to use
            ``shield_suggest``.
        session_id: Session identifier for multi-turn tracking.
        source_ip: Client IP forwarded to Shield.
    """

    def __init__(
        self,
        inner: Any,
        shield: Any,
        mode: str = "block",
        session_id: str = "default",
        source_ip: str = "127.0.0.1",
    ):
        self.inner = inner
        self.shield = shield
        self.mode = mode
        self.session_id = session_id
        self.source_ip = source_ip
        self.last_result: Any | None = None

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Screen input then forward to the inner module."""
        # Try to find text to screen
        text = kwargs.get("text") or kwargs.get("input") or kwargs.get("query")
        if text is None and args:
            for arg in args:
                if isinstance(arg, str):
                    text = arg
                    break

        if text and isinstance(text, str):
            if self.mode == "block":
                self.last_result = shield_assert(
                    self.shield,
                    text,
                    self.session_id,
                    self.source_ip,
                )
            else:
                self.last_result = shield_suggest(
                    self.shield,
                    text,
                    self.session_id,
                    self.source_ip,
                )

        return self.inner(*args, **kwargs)

    def forward(self, *args: Any, **kwargs: Any) -> Any:
        """Alias for ``__call__`` to match dspy.Module interface."""
        return self.__call__(*args, **kwargs)
