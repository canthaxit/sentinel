"""
LangGraph integration for Sentinel.

Provides guard node factories and node wrappers for LangGraph StateGraphs
that screen messages through the Shield detection pipeline.

Usage::

    from sentinel import Shield
    from sentinel.langgraph import create_shield_node, shield_wrap_node

    shield = Shield()

    # Option 1: Dedicated guard node
    guard = create_shield_node(shield, mode="block")
    graph.add_node("shield_guard", guard)

    # Option 2: Wrap an existing node
    wrapped = shield_wrap_node(shield, my_node_fn, mode="block")
    graph.add_node("my_node", wrapped)

Requires ``langgraph>=0.2.0`` (install with
``pip install sentinel[langgraph]``).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

log = logging.getLogger(__name__)


class ShieldBlockedError(Exception):
    """Raised when Shield blocks input in ``block`` mode."""

    def __init__(self, message: str, result: Any = None):
        super().__init__(message)
        self.result = result


def _extract_last_message_content(state: Dict[str, Any]) -> Optional[str]:
    """Extract text content from the last message in a LangGraph state dict.

    Supports both dict-style messages and LangChain BaseMessage objects.
    """
    messages = state.get("messages")
    if not messages:
        return None
    last = messages[-1]
    # LangChain BaseMessage
    if hasattr(last, "content"):
        return last.content
    # Dict-style message
    if isinstance(last, dict):
        return last.get("content")
    # Plain string
    if isinstance(last, str):
        return last
    return str(last)


def _screen(shield: Any, text: str, mode: str,
            session_id: str, source_ip: str) -> Any:
    """Run text through Shield and raise or log depending on mode."""
    if not text or not text.strip():
        return None
    result = shield.analyze(text, session_id=session_id, source_ip=source_ip)
    if result.blocked:
        log.warning(
            "Shield blocked input (verdict=%s method=%s session=%s)",
            result.verdict, result.detection_method, session_id,
        )
        if mode == "block":
            raise ShieldBlockedError(
                f"Blocked by Sentinel: {result.verdict}",
                result=result,
            )
    return result


def create_shield_node(
    shield: Any,
    mode: str = "block",
    session_id: str = "default",
    source_ip: str = "127.0.0.1",
) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Create a LangGraph node function that screens the last message.

    The returned function accepts a LangGraph state dict and screens
    ``state["messages"][-1].content`` through Shield.

    Args:
        shield: A ``Shield`` instance.
        mode: ``"block"`` to raise on malicious input, ``"monitor"`` to log only.
        session_id: Session identifier for multi-turn tracking.
        source_ip: Client IP forwarded to Shield.

    Returns:
        A callable suitable for ``graph.add_node()``.
    """

    def guard_node(state: Dict[str, Any]) -> Dict[str, Any]:
        text = _extract_last_message_content(state)
        if text:
            _screen(shield, text, mode, session_id, source_ip)
        return state

    guard_node.__name__ = "shield_guard"
    guard_node.__qualname__ = "shield_guard"
    return guard_node


def shield_wrap_node(
    shield: Any,
    node_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
    mode: str = "block",
    session_id: str = "default",
    source_ip: str = "127.0.0.1",
) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Wrap an existing LangGraph node so its input is screened first.

    The wrapper screens ``state["messages"][-1].content`` through Shield
    *before* calling the wrapped node function.

    Args:
        shield: A ``Shield`` instance.
        node_fn: The original node function to wrap.
        mode: ``"block"`` to raise on malicious input, ``"monitor"`` to log only.
        session_id: Session identifier for multi-turn tracking.
        source_ip: Client IP forwarded to Shield.

    Returns:
        A wrapped callable suitable for ``graph.add_node()``.
    """

    def wrapped_node(state: Dict[str, Any]) -> Dict[str, Any]:
        text = _extract_last_message_content(state)
        if text:
            _screen(shield, text, mode, session_id, source_ip)
        return node_fn(state)

    wrapped_node.__name__ = getattr(node_fn, "__name__", "wrapped_node")
    wrapped_node.__qualname__ = getattr(node_fn, "__qualname__", "wrapped_node")
    return wrapped_node
