"""
Semantic Kernel integration for Sentinel.

Provides prompt rendering and function invocation filters that screen
inputs through the Shield detection pipeline.

Usage::

    from semantic_kernel import Kernel
    from sentinel import Shield
    from sentinel.semantic_kernel import (
        ShieldPromptFilter, ShieldFunctionFilter,
    )

    shield = Shield()
    kernel = Kernel()

    # Screen rendered prompts before they reach the LLM
    kernel.add_filter("prompt_rendering", ShieldPromptFilter(shield))

    # Screen function arguments before execution
    kernel.add_filter("function_invocation", ShieldFunctionFilter(shield))

Requires ``semantic-kernel>=1.0.0`` (install with
``pip install sentinel[semantic-kernel]``).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)


class ShieldBlockedError(Exception):
    """Raised when Shield blocks input in ``block`` mode."""

    def __init__(self, message: str, result: Any = None):
        super().__init__(message)
        self.result = result


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


class ShieldPromptFilter:
    """Semantic Kernel prompt rendering filter.

    Screens the rendered prompt text before it is sent to the LLM.
    Attach via ``kernel.add_filter("prompt_rendering", filter_instance)``.

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
        self.last_result: Optional[Any] = None

    async def on_prompt_render(
        self, context: Any, next_handler: Callable,
    ) -> None:
        """Screen the rendered prompt before sending to the LLM."""
        # Extract rendered prompt from context
        rendered = getattr(context, "rendered_prompt", None)
        if rendered is None and hasattr(context, "arguments"):
            # Fallback: screen all string arguments
            args = context.arguments
            if hasattr(args, "values"):
                for val in args.values():
                    if isinstance(val, str):
                        self.last_result = _screen(
                            self.shield, val, self.mode,
                            self.session_id, self.source_ip,
                        )
        else:
            if isinstance(rendered, str):
                self.last_result = _screen(
                    self.shield, rendered, self.mode,
                    self.session_id, self.source_ip,
                )

        await next_handler(context)


class ShieldFunctionFilter:
    """Semantic Kernel function invocation filter.

    Screens function arguments before execution. Attach via
    ``kernel.add_filter("function_invocation", filter_instance)``.

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
        self.last_result: Optional[Any] = None

    async def on_function_invocation(
        self, context: Any, next_handler: Callable,
    ) -> None:
        """Screen function arguments before the function executes."""
        args = getattr(context, "arguments", None)
        if args is not None and hasattr(args, "values"):
            for val in args.values():
                if isinstance(val, str):
                    self.last_result = _screen(
                        self.shield, val, self.mode,
                        self.session_id, self.source_ip,
                    )

        await next_handler(context)
