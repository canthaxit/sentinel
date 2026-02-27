"""
Haystack integration for Sentinel.

Provides a ``ShieldGuard`` component that screens text through the Shield
detection pipeline. Fits into Haystack 2.x pipelines between any
retriever/generator pair.

Usage::

    from haystack import Pipeline
    from sentinel import Shield
    from sentinel.haystack_integration import ShieldGuard

    shield = Shield()
    guard = ShieldGuard(shield, mode="block")

    pipe = Pipeline()
    pipe.add_component("guard", guard)
    pipe.add_component("generator", my_generator)
    pipe.connect("guard.text", "generator.prompt")

    result = pipe.run({"guard": {"text": "user input here"}})

Requires ``haystack-ai>=2.0.0`` (install with
``pip install sentinel[haystack]``).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

# Conditional import -- gracefully degrade when haystack is absent.
_haystack_component = None
try:
    from haystack import component as _haystack_component
except ImportError:
    pass


class ShieldBlockedError(Exception):
    """Raised when Shield blocks input in ``block`` mode."""

    def __init__(self, message: str, result: Any = None):
        super().__init__(message)
        self.result = result


class ShieldGuard:
    """Haystack 2.x component that screens text via Sentinel.

    Input:
        - ``text`` (str): The text to screen.

    Output:
        - ``text`` (str): The original text (passed through if safe).
        - ``blocked`` (bool): Whether Shield blocked the input.
        - ``result`` (dict): Full Shield result as a dictionary.

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

    def run(self, text: str) -> Dict[str, Any]:
        """Screen *text* through Shield.

        Args:
            text: The input text to screen.

        Returns:
            Dict with ``text``, ``blocked``, and ``result`` keys.
        """
        if not text or not text.strip():
            return {"text": text, "blocked": False, "result": {}}

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

        return {
            "text": text,
            "blocked": result.blocked,
            "result": result.to_dict(),
        }


# Apply @component decorator when haystack is available.
if _haystack_component is not None:
    ShieldGuard = _haystack_component(ShieldGuard)
