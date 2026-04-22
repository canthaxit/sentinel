"""
CrewAI integration for Sentinel.

Provides task callbacks, step callbacks, and a Shield-as-Tool for CrewAI
agents that screen inputs through the Shield detection pipeline.

Usage::

    from sentinel import Shield
    from sentinel.crewai import (
        ShieldTaskCallback, ShieldGuardCallback, ShieldTool,
    )

    shield = Shield()

    # Option 1: Screen task outputs on completion
    task = Task(
        description="...",
        callback=ShieldTaskCallback(shield, mode="block"),
    )

    # Option 2: Step callback screening agent inputs
    crew = Crew(
        agents=[...], tasks=[...],
        step_callback=ShieldGuardCallback(shield, mode="block"),
    )

    # Option 3: Give agents a screening tool
    tool = ShieldTool(shield)
    agent = Agent(role="...", tools=[tool])

Requires ``crewai>=0.50.0`` (install with
``pip install sentinel[crewai]``).
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

# Conditional import -- gracefully degrade when crewai is absent.
try:
    from crewai.tools import BaseTool as _CrewAIBaseTool
except ImportError:
    _CrewAIBaseTool = None  # type: ignore[assignment,misc]


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


class ShieldTaskCallback:
    """CrewAI task callback that screens task output upon completion.

    Use as the ``callback`` argument to a CrewAI ``Task``.

    Args:
        shield: A ``Shield`` instance.
        mode: ``"block"`` to raise on malicious output, ``"monitor"`` to log only.
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

    def __call__(self, output: Any) -> None:
        """Screen the task output text."""
        text = ""
        if isinstance(output, str):
            text = output
        elif hasattr(output, "raw_output"):
            text = str(output.raw_output)
        elif hasattr(output, "result"):
            text = str(output.result)
        elif hasattr(output, "output"):
            text = str(output.output)
        else:
            text = str(output)

        self.last_result = _screen(
            self.shield, text, self.mode, self.session_id, self.source_ip,
        )


class ShieldGuardCallback:
    """CrewAI step callback that screens agent inputs at each step.

    Use as the ``step_callback`` argument to a CrewAI ``Crew``.

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

    def __call__(self, step_output: Any) -> None:
        """Screen the step output text."""
        text = ""
        if isinstance(step_output, str):
            text = step_output
        elif hasattr(step_output, "text"):
            text = str(step_output.text)
        elif hasattr(step_output, "output"):
            text = str(step_output.output)
        elif hasattr(step_output, "result"):
            text = str(step_output.result)
        else:
            text = str(step_output)

        self.last_result = _screen(
            self.shield, text, self.mode, self.session_id, self.source_ip,
        )


class ShieldTool:
    """CrewAI tool that agents can call to screen text through Shield.

    When CrewAI's ``BaseTool`` is available, this class inherits from it
    for full framework integration. Otherwise it works standalone.

    Args:
        shield: A ``Shield`` instance.
        session_id: Session identifier for multi-turn tracking.
        source_ip: Client IP forwarded to Shield.
    """

    name: str = "sentinel_scan"
    description: str = (
        "Scan text for prompt injection, jailbreak attempts, and adversarial "
        "content. Input should be the text to scan. Returns a JSON-like dict "
        "with verdict, blocked status, and detection method."
    )

    def __init__(
        self,
        shield: Any,
        session_id: str = "default",
        source_ip: str = "127.0.0.1",
    ):
        self.shield = shield
        self.session_id = session_id
        self.source_ip = source_ip
        self.last_result: Any | None = None

    def _run(self, text: str) -> str:
        """Execute the tool: screen text through Shield."""
        if not text or not text.strip():
            return "{'verdict': 'SAFE', 'blocked': false, 'note': 'empty input'}"
        result = self.shield.analyze(
            text, session_id=self.session_id, source_ip=self.source_ip,
        )
        self.last_result = result
        return str(result.to_dict())


# Dynamically make ShieldTool inherit from BaseTool when crewai is available.
if _CrewAIBaseTool is not None:
    ShieldTool = type(
        "ShieldTool",
        (_CrewAIBaseTool, ShieldTool),
        dict(ShieldTool.__dict__),
    )
