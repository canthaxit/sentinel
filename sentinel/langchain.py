"""
LangChain integration for Sentinel.

Provides a callback handler that screens prompts and tool inputs through
the Shield detection pipeline before they reach the LLM.

Usage::

    from sentinel import Shield
    from sentinel.langchain import SentinelCallbackHandler

    shield = Shield()
    handler = SentinelCallbackHandler(shield, mode="block")
    chain.invoke({"input": "..."}, config={"callbacks": [handler]})

Requires ``langchain-core>=0.1.0`` (install with
``pip install sentinel[langchain]``).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Union

log = logging.getLogger(__name__)

# Conditional import -- users who don't install langchain-core still get
# a usable module (the classes just won't inherit from BaseCallbackHandler).
try:
    from langchain_core.callbacks import BaseCallbackHandler as _LCBase
except ImportError:
    _LCBase = object  # type: ignore[assignment,misc]


class ShieldBlockedError(Exception):
    """Raised when Shield blocks a prompt in ``block`` mode."""

    def __init__(self, message: str, result: Any = None):
        super().__init__(message)
        self.result = result


class SentinelCallbackHandler(_LCBase):  # type: ignore[misc]
    """LangChain callback handler that screens inputs via Sentinel.

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
        # langchain BaseCallbackHandler expects super().__init__()
        if _LCBase is not object:
            super().__init__()
        self.shield = shield
        self.mode = mode
        self.session_id = session_id
        self.source_ip = source_ip
        self.last_result: Optional[Any] = None

    # ---- core screening ----

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

    # ---- LangChain callback hooks ----

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        for prompt in prompts:
            self._screen(prompt)

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[Any],
        **kwargs: Any,
    ) -> None:
        # messages is List[List[BaseMessage]]; screen the last user message
        # from each conversation.
        for conversation in messages:
            if conversation:
                last = conversation[-1]
                content = getattr(last, "content", str(last))
                self._screen(content)

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Union[Dict[str, Any], Any],
        **kwargs: Any,
    ) -> None:
        if isinstance(inputs, dict):
            for value in inputs.values():
                if isinstance(value, str):
                    self._screen(value)
        elif isinstance(inputs, str):
            self._screen(inputs)

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        self._screen(input_str)

    # ---- no-op stubs (required by interface) ----

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        pass

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        pass

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        pass

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        pass

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        pass

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        pass
