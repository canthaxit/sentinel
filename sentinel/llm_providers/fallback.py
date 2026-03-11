"""Sentinel - Fallback Chain LLM Provider (tries providers in order)."""

import logging
import os

from sentinel.llm_judge import LLMJudge

log = logging.getLogger(__name__)


# ============================================================================
# Provider: Fallback Chain (tries providers in order)
# ============================================================================

class FallbackJudge(LLMJudge):
    """Tries multiple LLM providers in order until one succeeds.

    Useful for resilient setups: e.g. try local Ollama first, fall back to
    cloud provider if unavailable, then fall back to a fast classifier.

    Config env vars:
        SHIELD_FALLBACK_PROVIDERS: Comma-separated provider names
            (default: ollama,openai_compat,transformer_classifier)
    """

    def __init__(self, providers=None, **kwargs):
        super().__init__(**kwargs)
        if providers is not None:
            self._provider_names = providers
        else:
            env = os.getenv(
                "SHIELD_FALLBACK_PROVIDERS",
                "ollama,openai_compat,transformer_classifier",
            )
            self._provider_names = [p.strip() for p in env.split(",") if p.strip()]
        self._chain = None

    def _init_chain(self):
        """Lazy-initialize the provider chain on first use."""
        if self._chain is not None:
            return
        # Lazy import to avoid circular dependency with factory.py
        from .factory import create_llm_judge
        self._chain = []
        for name in self._provider_names:
            try:
                judge = create_llm_judge(name)
                self._chain.append((name, judge))
                log.info("Initialized provider: %s", name)
            except Exception as e:
                log.warning("Skipped provider '%s': %s", name, e)

    def get_verdict(self, user_input):
        """Try each provider in order; return first successful verdict."""
        self._init_chain()
        for name, judge in self._chain:
            try:
                verdict = judge.get_verdict(user_input)
                log.debug("Got verdict from '%s': %s", name, verdict)
                return verdict
            except Exception as e:
                log.warning("Provider '%s' failed: %s", name, e)
                continue

        log.error("All providers failed, defaulting to UNSAFE")
        return "UNSAFE"

    def _call_llm(self, user_input):
        """Not used -- get_verdict() is overridden."""
        raise NotImplementedError("FallbackJudge does not use _call_llm()")
