"""Sentinel - LLM Provider Factory."""

import logging
import os

from .anthropic_provider import AnthropicJudge
from .azure import AzureOpenAIJudge
from .bedrock import BedrockJudge
from .fallback import FallbackJudge
from .google import GeminiJudge, VertexAIJudge
from .llamacpp import LlamaCppJudge
from .ollama import OllamaJudge, OllamaStructuredJudge
from .openai_compat import OpenAICompatibleJudge
from .openai_provider import OpenAIJudge
from .transformer import TransformerClassifierJudge

log = logging.getLogger(__name__)


# ============================================================================
# Factory
# ============================================================================

_PROVIDERS = {
    "ollama": OllamaJudge,
    "ollama_structured": OllamaStructuredJudge,
    "openai": OpenAIJudge,
    "openai_compat": OpenAICompatibleJudge,
    "anthropic": AnthropicJudge,
    "azure": AzureOpenAIJudge,
    "bedrock": BedrockJudge,
    "vertex": VertexAIJudge,
    "gemini": GeminiJudge,
    "llamacpp": LlamaCppJudge,
    "transformer_classifier": TransformerClassifierJudge,
    "fallback": FallbackJudge,
}


def create_llm_judge(provider=None, **kwargs):
    """
    Factory: create an LLM judge for the configured provider.

    Args:
        provider: Provider name. One of: ollama, ollama_structured, openai,
                  openai_compat, anthropic, azure, bedrock, vertex, gemini,
                  llamacpp, transformer_classifier, fallback.
                  Defaults to SHIELD_LLM_PROVIDER env var or "ollama".
        **kwargs: Provider-specific arguments (api_key, endpoint, etc.)

    Returns:
        LLMJudge subclass instance

    Raises:
        ValueError: If provider is unknown
    """
    provider = provider or os.getenv("SHIELD_LLM_PROVIDER", "ollama")
    provider = provider.lower().strip()

    cls = _PROVIDERS.get(provider)
    if cls is None:
        available = ", ".join(sorted(_PROVIDERS.keys()))
        raise ValueError(f"Unknown LLM provider: '{provider}'. Available: {available}")

    log.info("Initializing provider: %s", provider)
    return cls(**kwargs)
