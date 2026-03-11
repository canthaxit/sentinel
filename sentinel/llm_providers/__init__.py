"""
Sentinel - Cloud LLM Provider Adapters (package)
================================================
Pluggable LLM backends for the security classifier and chat completion.

Supported providers:
    - ollama (default): Local Ollama with llama3, mistral, phi3, gemma2, qwen2.5
    - ollama_structured: Ollama with JSON schema output (v0.5+)
    - openai: OpenAI GPT-4o / GPT-4o-mini
    - openai_compat: Any OpenAI-compatible server (vLLM, LocalAI, LM Studio, llama.cpp)
    - anthropic: Anthropic Claude Sonnet / Haiku
    - azure: Azure OpenAI Service
    - bedrock: AWS Bedrock (Claude, Titan, Llama)
    - vertex: Google Vertex AI (Gemini)
    - gemini: Google Gemini API (direct)
    - llamacpp: Direct in-process GGUF inference via llama-cpp-python
    - transformer_classifier: HuggingFace transformers binary classifier (e.g. ProtectAI DeBERTa)
    - fallback: Try multiple providers in order until one succeeds

Usage:
    from sentinel.llm_providers import create_llm_judge, chat_completion

    # Create a judge using env vars
    judge = create_llm_judge()

    # Or specify provider explicitly
    judge = create_llm_judge("openai", api_key="sk-...")

    # Simple chat completion (for decoy/assistant responses)
    response = chat_completion(
        messages=[{"role": "user", "content": "Hello"}],
        system="You are a helpful assistant.",
    )
"""
from .ollama import OllamaJudge, OllamaStructuredJudge
from .openai_provider import OpenAIJudge
from .openai_compat import OpenAICompatibleJudge
from .anthropic_provider import AnthropicJudge
from .azure import AzureOpenAIJudge
from .bedrock import BedrockJudge
from .google import VertexAIJudge, GeminiJudge
from .llamacpp import LlamaCppJudge
from .transformer import TransformerClassifierJudge
from .fallback import FallbackJudge
from .factory import create_llm_judge, _PROVIDERS
from .chat import chat_completion

__all__ = [
    "OllamaJudge", "OllamaStructuredJudge",
    "OpenAIJudge", "OpenAICompatibleJudge",
    "AnthropicJudge", "AzureOpenAIJudge",
    "BedrockJudge", "VertexAIJudge", "GeminiJudge",
    "LlamaCppJudge", "TransformerClassifierJudge",
    "FallbackJudge",
    "create_llm_judge", "chat_completion",
]
