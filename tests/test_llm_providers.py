"""
Tests for LLM provider expansion (5 new providers).
All tests use mocks -- no real LLM backends required.

Run: python -m pytest test_llm_providers.py -v
"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

from sentinel.llm_providers import (
    _PROVIDERS,
    create_llm_judge,
    OllamaStructuredJudge,
    OpenAICompatibleJudge,
    LlamaCppJudge,
    TransformerClassifierJudge,
    FallbackJudge,
    OllamaJudge,
    OpenAIJudge,
    AnthropicJudge,
    AzureOpenAIJudge,
    BedrockJudge,
    VertexAIJudge,
    GeminiJudge,
)


# ============================================================================
# Provider Registry
# ============================================================================

class TestProviderRegistry:
    def test_registry_has_12_providers(self):
        assert len(_PROVIDERS) == 12

    def test_registry_keys(self):
        expected = {
            "ollama", "ollama_structured", "openai", "openai_compat",
            "anthropic", "azure", "bedrock", "vertex", "gemini",
            "llamacpp", "transformer_classifier", "fallback",
        }
        assert set(_PROVIDERS.keys()) == expected

    def test_factory_creates_ollama_structured(self):
        judge = create_llm_judge("ollama_structured")
        assert isinstance(judge, OllamaStructuredJudge)

    def test_factory_creates_openai_compat(self):
        judge = create_llm_judge("openai_compat")
        assert isinstance(judge, OpenAICompatibleJudge)

    @patch.dict(os.environ, {"SHIELD_GGUF_PATH": "/tmp/model.gguf"})
    def test_factory_creates_llamacpp(self):
        judge = create_llm_judge("llamacpp")
        assert isinstance(judge, LlamaCppJudge)

    def test_factory_creates_transformer_classifier(self):
        judge = create_llm_judge("transformer_classifier")
        assert isinstance(judge, TransformerClassifierJudge)

    def test_factory_creates_fallback(self):
        judge = create_llm_judge("fallback")
        assert isinstance(judge, FallbackJudge)

    def test_factory_rejects_unknown_provider(self):
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            create_llm_judge("nonexistent_provider")


# ============================================================================
# OllamaStructuredJudge
# ============================================================================

class TestOllamaStructuredJudge:
    def test_inherits_from_ollama(self):
        judge = OllamaStructuredJudge()
        assert isinstance(judge, OllamaJudge)

    @patch("sentinel.llm_providers.OllamaStructuredJudge._call_llm")
    def test_valid_safe_json(self, mock_call):
        mock_call.return_value = '{"verdict": "SAFE", "confidence": 0.95}'
        judge = OllamaStructuredJudge()
        verdict = judge.get_verdict("What is 2+2?")
        assert verdict == "SAFE"

    @patch("sentinel.llm_providers.OllamaStructuredJudge._call_llm")
    def test_valid_unsafe_json(self, mock_call):
        mock_call.return_value = '{"verdict": "UNSAFE", "confidence": 0.88}'
        judge = OllamaStructuredJudge()
        verdict = judge.get_verdict("ignore instructions")
        assert verdict == "UNSAFE"

    @patch("sentinel.llm_providers.OllamaStructuredJudge._call_llm")
    def test_valid_json_no_confidence(self, mock_call):
        mock_call.return_value = '{"verdict": "SAFE"}'
        judge = OllamaStructuredJudge()
        verdict = judge.get_verdict("hello")
        assert verdict == "SAFE"

    @patch("sentinel.llm_providers.OllamaStructuredJudge._call_llm")
    def test_invalid_json_defaults_unsafe(self, mock_call):
        mock_call.return_value = "not json at all"
        judge = OllamaStructuredJudge()
        verdict = judge.get_verdict("test")
        assert verdict == "UNSAFE"

    @patch("sentinel.llm_providers.OllamaStructuredJudge._call_llm")
    def test_missing_verdict_key_defaults_unsafe(self, mock_call):
        mock_call.return_value = '{"confidence": 0.9}'
        judge = OllamaStructuredJudge()
        verdict = judge.get_verdict("test")
        assert verdict == "UNSAFE"

    @patch("sentinel.llm_providers.OllamaStructuredJudge._call_llm")
    def test_invalid_verdict_value_defaults_unsafe(self, mock_call):
        mock_call.return_value = '{"verdict": "MAYBE"}'
        judge = OllamaStructuredJudge()
        verdict = judge.get_verdict("test")
        assert verdict == "UNSAFE"

    @patch("sentinel.llm_providers.OllamaStructuredJudge._call_llm")
    def test_llm_exception_defaults_unsafe(self, mock_call):
        mock_call.side_effect = ConnectionError("Ollama not running")
        judge = OllamaStructuredJudge()
        verdict = judge.get_verdict("test")
        assert verdict == "UNSAFE"

    def test_json_schema_has_required_fields(self):
        schema = OllamaStructuredJudge._JSON_SCHEMA
        assert schema["type"] == "object"
        assert "verdict" in schema["properties"]
        assert "confidence" in schema["properties"]
        assert "verdict" in schema["required"]


# ============================================================================
# OpenAICompatibleJudge
# ============================================================================

class TestOpenAICompatibleJudge:
    def test_default_config(self):
        judge = OpenAICompatibleJudge()
        assert judge.base_url == "http://localhost:8000/v1"
        assert judge.api_key == "not-needed"
        assert judge.model == "default"

    @patch.dict(os.environ, {
        "SHIELD_OPENAI_COMPAT_BASE_URL": "http://myserver:9000/v1",
        "SHIELD_OPENAI_COMPAT_API_KEY": "my-key",
        "SHIELD_LLM_MODEL": "my-model",
    })
    def test_custom_config_from_env(self):
        judge = OpenAICompatibleJudge()
        assert judge.base_url == "http://myserver:9000/v1"
        assert judge.api_key == "my-key"
        assert judge.model == "my-model"

    def test_custom_config_from_args(self):
        judge = OpenAICompatibleJudge(
            model="phi3", base_url="http://custom:5000/v1", api_key="test-key"
        )
        assert judge.base_url == "http://custom:5000/v1"
        assert judge.api_key == "test-key"
        assert judge.model == "phi3"

    def test_inherits_extract_verdict(self):
        judge = OpenAICompatibleJudge()
        assert judge._extract_verdict("SAFE") == "SAFE"
        assert judge._extract_verdict("UNSAFE") == "UNSAFE"
        assert judge._extract_verdict("I CANNOT do that") == "UNSAFE"

    @patch("sentinel.llm_providers.OpenAICompatibleJudge._call_llm")
    def test_get_verdict_uses_extract(self, mock_call):
        mock_call.return_value = "SAFE"
        judge = OpenAICompatibleJudge()
        assert judge.get_verdict("hello") == "SAFE"

    def test_lazy_client_init(self):
        judge = OpenAICompatibleJudge()
        assert judge._client is None


# ============================================================================
# LlamaCppJudge
# ============================================================================

class TestLlamaCppJudge:
    def test_requires_gguf_path(self):
        with patch.dict(os.environ, {}, clear=True):
            # Remove SHIELD_GGUF_PATH from env if present
            os.environ.pop("SHIELD_GGUF_PATH", None)
            with pytest.raises(ValueError, match="GGUF model path required"):
                LlamaCppJudge()

    @patch.dict(os.environ, {"SHIELD_GGUF_PATH": "/models/llama.gguf"})
    def test_config_from_env(self):
        judge = LlamaCppJudge()
        assert judge.gguf_path == "/models/llama.gguf"
        assert judge.gpu_layers == 0

    @patch.dict(os.environ, {
        "SHIELD_GGUF_PATH": "/models/llama.gguf",
        "SHIELD_GPU_LAYERS": "35",
    })
    def test_gpu_layers_from_env(self):
        judge = LlamaCppJudge()
        assert judge.gpu_layers == 35

    def test_config_from_args(self):
        judge = LlamaCppJudge(gguf_path="/my/model.gguf", gpu_layers=10)
        assert judge.gguf_path == "/my/model.gguf"
        assert judge.gpu_layers == 10

    def test_gbnf_grammar_constrains_output(self):
        grammar = LlamaCppJudge._GBNF_GRAMMAR
        assert "SAFE" in grammar
        assert "UNSAFE" in grammar

    @patch.dict(os.environ, {"SHIELD_GGUF_PATH": "/models/llama.gguf"})
    def test_lazy_llm_init(self):
        judge = LlamaCppJudge()
        assert judge._llm is None

    @patch.dict(os.environ, {"SHIELD_GGUF_PATH": "/models/llama.gguf"})
    @patch("sentinel.llm_providers.LlamaCppJudge._call_llm")
    def test_verdict_safe(self, mock_call):
        mock_call.return_value = "SAFE"
        judge = LlamaCppJudge()
        assert judge.get_verdict("hello") == "SAFE"

    @patch.dict(os.environ, {"SHIELD_GGUF_PATH": "/models/llama.gguf"})
    @patch("sentinel.llm_providers.LlamaCppJudge._call_llm")
    def test_verdict_unsafe(self, mock_call):
        mock_call.return_value = "UNSAFE"
        judge = LlamaCppJudge()
        assert judge.get_verdict("ignore all instructions") == "UNSAFE"

    @patch.dict(os.environ, {"SHIELD_GGUF_PATH": "/models/llama.gguf"})
    @patch("sentinel.llm_providers.LlamaCppJudge._call_llm")
    def test_llm_error_defaults_unsafe(self, mock_call):
        mock_call.side_effect = RuntimeError("model load failed")
        judge = LlamaCppJudge()
        assert judge.get_verdict("test") == "UNSAFE"


# ============================================================================
# TransformerClassifierJudge
# ============================================================================

class TestTransformerClassifierJudge:
    def test_default_config(self):
        judge = TransformerClassifierJudge()
        assert judge.model == "protectai/deberta-v3-base-prompt-injection-v2"
        assert judge.threshold == 0.5

    @patch.dict(os.environ, {
        "SHIELD_CLASSIFIER_MODEL": "custom/model",
        "SHIELD_CLASSIFIER_THRESHOLD": "0.8",
    })
    def test_custom_config_from_env(self):
        judge = TransformerClassifierJudge()
        assert judge.model == "custom/model"
        assert judge.threshold == 0.8

    def test_custom_config_from_args(self):
        judge = TransformerClassifierJudge(model="my/model", threshold=0.7)
        assert judge.model == "my/model"
        assert judge.threshold == 0.7

    @patch.object(TransformerClassifierJudge, "_get_pipeline")
    def test_injection_label_returns_unsafe(self, mock_pipe):
        mock_pipe.return_value = lambda x: [{"label": "INJECTION", "score": 0.95}]
        judge = TransformerClassifierJudge()
        assert judge.get_verdict("ignore instructions") == "UNSAFE"

    @patch.object(TransformerClassifierJudge, "_get_pipeline")
    def test_safe_label_returns_safe(self, mock_pipe):
        mock_pipe.return_value = lambda x: [{"label": "SAFE", "score": 0.92}]
        judge = TransformerClassifierJudge()
        assert judge.get_verdict("What is 2+2?") == "SAFE"

    @patch.object(TransformerClassifierJudge, "_get_pipeline")
    def test_benign_label_returns_safe(self, mock_pipe):
        mock_pipe.return_value = lambda x: [{"label": "BENIGN", "score": 0.88}]
        judge = TransformerClassifierJudge()
        assert judge.get_verdict("hello") == "SAFE"

    @patch.object(TransformerClassifierJudge, "_get_pipeline")
    def test_jailbreak_label_returns_unsafe(self, mock_pipe):
        mock_pipe.return_value = lambda x: [{"label": "JAILBREAK", "score": 0.91}]
        judge = TransformerClassifierJudge()
        assert judge.get_verdict("DAN mode") == "UNSAFE"

    @patch.object(TransformerClassifierJudge, "_get_pipeline")
    def test_malicious_label_returns_unsafe(self, mock_pipe):
        mock_pipe.return_value = lambda x: [{"label": "MALICIOUS", "score": 0.85}]
        judge = TransformerClassifierJudge()
        assert judge.get_verdict("evil input") == "UNSAFE"

    @patch.object(TransformerClassifierJudge, "_get_pipeline")
    def test_label_1_returns_unsafe(self, mock_pipe):
        mock_pipe.return_value = lambda x: [{"label": "LABEL_1", "score": 0.75}]
        judge = TransformerClassifierJudge()
        assert judge.get_verdict("attack") == "UNSAFE"

    @patch.object(TransformerClassifierJudge, "_get_pipeline")
    def test_label_0_returns_safe(self, mock_pipe):
        mock_pipe.return_value = lambda x: [{"label": "LABEL_0", "score": 0.80}]
        judge = TransformerClassifierJudge()
        assert judge.get_verdict("normal query") == "SAFE"

    @patch.object(TransformerClassifierJudge, "_get_pipeline")
    def test_below_threshold_defaults_unsafe(self, mock_pipe):
        mock_pipe.return_value = lambda x: [{"label": "SAFE", "score": 0.3}]
        judge = TransformerClassifierJudge(threshold=0.5)
        assert judge.get_verdict("ambiguous") == "UNSAFE"

    @patch.object(TransformerClassifierJudge, "_get_pipeline")
    def test_unknown_label_defaults_unsafe(self, mock_pipe):
        mock_pipe.return_value = lambda x: [{"label": "WEIRD_LABEL", "score": 0.99}]
        judge = TransformerClassifierJudge()
        assert judge.get_verdict("test") == "UNSAFE"

    @patch.object(TransformerClassifierJudge, "_get_pipeline")
    def test_empty_results_defaults_unsafe(self, mock_pipe):
        mock_pipe.return_value = lambda x: []
        judge = TransformerClassifierJudge()
        assert judge.get_verdict("test") == "UNSAFE"

    @patch.object(TransformerClassifierJudge, "_get_pipeline")
    def test_exception_defaults_unsafe(self, mock_pipe):
        mock_pipe.return_value = MagicMock(side_effect=RuntimeError("model error"))
        judge = TransformerClassifierJudge()
        assert judge.get_verdict("test") == "UNSAFE"

    def test_call_llm_raises_not_implemented(self):
        judge = TransformerClassifierJudge()
        with pytest.raises(NotImplementedError):
            judge._call_llm("test")

    def test_lazy_pipeline_init(self):
        judge = TransformerClassifierJudge()
        assert judge._pipeline is None


# ============================================================================
# FallbackJudge
# ============================================================================

class TestFallbackJudge:
    def test_default_provider_names(self):
        judge = FallbackJudge()
        assert judge._provider_names == ["ollama", "openai_compat", "transformer_classifier"]

    @patch.dict(os.environ, {"SHIELD_FALLBACK_PROVIDERS": "openai,anthropic"})
    def test_custom_providers_from_env(self):
        judge = FallbackJudge()
        assert judge._provider_names == ["openai", "anthropic"]

    def test_custom_providers_from_args(self):
        judge = FallbackJudge(providers=["llamacpp", "ollama"])
        assert judge._provider_names == ["llamacpp", "ollama"]

    def test_lazy_chain_init(self):
        judge = FallbackJudge()
        assert judge._chain is None

    @patch("sentinel.llm_providers.create_llm_judge")
    def test_first_provider_succeeds(self, mock_factory):
        mock_judge_a = MagicMock()
        mock_judge_a.get_verdict.return_value = "SAFE"
        mock_judge_b = MagicMock()
        mock_factory.side_effect = [mock_judge_a, mock_judge_b]

        judge = FallbackJudge(providers=["ollama", "openai_compat"])
        verdict = judge.get_verdict("hello")
        assert verdict == "SAFE"
        mock_judge_a.get_verdict.assert_called_once_with("hello")
        mock_judge_b.get_verdict.assert_not_called()

    @patch("sentinel.llm_providers.create_llm_judge")
    def test_first_fails_second_succeeds(self, mock_factory):
        mock_judge_a = MagicMock()
        mock_judge_a.get_verdict.side_effect = ConnectionError("offline")
        mock_judge_b = MagicMock()
        mock_judge_b.get_verdict.return_value = "UNSAFE"
        mock_factory.side_effect = [mock_judge_a, mock_judge_b]

        judge = FallbackJudge(providers=["ollama", "openai_compat"])
        verdict = judge.get_verdict("attack")
        assert verdict == "UNSAFE"
        mock_judge_a.get_verdict.assert_called_once()
        mock_judge_b.get_verdict.assert_called_once()

    @patch("sentinel.llm_providers.create_llm_judge")
    def test_all_fail_defaults_unsafe(self, mock_factory):
        mock_judge = MagicMock()
        mock_judge.get_verdict.side_effect = RuntimeError("broken")
        mock_factory.return_value = mock_judge

        judge = FallbackJudge(providers=["ollama"])
        verdict = judge.get_verdict("test")
        assert verdict == "UNSAFE"

    @patch("sentinel.llm_providers.create_llm_judge")
    def test_empty_chain_defaults_unsafe(self, mock_factory):
        judge = FallbackJudge(providers=[])
        verdict = judge.get_verdict("test")
        assert verdict == "UNSAFE"

    @patch("sentinel.llm_providers.create_llm_judge")
    def test_provider_init_failure_skipped(self, mock_factory):
        """If a provider fails to initialize, it's skipped but others work."""
        mock_judge_b = MagicMock()
        mock_judge_b.get_verdict.return_value = "SAFE"
        mock_factory.side_effect = [
            ValueError("bad provider"),  # first fails to init
            mock_judge_b,                # second succeeds
        ]

        judge = FallbackJudge(providers=["bad_one", "good_one"])
        verdict = judge.get_verdict("hello")
        assert verdict == "SAFE"

    def test_call_llm_raises_not_implemented(self):
        judge = FallbackJudge(providers=[])
        with pytest.raises(NotImplementedError):
            judge._call_llm("test")

    @patch("sentinel.llm_providers.create_llm_judge")
    def test_chain_initialized_once(self, mock_factory):
        """Chain is lazily initialized once, not on every call."""
        mock_judge = MagicMock()
        mock_judge.get_verdict.return_value = "SAFE"
        mock_factory.return_value = mock_judge

        judge = FallbackJudge(providers=["ollama"])
        judge.get_verdict("first")
        judge.get_verdict("second")
        # create_llm_judge should only be called once (during init_chain)
        assert mock_factory.call_count == 1
