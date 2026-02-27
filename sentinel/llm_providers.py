"""
Sentinel - Cloud LLM Provider Adapters
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

import logging
import os
from .llm_judge import LLMJudge
from . import config

log = logging.getLogger(__name__)


# ============================================================================
# Provider: Ollama (default, local)
# ============================================================================
# Supported local models via Ollama:
#   llama3     - Meta Llama 3 8B (default, balanced performance)
#   mistral    - Mistral 7B (strong instruction following)
#   phi3       - Microsoft Phi-3 (small, very fast, good for constrained envs)
#   gemma2     - Google Gemma 2 (good reasoning, larger context)
#   qwen2.5    - Alibaba Qwen 2.5 (strong multilingual support)
# Select via SHIELD_LLM_MODEL env var (default: llama3)

class OllamaJudge(LLMJudge):
    """Explicit Ollama judge (same as base LLMJudge, for clarity)."""

    def __init__(self, model=None, **kwargs):
        super().__init__(model=model, **kwargs)

    def _call_llm(self, user_input):
        import ollama
        response = ollama.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_input},
            ],
            options=self.options,
        )
        return response["message"]["content"].strip()


# ============================================================================
# Provider: OpenAI
# ============================================================================

class OpenAIJudge(LLMJudge):
    """OpenAI GPT-based judge. Requires: pip install openai"""

    def __init__(self, model=None, api_key=None, **kwargs):
        default_model = os.getenv("SHIELD_LLM_MODEL", "gpt-4o-mini")
        super().__init__(model=model or default_model, **kwargs)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        if not self.api_key:
            raise ValueError("OpenAI API key required. Set OPENAI_API_KEY env var.")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import openai
            except ImportError:
                raise ImportError(
                    "openai package required. Install with: pip install openai>=1.0.0"
                )
            self._client = openai.OpenAI(api_key=self.api_key)
        return self._client

    def _call_llm(self, user_input):
        client = self._get_client()
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_input},
            ],
            max_tokens=10,
            temperature=0.1,
        )
        return response.choices[0].message.content.strip()


# ============================================================================
# Provider: Anthropic
# ============================================================================

class AnthropicJudge(LLMJudge):
    """Anthropic Claude judge. Requires: pip install anthropic"""

    def __init__(self, model=None, api_key=None, **kwargs):
        default_model = os.getenv("SHIELD_LLM_MODEL", "claude-sonnet-4-5-20250929")
        super().__init__(model=model or default_model, **kwargs)
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError("Anthropic API key required. Set ANTHROPIC_API_KEY env var.")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError:
                raise ImportError(
                    "anthropic package required. Install with: pip install anthropic>=0.40.0"
                )
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def _call_llm(self, user_input):
        client = self._get_client()
        response = client.messages.create(
            model=self.model,
            max_tokens=10,
            system=self.system_prompt,
            messages=[
                {"role": "user", "content": user_input},
            ],
        )
        return response.content[0].text.strip()


# ============================================================================
# Provider: Azure OpenAI
# ============================================================================

class AzureOpenAIJudge(LLMJudge):
    """Azure OpenAI judge. Requires: pip install openai"""

    def __init__(self, model=None, endpoint=None, api_key=None,
                 deployment=None, api_version=None, **kwargs):
        super().__init__(model=model or "gpt-4o-mini", **kwargs)
        self.endpoint = endpoint or os.getenv("AZURE_OPENAI_ENDPOINT", "")
        self.api_key = api_key or os.getenv("AZURE_OPENAI_KEY", "")
        self.deployment = deployment or os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
        self.api_version = api_version or os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
        if not self.endpoint or not self.api_key or not self.deployment:
            raise ValueError(
                "Azure OpenAI requires AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_KEY, "
                "and AZURE_OPENAI_DEPLOYMENT env vars."
            )
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import openai
            except ImportError:
                raise ImportError(
                    "openai package required. Install with: pip install openai>=1.0.0"
                )
            self._client = openai.AzureOpenAI(
                azure_endpoint=self.endpoint,
                api_key=self.api_key,
                api_version=self.api_version,
            )
        return self._client

    def _call_llm(self, user_input):
        client = self._get_client()
        response = client.chat.completions.create(
            model=self.deployment,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_input},
            ],
            max_tokens=10,
            temperature=0.1,
        )
        return response.choices[0].message.content.strip()


# ============================================================================
# Provider: AWS Bedrock
# ============================================================================

class BedrockJudge(LLMJudge):
    """AWS Bedrock judge. Requires: pip install boto3"""

    def __init__(self, model=None, region=None, **kwargs):
        default_model = os.getenv("SHIELD_LLM_MODEL", "anthropic.claude-3-5-sonnet-20241022-v2:0")
        super().__init__(model=model or default_model, **kwargs)
        self.region = region or os.getenv("AWS_REGION", "us-east-1")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import boto3
            except ImportError:
                raise ImportError(
                    "boto3 package required. Install with: pip install boto3>=1.34.0"
                )
            self._client = boto3.client(
                "bedrock-runtime",
                region_name=self.region,
            )
        return self._client

    def _call_llm(self, user_input):
        import json
        client = self._get_client()

        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 10,
            "system": self.system_prompt,
            "messages": [
                {"role": "user", "content": user_input},
            ],
        })

        response = client.invoke_model(
            modelId=self.model,
            body=body,
            contentType="application/json",
            accept="application/json",
        )

        result = json.loads(response["body"].read())
        return result["content"][0]["text"].strip()


# ============================================================================
# Provider: Google Vertex AI
# ============================================================================

class VertexAIJudge(LLMJudge):
    """Google Vertex AI judge. Requires: pip install google-cloud-aiplatform"""

    def __init__(self, model=None, project=None, location=None, **kwargs):
        default_model = os.getenv("SHIELD_LLM_MODEL", "gemini-2.0-flash")
        super().__init__(model=model or default_model, **kwargs)
        self.project = project or os.getenv("GOOGLE_CLOUD_PROJECT", "")
        self.location = location or os.getenv("GOOGLE_CLOUD_REGION", "us-central1")
        if not self.project:
            raise ValueError("Vertex AI requires GOOGLE_CLOUD_PROJECT env var.")
        self._model_instance = None

    def _get_model(self):
        if self._model_instance is None:
            try:
                import vertexai
                from vertexai.generative_models import GenerativeModel
            except ImportError:
                raise ImportError(
                    "google-cloud-aiplatform required. "
                    "Install with: pip install google-cloud-aiplatform>=1.40.0"
                )
            vertexai.init(project=self.project, location=self.location)
            self._model_instance = GenerativeModel(
                self.model,
                system_instruction=self.system_prompt,
            )
        return self._model_instance

    def _call_llm(self, user_input):
        model = self._get_model()
        response = model.generate_content(
            user_input,
            generation_config={"max_output_tokens": 10, "temperature": 0.1},
        )
        return response.text.strip()


# ============================================================================
# Provider: Google Gemini (direct API)
# ============================================================================

class GeminiJudge(LLMJudge):
    """Google Gemini API judge. Requires: pip install google-generativeai"""

    def __init__(self, model=None, api_key=None, **kwargs):
        default_model = os.getenv("SHIELD_LLM_MODEL", "gemini-2.0-flash")
        super().__init__(model=model or default_model, **kwargs)
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY", "")
        if not self.api_key:
            raise ValueError("Google API key required. Set GOOGLE_API_KEY env var.")
        self._model_instance = None

    def _get_model(self):
        if self._model_instance is None:
            try:
                import google.generativeai as genai
            except ImportError:
                raise ImportError(
                    "google-generativeai required. "
                    "Install with: pip install google-generativeai>=0.8.0"
                )
            genai.configure(api_key=self.api_key)
            self._model_instance = genai.GenerativeModel(
                self.model,
                system_instruction=self.system_prompt,
            )
        return self._model_instance

    def _call_llm(self, user_input):
        model = self._get_model()
        response = model.generate_content(
            user_input,
            generation_config={"max_output_tokens": 10, "temperature": 0.1},
        )
        return response.text.strip()


# ============================================================================
# Provider: Ollama Structured (JSON schema output, v0.5+)
# ============================================================================

class OllamaStructuredJudge(OllamaJudge):
    """Ollama judge using structured JSON output (requires Ollama v0.5+).

    Returns JSON: {"verdict": "SAFE"|"UNSAFE", "confidence": 0.0-1.0}
    Eliminates verdict parsing errors by constraining output format.
    """

    _JSON_SCHEMA = {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["SAFE", "UNSAFE"]},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        },
        "required": ["verdict"],
    }

    def _call_llm(self, user_input):
        import ollama
        response = ollama.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_input},
            ],
            options=self.options,
            format=self._JSON_SCHEMA,
        )
        return response["message"]["content"].strip()

    def get_verdict(self, user_input):
        """Parse structured JSON verdict directly instead of text extraction."""
        import json
        try:
            raw = self._call_llm(user_input)
            data = json.loads(raw)
            verdict = data.get("verdict", "").upper()
            if verdict in ("SAFE", "UNSAFE"):
                confidence = data.get("confidence", None)
                conf_str = f" (confidence={confidence})" if confidence is not None else ""
                log.debug("Structured verdict: %s%s", verdict, conf_str)
                return verdict
            log.warning("Invalid structured verdict: %s, defaulting to UNSAFE", verdict)
            return "UNSAFE"
        except (json.JSONDecodeError, KeyError) as e:
            log.warning("Structured JSON parse error: %s, defaulting to UNSAFE", e)
            return "UNSAFE"
        except Exception as e:
            log.error("LLM error: %s", e, exc_info=True)
            return "UNSAFE"


# ============================================================================
# Provider: OpenAI-Compatible (vLLM, LocalAI, LM Studio, llama.cpp server)
# ============================================================================

class OpenAICompatibleJudge(LLMJudge):
    """Generic judge for any OpenAI-compatible API server.

    Works with vLLM, LocalAI, LM Studio, llama.cpp server, and others.
    Requires: pip install openai

    Config env vars:
        SHIELD_OPENAI_COMPAT_BASE_URL: Server URL (default: http://localhost:8000/v1)
        SHIELD_OPENAI_COMPAT_API_KEY: API key (default: not-needed)
        SHIELD_LLM_MODEL: Model name (default: default)
    """

    def __init__(self, model=None, base_url=None, api_key=None, **kwargs):
        default_model = os.getenv("SHIELD_LLM_MODEL", "default")
        super().__init__(model=model or default_model, **kwargs)
        self.base_url = base_url or os.getenv(
            "SHIELD_OPENAI_COMPAT_BASE_URL", "http://localhost:8000/v1"
        )
        self.api_key = api_key or os.getenv("SHIELD_OPENAI_COMPAT_API_KEY", "not-needed")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import openai
            except ImportError:
                raise ImportError(
                    "openai package required. Install with: pip install openai>=1.0.0"
                )
            self._client = openai.OpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
            )
        return self._client

    def _call_llm(self, user_input):
        client = self._get_client()
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_input},
            ],
            max_tokens=10,
            temperature=0.1,
        )
        return response.choices[0].message.content.strip()


# ============================================================================
# Provider: llama-cpp-python (direct in-process GGUF inference)
# ============================================================================

class LlamaCppJudge(LLMJudge):
    """Direct in-process GGUF inference via llama-cpp-python.

    No server required -- loads the model directly into the Python process.
    Uses GBNF grammar to constrain output to exactly "SAFE" or "UNSAFE".
    Requires: pip install llama-cpp-python>=0.2.0

    Config env vars:
        SHIELD_GGUF_PATH: Path to .gguf model file (required)
        SHIELD_GPU_LAYERS: Number of layers to offload to GPU (default: 0)
    """

    _GBNF_GRAMMAR = 'root ::= "SAFE" | "UNSAFE"'

    def __init__(self, model=None, gguf_path=None, gpu_layers=None, **kwargs):
        super().__init__(model=model or "gguf-local", **kwargs)
        self.gguf_path = gguf_path or os.getenv("SHIELD_GGUF_PATH", "")
        if not self.gguf_path:
            raise ValueError(
                "GGUF model path required. Set SHIELD_GGUF_PATH env var "
                "or pass gguf_path= parameter."
            )
        self.gpu_layers = int(
            gpu_layers if gpu_layers is not None
            else os.getenv("SHIELD_GPU_LAYERS", "0")
        )
        self._llm = None

    def _get_llm(self):
        if self._llm is None:
            try:
                from llama_cpp import Llama
            except ImportError:
                raise ImportError(
                    "llama-cpp-python required. Install with: "
                    "pip install llama-cpp-python>=0.2.0"
                )
            self._llm = Llama(
                model_path=self.gguf_path,
                n_gpu_layers=self.gpu_layers,
                n_ctx=512,
                verbose=False,
            )
        return self._llm

    def _call_llm(self, user_input):
        from llama_cpp import LlamaGrammar
        llm = self._get_llm()
        grammar = LlamaGrammar.from_string(self._GBNF_GRAMMAR)
        prompt = (
            f"<|system|>\n{self.system_prompt}\n"
            f"<|user|>\n{user_input}\n"
            f"<|assistant|>\n"
        )
        output = llm(
            prompt,
            max_tokens=8,
            temperature=0.0,
            grammar=grammar,
        )
        return output["choices"][0]["text"].strip()


# ============================================================================
# Provider: Transformer Classifier (HuggingFace binary classifier)
# ============================================================================

class TransformerClassifierJudge(LLMJudge):
    """HuggingFace transformers binary injection classifier.

    Uses a text-classification pipeline for fast (~30ms) binary verdicts.
    Not a generative model -- overrides get_verdict() entirely.
    Requires: pip install transformers>=4.35.0 torch>=2.0.0

    Config env vars:
        SHIELD_CLASSIFIER_MODEL: HF model ID
            (default: protectai/deberta-v3-base-prompt-injection-v2)
        SHIELD_CLASSIFIER_THRESHOLD: Confidence threshold (default: 0.5)
    """

    # Labels that map to UNSAFE
    _UNSAFE_LABELS = {"INJECTION", "JAILBREAK", "MALICIOUS", "LABEL_1", "1"}
    # Labels that map to SAFE
    _SAFE_LABELS = {"BENIGN", "SAFE", "LABEL_0", "0"}

    def __init__(self, model=None, threshold=None, **kwargs):
        default_model = os.getenv(
            "SHIELD_CLASSIFIER_MODEL",
            "protectai/deberta-v3-base-prompt-injection-v2",
        )
        super().__init__(model=model or default_model, **kwargs)
        self.threshold = float(
            threshold if threshold is not None
            else os.getenv("SHIELD_CLASSIFIER_THRESHOLD", "0.5")
        )
        self._pipeline = None

    def _get_pipeline(self):
        if self._pipeline is None:
            try:
                from transformers import pipeline
            except ImportError:
                raise ImportError(
                    "transformers package required. Install with: "
                    "pip install transformers>=4.35.0 torch>=2.0.0"
                )
            self._pipeline = pipeline(
                "text-classification",
                model=self.model,
                truncation=True,
            )
        return self._pipeline

    def get_verdict(self, user_input):
        """Classify via HuggingFace pipeline instead of generative LLM."""
        try:
            pipe = self._get_pipeline()
            results = pipe(user_input)
            if not results:
                log.warning("Transformer returned empty results, defaulting to UNSAFE")
                return "UNSAFE"

            label = results[0]["label"].upper()
            score = results[0]["score"]

            if label in self._UNSAFE_LABELS and score >= self.threshold:
                log.debug("Transformer: UNSAFE (%s=%.3f)", label, score)
                return "UNSAFE"
            elif label in self._SAFE_LABELS and score >= self.threshold:
                log.debug("Transformer: SAFE (%s=%.3f)", label, score)
                return "SAFE"
            else:
                # Unknown label or below threshold -- fail closed
                log.warning(
                    "Transformer: unknown label '%s' (score=%.3f), defaulting to UNSAFE",
                    label, score,
                )
                return "UNSAFE"
        except Exception as e:
            log.error("Transformer error: %s", e, exc_info=True)
            return "UNSAFE"

    def _call_llm(self, user_input):
        """Not used -- get_verdict() is overridden."""
        raise NotImplementedError("TransformerClassifierJudge does not use _call_llm()")


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
        raise ValueError(
            f"Unknown LLM provider: '{provider}'. Available: {available}"
        )

    log.info("Initializing provider: %s", provider)
    return cls(**kwargs)


# ============================================================================
# Chat Completion Helper (for decoy/assistant responses)
# ============================================================================

def chat_completion(messages, system=None, options=None, **kwargs):
    """
    Provider-agnostic chat completion for general conversation.

    Uses the configured SHIELD_LLM_PROVIDER to generate responses.
    This replaces direct ollama.chat() calls in sentinel_app.py.

    Args:
        messages: List of {"role": ..., "content": ...} dicts
        system: Optional system prompt (prepended to messages)
        options: Provider-specific options (Ollama options dict, etc.)
        **kwargs: Additional provider-specific arguments

    Returns:
        str: The assistant's response text
    """
    provider = os.getenv("SHIELD_LLM_PROVIDER", "ollama").lower().strip()
    model = os.getenv("SHIELD_LLM_MODEL", "llama3")

    # Build full message list with system prompt
    full_messages = []
    if system and provider in ("ollama", "ollama_structured", "openai", "openai_compat", "azure", "llamacpp"):
        full_messages.append({"role": "system", "content": system})
    full_messages.extend(messages)

    if provider in ("ollama", "ollama_structured"):
        return _chat_ollama(full_messages, model, options)
    elif provider == "openai":
        return _chat_openai(full_messages, model, kwargs.get("api_key"))
    elif provider == "openai_compat":
        return _chat_openai_compat(full_messages, model, kwargs)
    elif provider == "anthropic":
        return _chat_anthropic(full_messages, model, system, kwargs.get("api_key"))
    elif provider == "azure":
        return _chat_azure(full_messages, kwargs)
    elif provider == "bedrock":
        return _chat_bedrock(full_messages, model, system, kwargs)
    elif provider in ("vertex", "gemini"):
        return _chat_gemini(full_messages, model, system, provider, kwargs)
    elif provider == "llamacpp":
        return _chat_llamacpp(full_messages, kwargs)
    else:
        # Fallback to Ollama
        return _chat_ollama(full_messages, model, options)


def _chat_ollama(messages, model, options=None):
    """Ollama chat completion."""
    import ollama
    default_options = {
        "num_ctx": 1024,
        "num_predict": 200,
        "temperature": 0.7,
        "top_k": 40,
        "top_p": 0.9,
    }
    if options:
        default_options.update(options)
    response = ollama.chat(model=model, messages=messages, options=default_options)
    return response["message"]["content"]


def _chat_openai(messages, model, api_key=None):
    """OpenAI chat completion."""
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required. Install with: pip install openai>=1.0.0")
    client = openai.OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY", ""))
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=200,
        temperature=0.7,
    )
    return response.choices[0].message.content


def _chat_anthropic(messages, model, system=None, api_key=None):
    """Anthropic chat completion."""
    try:
        import anthropic
    except ImportError:
        raise ImportError("anthropic package required. Install with: pip install anthropic>=0.40.0")
    client = anthropic.Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY", ""))
    # Filter out system messages (Anthropic uses separate system param)
    user_messages = [m for m in messages if m["role"] != "system"]
    sys_prompt = system or ""
    if not sys_prompt:
        for m in messages:
            if m["role"] == "system":
                sys_prompt = m["content"]
                break
    response = client.messages.create(
        model=model,
        max_tokens=200,
        system=sys_prompt,
        messages=user_messages,
    )
    return response.content[0].text


def _chat_azure(messages, kwargs):
    """Azure OpenAI chat completion."""
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required. Install with: pip install openai>=1.0.0")
    client = openai.AzureOpenAI(
        azure_endpoint=kwargs.get("endpoint") or os.getenv("AZURE_OPENAI_ENDPOINT", ""),
        api_key=kwargs.get("api_key") or os.getenv("AZURE_OPENAI_KEY", ""),
        api_version=kwargs.get("api_version") or os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"),
    )
    deployment = kwargs.get("deployment") or os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
    response = client.chat.completions.create(
        model=deployment,
        messages=messages,
        max_tokens=200,
        temperature=0.7,
    )
    return response.choices[0].message.content


def _chat_bedrock(messages, model, system=None, kwargs=None):
    """AWS Bedrock chat completion."""
    import json
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 package required. Install with: pip install boto3>=1.34.0")
    kwargs = kwargs or {}
    region = kwargs.get("region") or os.getenv("AWS_REGION", "us-east-1")
    client = boto3.client("bedrock-runtime", region_name=region)
    user_messages = [m for m in messages if m["role"] != "system"]
    sys_prompt = system or ""
    if not sys_prompt:
        for m in messages:
            if m["role"] == "system":
                sys_prompt = m["content"]
                break
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 200,
        "system": sys_prompt,
        "messages": user_messages,
    })
    response = client.invoke_model(
        modelId=model, body=body,
        contentType="application/json", accept="application/json",
    )
    result = json.loads(response["body"].read())
    return result["content"][0]["text"]


def _chat_gemini(messages, model, system=None, provider="gemini", kwargs=None):
    """Google Gemini/Vertex chat completion."""
    kwargs = kwargs or {}
    if provider == "vertex":
        try:
            import vertexai
            from vertexai.generative_models import GenerativeModel
        except ImportError:
            raise ImportError("google-cloud-aiplatform required.")
        project = kwargs.get("project") or os.getenv("GOOGLE_CLOUD_PROJECT", "")
        location = kwargs.get("location") or os.getenv("GOOGLE_CLOUD_REGION", "us-central1")
        vertexai.init(project=project, location=location)
        gen_model = GenerativeModel(model, system_instruction=system or "")
    else:
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError("google-generativeai required.")
        genai.configure(api_key=kwargs.get("api_key") or os.getenv("GOOGLE_API_KEY", ""))
        gen_model = genai.GenerativeModel(model, system_instruction=system or "")

    # Combine user messages into a single prompt for Gemini
    user_text = "\n".join(m["content"] for m in messages if m["role"] != "system")
    response = gen_model.generate_content(
        user_text,
        generation_config={"max_output_tokens": 200, "temperature": 0.7},
    )
    return response.text


def _chat_openai_compat(messages, model, kwargs=None):
    """OpenAI-compatible server chat completion (vLLM, LocalAI, etc.)."""
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required. Install with: pip install openai>=1.0.0")
    kwargs = kwargs or {}
    base_url = kwargs.get("base_url") or os.getenv(
        "SHIELD_OPENAI_COMPAT_BASE_URL", "http://localhost:8000/v1"
    )
    api_key = kwargs.get("api_key") or os.getenv("SHIELD_OPENAI_COMPAT_API_KEY", "not-needed")
    client = openai.OpenAI(base_url=base_url, api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=200,
        temperature=0.7,
    )
    return response.choices[0].message.content


def _chat_llamacpp(messages, kwargs=None):
    """llama-cpp-python chat completion."""
    try:
        from llama_cpp import Llama
    except ImportError:
        raise ImportError(
            "llama-cpp-python required. Install with: pip install llama-cpp-python>=0.2.0"
        )
    kwargs = kwargs or {}
    gguf_path = kwargs.get("gguf_path") or os.getenv("SHIELD_GGUF_PATH", "")
    if not gguf_path:
        raise ValueError("GGUF model path required. Set SHIELD_GGUF_PATH env var.")
    gpu_layers = int(kwargs.get("gpu_layers", os.getenv("SHIELD_GPU_LAYERS", "0")))
    llm = Llama(model_path=gguf_path, n_gpu_layers=gpu_layers, n_ctx=1024, verbose=False)
    # Build prompt from messages
    prompt_parts = []
    for m in messages:
        role = m["role"]
        prompt_parts.append(f"<|{role}|>\n{m['content']}")
    prompt_parts.append("<|assistant|>\n")
    prompt = "\n".join(prompt_parts)
    output = llm(prompt, max_tokens=200, temperature=0.7)
    return output["choices"][0]["text"].strip()
