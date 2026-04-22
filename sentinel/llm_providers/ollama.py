"""Sentinel - Ollama LLM Provider (default, local)."""

import logging

from sentinel.llm_judge import LLMJudge

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
