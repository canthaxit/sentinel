"""Sentinel - OpenAI-Compatible LLM Provider (vLLM, LocalAI, LM Studio, llama.cpp server)."""

import os

from sentinel.llm_judge import LLMJudge

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
