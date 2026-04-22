"""Sentinel - OpenAI LLM Provider."""

import os

from sentinel.llm_judge import LLMJudge
from sentinel.model_config import get_model

# ============================================================================
# Provider: OpenAI
# ============================================================================

class OpenAIJudge(LLMJudge):
    """OpenAI GPT-based judge. Requires: pip install openai"""

    def __init__(self, model=None, api_key=None, **kwargs):
        super().__init__(model=model or get_model("openai"), **kwargs)
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
