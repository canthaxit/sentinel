"""Sentinel - Anthropic Claude LLM Provider."""

import os

from sentinel.llm_judge import LLMJudge


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
