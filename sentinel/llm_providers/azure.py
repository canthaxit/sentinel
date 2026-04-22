"""Sentinel - Azure OpenAI LLM Provider."""

import os

from sentinel.llm_judge import LLMJudge

# ============================================================================
# Provider: Azure OpenAI
# ============================================================================


class AzureOpenAIJudge(LLMJudge):
    """Azure OpenAI judge. Requires: pip install openai"""

    def __init__(
        self, model=None, endpoint=None, api_key=None, deployment=None, api_version=None, **kwargs
    ):
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
