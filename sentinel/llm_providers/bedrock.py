"""Sentinel - AWS Bedrock LLM Provider."""

import os

from sentinel.llm_judge import LLMJudge


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
