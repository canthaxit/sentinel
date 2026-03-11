"""Sentinel - Google Vertex AI and Gemini LLM Providers."""

import os

from sentinel.llm_judge import LLMJudge


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
