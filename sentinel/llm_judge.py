"""
Sentinel - LLM Judge
Pluggable LLM-based security classifier with smart verdict extraction.
"""

import logging

from . import config

log = logging.getLogger(__name__)


class LLMJudge:
    """
    LLM-based security classifier.

    Supports pluggable backends. Default uses Ollama.
    Override `_call_llm()` for custom providers (OpenAI, Anthropic, etc.).
    """

    def __init__(self, model=None, options=None, system_prompt=None):
        self.model = model or config.LLM_MODEL
        self.options = options or config.LLM_JUDGE_OPTIONS
        self.system_prompt = system_prompt or config.LLM_JUDGE_SYSTEM_PROMPT

    def get_verdict(self, user_input, fail_open=False):
        """
        Classify user input as SAFE or UNSAFE.

        Args:
            user_input: The user's message text
            fail_open: When True, return "FAIL_OPEN" instead of "UNSAFE"
                on LLM errors so callers can allow the request through.

        Returns:
            str: "SAFE", "UNSAFE", or "FAIL_OPEN" (only when fail_open=True
                and the LLM call itself failed)
        """
        try:
            llm_response = self._call_llm(user_input)
            return self._extract_verdict(llm_response)
        except Exception as e:
            if fail_open:
                log.warning("LLM error (fail-open, allowing request): %s", e)
                return "FAIL_OPEN"
            log.error("LLM error (fail-closed to UNSAFE): %s", e, exc_info=True)
            return "UNSAFE"  # Fail closed

    def _call_llm(self, user_input):
        """
        Call the LLM backend. Override this for custom providers.

        Returns:
            str: Raw LLM response text
        """
        try:
            import ollama
        except ImportError:
            raise RuntimeError(
                "No LLM provider installed. Install one with:\n"
                "  pip install sentinel[ollama]    # Local Ollama\n"
                "  pip install sentinel[openai]    # OpenAI API\n"
                "  pip install sentinel[anthropic]  # Anthropic API\n"
                "Or use create_llm_judge() from sentinel.llm_providers."
            )
        response = ollama.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_input},
            ],
            options=self.options,
        )
        return response["message"]["content"].strip()

    def _extract_verdict(self, llm_response):
        """
        Extract SAFE/UNSAFE verdict from potentially conversational LLM response.
        Handles refusal patterns as implicit UNSAFE.
        """
        upper = llm_response.upper()

        if "UNSAFE" in upper:
            log.debug("Explicit UNSAFE detected")
            return "UNSAFE"
        if "SAFE" in upper and "UNSAFE" not in upper:
            log.debug("Explicit SAFE detected")
            return "SAFE"

        # Check for refusal language (implicit UNSAFE)
        matched = next((p for p in config.REFUSAL_PATTERNS if p in upper), None)
        if matched:
            log.debug("Refusal pattern detected: %s", matched)
            return "UNSAFE"

        # Default to UNSAFE if unclear (fail closed)
        log.debug("No explicit verdict, defaulting to UNSAFE")
        return "UNSAFE"
