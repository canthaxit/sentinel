"""
Sentinel - Ensemble Verdict Engine
Orchestrates the tiered detection pipeline:
  Sanitization -> Pre-Filter -> ML -> LLM
"""

from . import config
from .llm_judge import LLMJudge
from .ml_client import MLClient
from .pre_filter import pre_filter_check


class EnsembleEngine:
    """
    Tiered ensemble detection: Pre-filter -> ML -> LLM.
    Blocks obvious attacks fast (~10ms), uses expensive LLM only for ambiguity.

    Args:
        llm_judge: Custom LLMJudge instance (optional)
        ml_client: Custom MLClient instance (optional)
        fail_open: When True, return SAFE if both ML and LLM are
            unavailable instead of defaulting to MALICIOUS.
    """

    def __init__(self, llm_judge=None, ml_client=None, fail_open=False):
        self.llm_judge = llm_judge or LLMJudge()
        self.ml_client = ml_client or MLClient()
        self.fail_open = fail_open

    def get_verdict(self, user_input, session, source_ip, sanitizations=None):
        """
        Run the full detection pipeline.

        Args:
            user_input: The user's message text
            session: Session state dict
            source_ip: Client IP address
            sanitizations: List of sanitizations applied

        Returns:
            tuple: (verdict, ml_result, llm_verdict)
              - verdict: "SAFE", "MALICIOUS", or "SAFE_REVIEW"
              - ml_result: dict with score/threat_type/severity or None
              - llm_verdict: "SAFE"/"UNSAFE"/PRE_BLOCKED_* or None
        """
        # TIER 1: Pre-filter (fast pattern match, ~10ms)
        # Pre-filter runs locally and cannot fail, so it always runs
        # regardless of fail_open mode.
        should_block, block_reason = pre_filter_check(user_input, session, sanitizations)
        if should_block:
            return "MALICIOUS", None, f"PRE_BLOCKED_{block_reason}"

        # TIER 2: ML scoring
        ml_result = self.ml_client.score(user_input, session, source_ip)

        # If ML API unavailable, fallback to LLM-only
        if ml_result is None:
            llm_verdict = self.llm_judge.get_verdict(
                user_input, fail_open=self.fail_open)
            if llm_verdict == "FAIL_OPEN":
                return "SAFE", None, "FAIL_OPEN"
            verdict = "MALICIOUS" if "UNSAFE" in llm_verdict else "SAFE"
            return verdict, None, llm_verdict

        score = ml_result.get("score", 0.0)

        # High confidence malicious - skip LLM
        if score >= config.ML_HIGH_THRESHOLD:
            return "MALICIOUS", ml_result, None

        # High confidence safe - skip LLM
        if score <= config.ML_LOW_THRESHOLD:
            return "SAFE", ml_result, None

        # TIER 3: LLM disambiguation for ambiguous scores
        llm_verdict = self.llm_judge.get_verdict(
            user_input, fail_open=self.fail_open)
        if llm_verdict == "FAIL_OPEN":
            # ML was available but ambiguous, LLM failed -- allow through
            return "SAFE", ml_result, "FAIL_OPEN"
        verdict = "MALICIOUS" if "UNSAFE" in llm_verdict else "SAFE"

        # SAFE_REVIEW: high ML score but LLM says safe
        if score >= 0.7 and verdict == "SAFE":
            verdict = "SAFE_REVIEW"

        return verdict, ml_result, llm_verdict
