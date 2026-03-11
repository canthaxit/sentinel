"""Sentinel - HuggingFace Transformer Classifier LLM Provider."""

import logging
import os

from sentinel.llm_judge import LLMJudge

log = logging.getLogger(__name__)


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
