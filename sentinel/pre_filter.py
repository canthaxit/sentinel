"""
Sentinel - Pre-Filter
Blocks obvious attacks before expensive ML/LLM processing.
Achieves ~10ms blocking vs ~15s LLM judgment (1,550x speedup).
"""

import logging
import unicodedata

from . import config

log = logging.getLogger(__name__)


def pre_filter_check(user_input: str, session: dict, sanitizations: list | None = None) -> tuple:
    """
    Pre-filter to block obvious attacks before expensive LLM judgment.

    Args:
        user_input: The user's message text
        session: Session state dict
        sanitizations: List of sanitizations applied to the input

    Returns:
        tuple: (should_block: bool, block_reason: str or None)
    """
    # Rule 1: Heavy sanitization indicates attack attempt
    if sanitizations and len(sanitizations) >= 3:
        log.info("Pre-filter blocked: Heavy sanitization (%d types)", len(sanitizations))
        return True, "HEAVY_SANITIZATION"

    # Rule 2: Session already escalated
    if session.get("escalated", False):
        log.info("Pre-filter blocked: Session already escalated")
        return True, "SESSION_ESCALATED"

    # Rule 3: Multiple instruction override attempts
    if session.get("instruction_override_attempts", 0) >= 1:
        log.info("Pre-filter blocked: Instruction override detected")
        return True, "INSTRUCTION_OVERRIDE"

    # HIGH F-03 fix (2026-04-22 audit): substring matching alone was bypassed
    # by homoglyph obfuscation (e.g. Cyrillic \u0430 for Latin 'a') and by
    # combining / non-ASCII characters. NFKD folds compatibility forms
    # (superscripts, full-width, decorated letters) so the subsequent
    # substring sweep catches those evasions. This is a defence-in-depth
    # measure -- paraphrase / non-English evasions still require the ML and
    # LLM judge layers downstream.
    text_lower = unicodedata.normalize("NFKD", user_input).lower()

    # Rule 4: Critical keyword combinations
    for combo in config.CRITICAL_COMBINATIONS:
        trigger_words, target_words = combo
        has_trigger = any(word in text_lower for word in trigger_words)
        has_target = any(word in text_lower for word in target_words)
        if has_trigger and has_target:
            log.info("Pre-filter blocked: Critical keyword combination")
            return True, "CRITICAL_KEYWORDS"

    # Rule 5: Repeated attack patterns (3+ diverse patterns)
    if len(session.get("attack_patterns", [])) >= 3:
        log.info(
            "Pre-filter blocked: Multiple attack patterns (%d)", len(session["attack_patterns"])
        )
        return True, "MULTIPLE_PATTERNS"

    # Rule 6: High frequency of sanitization events
    if session.get("sanitization_events", 0) >= 2:
        log.info("Pre-filter blocked: Repeated sanitization attempts")
        return True, "REPEATED_SANITIZATION"

    # Rule 7: Specific dangerous patterns
    for pattern in config.DANGEROUS_PATTERNS:
        if pattern in text_lower:
            log.info("Pre-filter blocked: Dangerous pattern '%s'", pattern)
            return True, f"DANGEROUS_PATTERN_{pattern.upper().replace(' ', '_')}"

    # Rule 8: DAN/Jailbreak mode detection (ATK-008)
    for pattern in config.DAN_JAILBREAK_PATTERNS:
        if pattern in text_lower:
            log.info("Pre-filter blocked: DAN jailbreak pattern '%s'", pattern)
            return True, f"DAN_JAILBREAK_{pattern.upper().replace(' ', '_')}"

    # Rule 9: Logic trap detection (ATK-011 - 81.4% success rate)
    if session.get("logic_trap_attempts", 0) >= 1:
        log.info("Pre-filter blocked: Logic trap detected")
        return True, "LOGIC_TRAP"

    # Rule 10: Hypothetical framing with restricted keywords
    if session.get("hypothetical_framing_count", 0) >= 1:
        if any(keyword in text_lower for keyword in config.RESTRICTED_KEYWORDS):
            log.info("Pre-filter blocked: Hypothetical framing with restricted keywords")
            return True, "JAILBREAK_WITH_RESTRICTED_KEYWORDS"

    # Rule 11: Roleplay/fictional framing with attack intent (ATK-006 - 89.6% success rate)
    has_fictional = any(ind in text_lower for ind in config.FICTIONAL_INDICATORS)
    has_attack_intent = any(keyword in text_lower for keyword in config.ATTACK_INTENT_KEYWORDS)
    if has_fictional and has_attack_intent:
        log.info("Pre-filter blocked: Roleplay jailbreak (ATK-006)")
        return True, "ROLEPLAY_JAILBREAK_ATK006"

    return False, None
