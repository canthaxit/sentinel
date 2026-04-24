"""
Sentinel - Attack Pattern Detector
Detects attack patterns in user input for multi-turn attack tracking.
"""
from typing import Any


from . import config


def detect_attack_patterns(user_input: str, session: dict[str, Any]) -> list[Any]:
    """
    Detect attack patterns in user input for multi-turn attack tracking.

    Args:
        user_input: The user's message text
        session: Session state dict with 'interactions' list

    Returns:
        list of detected pattern type strings
    """
    patterns = []
    text_lower = user_input.lower()

    # 1. Instruction Override Detection
    if any(ind in text_lower for ind in config.OVERRIDE_INDICATORS):
        patterns.append("instruction_override")

    # 2. Context Switch Detection
    if any(ind in text_lower for ind in config.CONTEXT_SWITCH_INDICATORS):
        patterns.append("context_switch")

    # 3. Persona Override Detection
    if any(ind in text_lower for ind in config.PERSONA_INDICATORS):
        patterns.append("persona_override")

    # 4. Hypothetical Framing Detection (ATK-006, ATK-007)
    if any(ind in text_lower for ind in config.HYPOTHETICAL_INDICATORS):
        patterns.append("hypothetical_framing")

    # 4b. DAN Mode Detection (ATK-008)
    if any(ind in text_lower for ind in config.DAN_INDICATORS):
        patterns.append("dan_jailbreak")

    # 4c. Logic Trap Detection (ATK-011 - 81.4% success rate)
    if any(ind in text_lower for ind in config.LOGIC_TRAP_INDICATORS):
        patterns.append("logic_trap")

    # 5. Encoding/Obfuscation Detection
    if "base64" in text_lower or "decode" in text_lower:
        patterns.append("encoding_attack")

    # 6. System Prompt Extraction Attempt
    if any(ind in text_lower for ind in config.EXTRACTION_INDICATORS):
        patterns.append("prompt_extraction")

    # 7. Gradual Escalation Detection
    interactions = session.get("interactions", [])
    if len(interactions) >= 2:
        prev_message = interactions[-1].get("message", "").lower()
        if any(word in prev_message for word in ["hypothetical", "imagine", "pretend"]):
            if any(word in text_lower for word in ["now", "so", "therefore", "given that"]):
                patterns.append("gradual_escalation")

    return patterns
