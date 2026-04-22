"""
Sentinel - Input Sanitizer
Sanitizes user input to prevent markup-based injection attacks.

Targets:
- HTML/XML tag injection (ATK-031)
- Markdown injection (ATK-032)
- CSV formula injection (ATK-033)
"""

import html
import logging
import re
import unicodedata

log = logging.getLogger(__name__)


MAX_SANITIZE_LENGTH = 50000


def sanitize_input(user_input: str) -> tuple:
    """
    Sanitize user input to prevent markup-based injection attacks.

    Returns:
        tuple: (sanitized_text, list_of_applied_sanitizations)
    """
    if len(user_input) > MAX_SANITIZE_LENGTH:
        user_input = user_input[:MAX_SANITIZE_LENGTH]
        return user_input, ["input_truncated"]

    sanitizations_applied = []

    # 0. Unicode NFKC normalization (prevents homoglyph bypasses)
    normalized = unicodedata.normalize("NFKC", user_input)
    if normalized != user_input:
        user_input = normalized
        sanitizations_applied.append("unicode_normalized")

    # 1. HTML/XML Tag Stripping
    html_tag_pattern = r"<[^>]+>"
    if re.search(html_tag_pattern, user_input):
        user_input = re.sub(html_tag_pattern, "", user_input)
        sanitizations_applied.append("html_tags_removed")

    # 2. HTML Entity Decoding (prevent double-encoding attacks)
    decoded_input = html.unescape(user_input)
    if decoded_input != user_input:
        user_input = decoded_input
        sanitizations_applied.append("html_entities_decoded")

    # 3. Markdown Link Injection Prevention
    markdown_link_pattern = r"\[([^\]]+)\]\([^\)]+\)"
    if re.search(markdown_link_pattern, user_input):
        user_input = re.sub(markdown_link_pattern, r"\1", user_input)
        sanitizations_applied.append("markdown_links_removed")

    # 4. Markdown Image Injection Prevention
    markdown_img_pattern = r"!\[([^\]]*)\]\([^\)]+\)"
    if re.search(markdown_img_pattern, user_input):
        user_input = re.sub(markdown_img_pattern, r"\1", user_input)
        sanitizations_applied.append("markdown_images_removed")

    # 5. Script Tag Removal (additional protection)
    script_pattern = r"<script[^>]*>.*?</script>"
    if re.search(script_pattern, user_input, re.IGNORECASE | re.DOTALL):
        user_input = re.sub(script_pattern, "", user_input, flags=re.IGNORECASE | re.DOTALL)
        sanitizations_applied.append("script_tags_removed")

    # 6. Inline Event Handler Removal (onclick, onerror, etc.)
    event_handler_pattern = r'\bon\w+\s*=\s*["\'][^"\']*["\']'
    if re.search(event_handler_pattern, user_input, re.IGNORECASE):
        user_input = re.sub(event_handler_pattern, "", user_input, flags=re.IGNORECASE)
        sanitizations_applied.append("event_handlers_removed")

    # 7. XML CDATA Section Removal
    cdata_pattern = r"<!\[CDATA\[.*?\]\]>"
    if re.search(cdata_pattern, user_input, re.DOTALL):
        user_input = re.sub(cdata_pattern, "", user_input, flags=re.DOTALL)
        sanitizations_applied.append("cdata_sections_removed")

    # 8. Normalize whitespace (prevent whitespace obfuscation)
    # Must run BEFORE CSV formula prevention so the space prefix isn't stripped
    normalized_input = " ".join(user_input.split())
    if normalized_input != user_input:
        user_input = normalized_input
        sanitizations_applied.append("whitespace_normalized")

    # 9. CSV Formula Injection Prevention
    csv_formula_indicators = ["=", "+", "-", "@"]
    stripped = user_input.lstrip()
    if stripped and stripped[0] in csv_formula_indicators:
        user_input = " " + stripped  # Prefix with space to neutralize formula
        sanitizations_applied.append("csv_formula_prefix_neutralized")

    # 10. Invisible Unicode character removal
    _invisible_chars = [
        "\u200b",  # zero-width space
        "\u200c",  # zero-width non-joiner
        "\u200d",  # zero-width joiner
        "\ufeff",  # byte order mark / zero-width no-break space
        "\u00ad",  # soft hyphen
        "\u2060",  # word joiner
        "\u202e",  # right-to-left override
        "\u202d",  # left-to-right override
    ]
    cleaned = user_input
    for char in _invisible_chars:
        cleaned = cleaned.replace(char, "")
    if cleaned != user_input:
        user_input = cleaned
        sanitizations_applied.append("invisible_unicode_removed")

    if sanitizations_applied:
        log.debug("Sanitizations applied: %s", ", ".join(sanitizations_applied))

    return user_input, sanitizations_applied
