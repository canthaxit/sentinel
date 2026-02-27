"""
Sentinel - Content Scanners
====================================
Seven zero-dependency content scanners for detecting secrets, PII,
invisible text, suspicious URLs, unexpected languages, gibberish
(adversarial suffixes), and LLM refusal patterns.

All scanners return lists of ScanFinding dataclass instances.
Use scan_all() to run multiple scanners in one call.
"""

import dataclasses
import math
import re
import unicodedata
from typing import List, Optional, Set

from . import config

# ---------------------------------------------------------------------------
# ScanFinding dataclass
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class ScanFinding:
    """A single finding from a content scanner."""
    scanner: str      # "secrets", "pii", "urls", "language", "gibberish", "refusal", "invisible_text"
    category: str     # Sub-type: "aws_key", "ssn", "phishing_url", etc.
    severity: str     # "critical", "high", "medium", "low", "info"
    text_match: str   # Matched text (redacted for PII)
    start: int        # Character offset in source text
    end: int          # Character offset end
    message: str      # Human-readable description


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---------------------------------------------------------------------------
# Scanner 1: Secrets
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    ("aws_access_key", "critical", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("aws_secret_key", "critical", re.compile(
        r'(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}')),
    ("github_token", "critical", re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}')),
    ("slack_token", "critical", re.compile(r'xox[baprs]-[0-9a-zA-Z-]+')),
    ("private_key", "critical", re.compile(
        r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----')),
    ("database_url", "critical", re.compile(
        r'(?i)(?:postgres|mysql|mongodb|redis)://[^\s\'"]+', re.ASCII)),
    ("jwt_token", "high", re.compile(
        r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+')),
    ("generic_api_key", "high", re.compile(
        r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*[\'"]?[A-Za-z0-9_\-]{20,}')),
    ("bearer_token", "high", re.compile(
        r'(?i)bearer\s+[A-Za-z0-9_\-.~+/]+=*')),
    ("basic_auth", "high", re.compile(
        r'(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}')),
]


def scan_secrets(text: str) -> List[ScanFinding]:
    """Scan text for leaked secrets, API keys, and credentials."""
    findings: List[ScanFinding] = []
    for category, severity, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            findings.append(ScanFinding(
                scanner="secrets",
                category=category,
                severity=severity,
                text_match=m.group()[:12] + "..." if len(m.group()) > 15 else m.group(),
                start=m.start(),
                end=m.end(),
                message=f"Possible {category.replace('_', ' ')} detected",
            ))
    return findings


# ---------------------------------------------------------------------------
# Scanner 2: PII
# ---------------------------------------------------------------------------

def _luhn_check(number_str: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in number_str if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


_PII_PATTERNS = [
    ("ssn", "critical", re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    ("credit_card", "critical", re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b')),
    ("email", "medium", re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
    ("phone", "medium", re.compile(
        r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')),
    ("date_of_birth", "medium", re.compile(
        r'(?i)\b(?:dob|date of birth|born)\s*[:\s]\s*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b')),
    ("ip_address", "low", re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
]

_SKIP_SSN = {"000-00-0000", "999-99-9999", "123-45-6789"}
_SKIP_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}


def _redact(text: str, category: str) -> str:
    """Redact PII for display in findings."""
    if category == "ssn":
        return "***-**-" + text[-4:]
    if category == "credit_card":
        digits = re.sub(r'\D', '', text)
        return "****-****-****-" + digits[-4:]
    if category == "email":
        parts = text.split("@")
        return parts[0][0] + "***@" + parts[1] if len(parts) == 2 else "***"
    return text


def scan_pii(text: str) -> List[ScanFinding]:
    """Scan text for personally identifiable information."""
    findings: List[ScanFinding] = []
    for category, severity, pattern in _PII_PATTERNS:
        for m in pattern.finditer(text):
            matched = m.group()
            # SSN skip known invalid patterns
            if category == "ssn" and matched in _SKIP_SSN:
                continue
            # Credit card: Luhn validation
            if category == "credit_card":
                digits_only = re.sub(r'\D', '', matched)
                if not _luhn_check(digits_only):
                    continue
            # IP address: skip localhost/broadcast
            if category == "ip_address" and matched in _SKIP_IPS:
                continue
            findings.append(ScanFinding(
                scanner="pii",
                category=category,
                severity=severity,
                text_match=_redact(matched, category),
                start=m.start(),
                end=m.end(),
                message=f"Possible {category.replace('_', ' ')} detected",
            ))
    return findings


# ---------------------------------------------------------------------------
# Scanner 3: Invisible Text
# ---------------------------------------------------------------------------

_INVISIBLE_CHARS = {
    '\u200b': ("zero_width_space", "high"),
    '\u200c': ("zero_width_non_joiner", "high"),
    '\u200d': ("zero_width_joiner", "high"),
    '\ufeff': ("byte_order_mark", "medium"),
    '\u202e': ("rtl_override", "high"),
    '\u202d': ("ltr_override", "high"),
    '\u00ad': ("soft_hyphen", "medium"),
    '\u2060': ("word_joiner", "medium"),
}

# Cyrillic lookalikes for Latin characters
_CYRILLIC_LOOKALIKES = set('\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u04bb')
_LATIN_CHARS = set('aeopscuxijh')


def scan_invisible_text(text: str) -> List[ScanFinding]:
    """Scan text for invisible Unicode characters and homoglyphs."""
    findings: List[ScanFinding] = []

    # Check for invisible characters
    for i, ch in enumerate(text):
        if ch in _INVISIBLE_CHARS:
            category, severity = _INVISIBLE_CHARS[ch]
            findings.append(ScanFinding(
                scanner="invisible_text",
                category=category,
                severity=severity,
                text_match=f"U+{ord(ch):04X}",
                start=i,
                end=i + 1,
                message=f"Invisible character {category.replace('_', ' ')} at position {i}",
            ))

    # Check for homoglyph mixing (Cyrillic + Latin in same word)
    has_latin = False
    has_cyrillic = False
    for ch in text:
        if ch in _LATIN_CHARS:
            has_latin = True
        if ch in _CYRILLIC_LOOKALIKES:
            has_cyrillic = True
        if has_latin and has_cyrillic:
            break

    if has_latin and has_cyrillic:
        findings.append(ScanFinding(
            scanner="invisible_text",
            category="homoglyph",
            severity="high",
            text_match="mixed Latin/Cyrillic scripts",
            start=0,
            end=len(text),
            message="Text contains mixed Latin and Cyrillic lookalike characters (possible homoglyph attack)",
        ))

    return findings


# ---------------------------------------------------------------------------
# Scanner 4: URLs
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+')
_IP_URL_PATTERN = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
_DATA_URI_PATTERN = re.compile(r'data:[a-zA-Z]+/[a-zA-Z]+[;,]', re.IGNORECASE)
_PHISHING_SUBDOMAIN = re.compile(
    r'(?:login|signin|secure|account|verify|update|confirm|banking)'
    r'[-.]'
    r'(?:paypal|google|microsoft|apple|amazon|facebook|netflix|bank)',
    re.IGNORECASE,
)


def scan_urls(text: str) -> List[ScanFinding]:
    """Scan text for suspicious URLs."""
    findings: List[ScanFinding] = []

    # Data URIs
    for m in _DATA_URI_PATTERN.finditer(text):
        findings.append(ScanFinding(
            scanner="urls", category="data_uri", severity="high",
            text_match=m.group(), start=m.start(), end=m.end(),
            message="Data URI detected (potential XSS vector)",
        ))

    for m in _URL_PATTERN.finditer(text):
        url = m.group()
        url_lower = url.lower()

        # IP-based URLs
        if _IP_URL_PATTERN.match(url):
            findings.append(ScanFinding(
                scanner="urls", category="ip_based_url", severity="high",
                text_match=url, start=m.start(), end=m.end(),
                message="IP-based URL detected",
            ))
            continue

        # Extract domain for further checks
        domain_match = re.search(r'(?:https?://|www\.)([\w.-]+)', url_lower)
        if not domain_match:
            continue
        domain = domain_match.group(1)

        # Suspicious TLDs
        for tld in config.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append(ScanFinding(
                    scanner="urls", category="suspicious_tld", severity="medium",
                    text_match=url, start=m.start(), end=m.end(),
                    message=f"URL uses suspicious TLD: {tld}",
                ))
                break

        # URL shorteners
        for shortener in config.URL_SHORTENERS:
            if domain == shortener or domain.endswith("." + shortener):
                findings.append(ScanFinding(
                    scanner="urls", category="url_shortener", severity="medium",
                    text_match=url, start=m.start(), end=m.end(),
                    message=f"URL shortener detected: {shortener}",
                ))
                break

        # Phishing subdomains
        if _PHISHING_SUBDOMAIN.search(domain):
            findings.append(ScanFinding(
                scanner="urls", category="phishing_subdomain", severity="high",
                text_match=url, start=m.start(), end=m.end(),
                message="URL contains phishing-style subdomain pattern",
            ))

        # Excessively long URLs
        if len(url) > 200:
            findings.append(ScanFinding(
                scanner="urls", category="long_url", severity="medium",
                text_match=url[:50] + "...", start=m.start(), end=m.end(),
                message=f"Excessively long URL ({len(url)} chars)",
            ))

    return findings


# ---------------------------------------------------------------------------
# Scanner 5: Language
# ---------------------------------------------------------------------------

_SCRIPT_RANGES = {
    "latin": lambda c: ('\u0041' <= c <= '\u024F'),
    "cyrillic": lambda c: ('\u0400' <= c <= '\u04FF'),
    "cjk": lambda c: ('\u4E00' <= c <= '\u9FFF') or ('\u3400' <= c <= '\u4DBF'),
    "arabic": lambda c: ('\u0600' <= c <= '\u06FF'),
    "devanagari": lambda c: ('\u0900' <= c <= '\u097F'),
    "hangul": lambda c: ('\uAC00' <= c <= '\uD7AF') or ('\u1100' <= c <= '\u11FF'),
    "thai": lambda c: ('\u0E00' <= c <= '\u0E7F'),
}


def scan_language(text: str, allowed_languages: Optional[Set[str]] = None) -> List[ScanFinding]:
    """Detect dominant script/language and flag if not in allowed set."""
    if allowed_languages is None:
        allowed_languages = config.ALLOWED_LANGUAGES
    if allowed_languages is None:
        return []

    counts = {script: 0 for script in _SCRIPT_RANGES}
    total = 0
    for ch in text:
        for script, check_fn in _SCRIPT_RANGES.items():
            if check_fn(ch):
                counts[script] += 1
                total += 1
                break

    if total == 0:
        return []

    dominant_script = max(counts, key=counts.get)
    if counts[dominant_script] == 0:
        return []

    if dominant_script not in allowed_languages:
        pct = counts[dominant_script] / total * 100
        return [ScanFinding(
            scanner="language",
            category=dominant_script,
            severity="medium",
            text_match=f"{dominant_script} ({pct:.0f}%)",
            start=0,
            end=len(text),
            message=f"Text uses {dominant_script} script which is not in allowed languages: {allowed_languages}",
        )]

    return []


# ---------------------------------------------------------------------------
# Scanner 6: Gibberish
# ---------------------------------------------------------------------------

_COMMON_WORDS = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
    "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her",
    "she", "or", "an", "will", "my", "one", "all", "would", "there",
    "their", "what", "so", "up", "out", "if", "about", "who", "get",
    "which", "go", "me", "when", "make", "can", "like", "time", "no",
    "just", "him", "know", "take", "people", "into", "year", "your",
    "good", "some", "could", "them", "see", "other", "than", "then",
    "now", "look", "only", "come", "its", "over", "think", "also",
    "back", "after", "use", "two", "how", "our", "work", "first",
    "well", "way", "even", "new", "want", "because", "any", "these",
    "give", "day", "most", "us", "is", "are", "was", "were", "been",
    "has", "had", "did", "does", "more", "very", "much", "too", "here",
    "where", "why", "should", "each", "still", "between", "high", "long",
    "made", "find", "own", "while", "may", "must", "tell", "through",
    "before", "right", "old", "every", "same", "off", "need", "house",
    "let", "keep", "world", "never", "small", "last", "hand", "under",
    "turn", "ask", "try", "large", "set", "big", "help", "line", "end",
    "point", "run", "move", "live", "night", "call", "open", "start",
    "might", "show", "part", "place", "life", "number", "name", "put",
    "read", "city", "play", "again", "many", "next", "few", "head",
    "left", "another", "side", "children", "water", "without", "being",
    "once", "done", "home", "school", "system", "data", "test", "user",
    "file", "code", "message", "error", "please", "thank", "hello",
    "yes", "ok", "sure", "question", "answer", "information",
}

_VOWELS = set("aeiouAEIOU")


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of character distribution."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def scan_gibberish(text: str) -> List[ScanFinding]:
    """Detect gibberish/adversarial text using heuristic scoring."""
    if len(text) < config.GIBBERISH_MIN_LENGTH:
        return []

    words = text.split()
    if not words:
        return []

    scores = []

    # 1. Character entropy
    entropy = _shannon_entropy(text)
    if entropy > 5.0 or entropy < 2.0:
        scores.append(1.0)
    elif entropy > 4.5 or entropy < 2.5:
        scores.append(0.6)
    else:
        scores.append(0.0)

    # 2. Vowel ratio
    alpha_chars = [c for c in text if c.isalpha()]
    if alpha_chars:
        vowel_ratio = sum(1 for c in alpha_chars if c in _VOWELS) / len(alpha_chars)
        if vowel_ratio < 0.15 or vowel_ratio > 0.60:
            scores.append(1.0)
        elif vowel_ratio < 0.20 or vowel_ratio > 0.55:
            scores.append(0.5)
        else:
            scores.append(0.0)
    else:
        scores.append(0.5)

    # 3. Average word length
    avg_len = sum(len(w) for w in words) / len(words)
    if avg_len > 12 or avg_len < 2:
        scores.append(1.0)
    elif avg_len > 9:
        scores.append(0.5)
    else:
        scores.append(0.0)

    # 4. Repeated character ratio
    repeat_count = 0
    for i in range(2, len(text)):
        if text[i] == text[i - 1] == text[i - 2]:
            repeat_count += 1
    repeat_ratio = repeat_count / max(len(text) - 2, 1)
    if repeat_ratio > 0.1:
        scores.append(1.0)
    elif repeat_ratio > 0.05:
        scores.append(0.5)
    else:
        scores.append(0.0)

    # 5. Dictionary word ratio
    lower_words = [w.lower().strip(".,!?;:\"'()[]{}") for w in words]
    dict_hits = sum(1 for w in lower_words if w in _COMMON_WORDS)
    dict_ratio = dict_hits / len(lower_words) if lower_words else 0
    if dict_ratio < 0.10:
        scores.append(1.0)
    elif dict_ratio < 0.25:
        scores.append(0.6)
    else:
        scores.append(0.0)

    overall = sum(scores) / len(scores)

    if overall >= config.GIBBERISH_THRESHOLD_HIGH:
        return [ScanFinding(
            scanner="gibberish", category="adversarial_text", severity="high",
            text_match=text[:40] + "..." if len(text) > 40 else text,
            start=0, end=len(text),
            message=f"Text appears to be gibberish/adversarial (score: {overall:.2f})",
        )]
    elif overall >= config.GIBBERISH_THRESHOLD_MEDIUM:
        return [ScanFinding(
            scanner="gibberish", category="adversarial_text", severity="medium",
            text_match=text[:40] + "..." if len(text) > 40 else text,
            start=0, end=len(text),
            message=f"Text may be gibberish/adversarial (score: {overall:.2f})",
        )]

    return []


# ---------------------------------------------------------------------------
# Scanner 7: Refusal
# ---------------------------------------------------------------------------

_REFUSAL_INDICATORS = [
    "i cannot", "i can't", "i'm unable", "i'm sorry but i",
    "i must decline", "i will not", "i won't", "i shouldn't",
    "i must not", "not appropriate", "against my guidelines",
    "violates my policy", "as an ai", "as a language model",
]

_COMPLIANCE_INDICATORS = [
    "here's how", "here is how", "the password is", "the secret is",
    "sure, i can", "of course", "certainly, here",
    "step 1:", "first, you need to",
]


def scan_refusal(text: str) -> List[ScanFinding]:
    """Classify LLM output as refusal, compliance, or ambiguous."""
    text_lower = text.lower()

    # Check compliance FIRST (overrides refusal if present)
    has_compliance = any(p in text_lower for p in _COMPLIANCE_INDICATORS)
    # Code blocks with implementation
    if "```" in text and not has_compliance:
        # Check if there's actual code (not just an empty block)
        code_content = re.search(r'```\w*\n(.+?)```', text, re.DOTALL)
        if code_content and len(code_content.group(1).strip()) > 20:
            has_compliance = True

    if has_compliance:
        return [ScanFinding(
            scanner="refusal", category="compliance", severity="info",
            text_match=text[:60] + "..." if len(text) > 60 else text,
            start=0, end=len(text),
            message="LLM response appears to comply with the request",
        )]

    has_refusal = any(p in text_lower for p in _REFUSAL_INDICATORS)
    # Also check config refusal patterns (uppercase)
    if not has_refusal:
        text_upper = text.upper()
        has_refusal = any(p in text_upper for p in config.REFUSAL_PATTERNS)

    if has_refusal:
        return [ScanFinding(
            scanner="refusal", category="refusal", severity="info",
            text_match=text[:60] + "..." if len(text) > 60 else text,
            start=0, end=len(text),
            message="LLM response appears to refuse the request",
        )]

    return [ScanFinding(
        scanner="refusal", category="ambiguous", severity="info",
        text_match=text[:60] + "..." if len(text) > 60 else text,
        start=0, end=len(text),
        message="LLM response classification is ambiguous",
    )]


# ---------------------------------------------------------------------------
# Scanner 8: AI-Generated Text (opt-in)
# ---------------------------------------------------------------------------

_HEDGE_PHRASES = [
    "it is important to note", "it's worth noting", "it should be noted",
    "it is worth mentioning", "it's important to", "one might consider",
    "it is generally", "it is recommended", "it may be helpful",
    "it could be argued", "on the other hand", "in conclusion",
    "however, it is", "furthermore,", "additionally,", "moreover,",
    "nevertheless,", "in this context",
]


def scan_ai_generated(text: str, threshold: float = 0.65) -> List[ScanFinding]:
    """Heuristic scanner to fingerprint LLM-authored prompt injections.

    Uses five signals: sentence length uniformity, type-token ratio,
    hedging language frequency, repetitive phrasing, and vocabulary
    richness. This is opt-in and NOT included in scan_all() by default.

    Args:
        text: The text to analyze.
        threshold: Score above which to flag as likely AI-generated (0-1).

    Returns:
        List of ScanFinding (empty if below threshold).
    """
    if len(text) < 100:
        return []

    sentences = re.split(r'[.!?\n]+', text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 5]
    if len(sentences) < 3:
        return []

    words = text.lower().split()
    if len(words) < 20:
        return []

    scores = []

    # 1. Sentence length uniformity (LLMs produce uniform sentence lengths)
    lengths = [len(s.split()) for s in sentences]
    mean_len = sum(lengths) / len(lengths)
    if mean_len > 0:
        variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
        cv = (variance ** 0.5) / mean_len  # coefficient of variation
        # Low CV = very uniform = likely AI; humans have CV > 0.5 typically
        if cv < 0.25:
            scores.append(1.0)
        elif cv < 0.40:
            scores.append(0.6)
        else:
            scores.append(0.0)
    else:
        scores.append(0.0)

    # 2. Type-token ratio (TTR) - AI tends to have moderate TTR
    unique_words = set(words)
    ttr = len(unique_words) / len(words)
    # AI text: TTR typically 0.40-0.60; very high or low is more human
    if 0.35 <= ttr <= 0.55:
        scores.append(0.7)
    elif 0.30 <= ttr <= 0.65:
        scores.append(0.3)
    else:
        scores.append(0.0)

    # 3. Hedging language frequency
    text_lower = text.lower()
    hedge_count = sum(1 for p in _HEDGE_PHRASES if p in text_lower)
    hedge_density = hedge_count / len(sentences)
    if hedge_density > 0.3:
        scores.append(1.0)
    elif hedge_density > 0.15:
        scores.append(0.6)
    else:
        scores.append(0.0)

    # 4. Repetitive phrasing (bigram repetition rate)
    bigrams = [f"{words[i]} {words[i+1]}" for i in range(len(words) - 1)]
    if bigrams:
        unique_bigrams = set(bigrams)
        bigram_repeat_rate = 1.0 - (len(unique_bigrams) / len(bigrams))
        if bigram_repeat_rate > 0.3:
            scores.append(0.8)
        elif bigram_repeat_rate > 0.15:
            scores.append(0.4)
        else:
            scores.append(0.0)
    else:
        scores.append(0.0)

    # 5. Vocabulary richness (hapax legomena ratio)
    word_freq = {}
    for w in words:
        word_freq[w] = word_freq.get(w, 0) + 1
    hapax = sum(1 for v in word_freq.values() if v == 1)
    hapax_ratio = hapax / len(words) if words else 0
    # AI tends to have lower hapax ratio (reuses vocabulary more)
    if hapax_ratio < 0.35:
        scores.append(0.7)
    elif hapax_ratio < 0.50:
        scores.append(0.3)
    else:
        scores.append(0.0)

    overall = sum(scores) / len(scores) if scores else 0

    if overall >= threshold:
        return [ScanFinding(
            scanner="ai_generated",
            category="llm_authored",
            severity="medium",
            text_match=text[:60] + "..." if len(text) > 60 else text,
            start=0,
            end=len(text),
            message=f"Text appears LLM-authored (score: {overall:.2f})",
        )]

    return []


# ---------------------------------------------------------------------------
# Orchestrator: scan_all
# ---------------------------------------------------------------------------

_ALL_SCANNERS = {
    "secrets": scan_secrets,
    "pii": scan_pii,
    "invisible_text": scan_invisible_text,
    "urls": scan_urls,
    "language": scan_language,
    "gibberish": scan_gibberish,
    "refusal": scan_refusal,
}

_DEFAULT_SCANNERS = {"secrets", "pii", "invisible_text", "urls", "language", "gibberish"}


def scan_all(
    text: str,
    scanners: Optional[List[str]] = None,
    allowed_languages: Optional[Set[str]] = None,
) -> List[ScanFinding]:
    """Run multiple scanners on text.

    Args:
        text: Text to scan
        scanners: List of scanner names to run, or None for defaults
            (all except refusal). Pass ["refusal"] or include "refusal"
            explicitly to enable it.
        allowed_languages: Passed to language scanner

    Returns:
        List of ScanFinding sorted by severity (critical first)
    """
    if not text:
        return []

    active = set(scanners) if scanners else _DEFAULT_SCANNERS

    findings: List[ScanFinding] = []
    for name in active:
        fn = _ALL_SCANNERS.get(name)
        if fn is None:
            continue
        if name == "language":
            findings.extend(fn(text, allowed_languages=allowed_languages))
        else:
            findings.extend(fn(text))

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    return findings
