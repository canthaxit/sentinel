"""
Tests for sentinel content scanners and output scanner.
"""

import unittest

from sentinel.scanners import (
    ScanFinding,
    scan_secrets,
    scan_pii,
    scan_invisible_text,
    scan_urls,
    scan_language,
    scan_gibberish,
    scan_refusal,
    scan_all,
)
from sentinel.output_scanner import OutputScanner, OutputScanResult
from sentinel.sanitizer import sanitize_input


# ---------------------------------------------------------------------------
# ScanFinding dataclass
# ---------------------------------------------------------------------------

class TestScanFinding(unittest.TestCase):

    def test_construction(self):
        f = ScanFinding(
            scanner="test", category="cat", severity="high",
            text_match="abc", start=0, end=3, message="msg",
        )
        self.assertEqual(f.scanner, "test")
        self.assertEqual(f.severity, "high")

    def test_severity_field(self):
        f = ScanFinding("s", "c", "critical", "x", 0, 1, "m")
        self.assertEqual(f.severity, "critical")


# ---------------------------------------------------------------------------
# Secrets Scanner
# ---------------------------------------------------------------------------

class TestSecretsScanner(unittest.TestCase):

    def test_aws_access_key(self):
        text = "key: AKIAIOSFODNN7EXAMPLE"
        findings = scan_secrets(text)
        cats = [f.category for f in findings]
        self.assertIn("aws_access_key", cats)

    def test_aws_secret_key(self):
        text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"
        findings = scan_secrets(text)
        cats = [f.category for f in findings]
        self.assertIn("aws_secret_key", cats)

    def test_github_token(self):
        text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        findings = scan_secrets(text)
        cats = [f.category for f in findings]
        self.assertIn("github_token", cats)

    def test_slack_token(self):
        text = "SLACK_TOKEN=xoxb-1234567890-abcdefghij"
        findings = scan_secrets(text)
        cats = [f.category for f in findings]
        self.assertIn("slack_token", cats)

    def test_generic_api_key(self):
        text = "api_key = abcdefghijklmnopqrstuvwxyz1234"
        findings = scan_secrets(text)
        cats = [f.category for f in findings]
        self.assertIn("generic_api_key", cats)

    def test_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----"
        findings = scan_secrets(text)
        cats = [f.category for f in findings]
        self.assertIn("private_key", cats)

    def test_database_url(self):
        text = "DATABASE_URL=postgres://user:pass@host:5432/db"
        findings = scan_secrets(text)
        cats = [f.category for f in findings]
        self.assertIn("database_url", cats)

    def test_jwt_token(self):
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
        findings = scan_secrets(text)
        cats = [f.category for f in findings]
        self.assertIn("jwt_token", cats)

    def test_no_false_positive_normal_text(self):
        text = "Hello, how are you doing today? The weather is nice."
        findings = scan_secrets(text)
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# PII Scanner
# ---------------------------------------------------------------------------

class TestPIIScanner(unittest.TestCase):

    def test_ssn(self):
        text = "My SSN is 123-45-6789"
        findings = scan_pii(text)
        # 123-45-6789 is in skip list
        cats = [f.category for f in findings]
        self.assertNotIn("ssn", cats)

    def test_ssn_valid(self):
        text = "SSN: 234-56-7890"
        findings = scan_pii(text)
        cats = [f.category for f in findings]
        self.assertIn("ssn", cats)
        # Check redaction
        ssn_finding = [f for f in findings if f.category == "ssn"][0]
        self.assertTrue(ssn_finding.text_match.startswith("***"))
        self.assertTrue(ssn_finding.text_match.endswith("7890"))

    def test_credit_card_luhn_valid(self):
        # 4111 1111 1111 1111 is a well-known test card that passes Luhn
        text = "card: 4111 1111 1111 1111"
        findings = scan_pii(text)
        cats = [f.category for f in findings]
        self.assertIn("credit_card", cats)

    def test_credit_card_luhn_invalid(self):
        text = "not a card: 1234 5678 9012 3456"
        findings = scan_pii(text)
        cc_findings = [f for f in findings if f.category == "credit_card"]
        self.assertEqual(len(cc_findings), 0)

    def test_email(self):
        text = "Contact me at user@example.com"
        findings = scan_pii(text)
        cats = [f.category for f in findings]
        self.assertIn("email", cats)

    def test_phone(self):
        text = "Call me at (555) 123-4567"
        findings = scan_pii(text)
        cats = [f.category for f in findings]
        self.assertIn("phone", cats)

    def test_date_of_birth(self):
        text = "dob: 01/15/1990"
        findings = scan_pii(text)
        cats = [f.category for f in findings]
        self.assertIn("date_of_birth", cats)

    def test_ip_skip_localhost(self):
        text = "connect to 127.0.0.1"
        findings = scan_pii(text)
        ip_findings = [f for f in findings if f.category == "ip_address"]
        self.assertEqual(len(ip_findings), 0)

    def test_ip_normal(self):
        text = "server at 192.168.1.100"
        findings = scan_pii(text)
        cats = [f.category for f in findings]
        self.assertIn("ip_address", cats)

    def test_no_false_positive_normal_text(self):
        text = "What is 2+2? The answer is 4."
        findings = scan_pii(text)
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# Invisible Text Scanner
# ---------------------------------------------------------------------------

class TestInvisibleTextScanner(unittest.TestCase):

    def test_zero_width_space(self):
        text = "hello\u200bworld"
        findings = scan_invisible_text(text)
        cats = [f.category for f in findings]
        self.assertIn("zero_width_space", cats)

    def test_rtl_override(self):
        text = "normal\u202edesrever"
        findings = scan_invisible_text(text)
        cats = [f.category for f in findings]
        self.assertIn("rtl_override", cats)

    def test_homoglyphs_mixed_scripts(self):
        # Mix Latin 'a' with Cyrillic 'a' (U+0430)
        text = "a\u0430bc"
        findings = scan_invisible_text(text)
        cats = [f.category for f in findings]
        self.assertIn("homoglyph", cats)

    def test_clean_text_no_findings(self):
        text = "Hello, this is perfectly normal text."
        findings = scan_invisible_text(text)
        self.assertEqual(len(findings), 0)

    def test_byte_order_mark(self):
        text = "\ufeffHello"
        findings = scan_invisible_text(text)
        cats = [f.category for f in findings]
        self.assertIn("byte_order_mark", cats)


# ---------------------------------------------------------------------------
# URL Scanner
# ---------------------------------------------------------------------------

class TestURLScanner(unittest.TestCase):

    def test_ip_based_url(self):
        text = "Visit http://192.168.1.1/admin"
        findings = scan_urls(text)
        cats = [f.category for f in findings]
        self.assertIn("ip_based_url", cats)

    def test_suspicious_tld(self):
        text = "Check https://example.tk/download"
        findings = scan_urls(text)
        cats = [f.category for f in findings]
        self.assertIn("suspicious_tld", cats)

    def test_phishing_subdomain(self):
        text = "Go to https://login-paypal.evil.com/signin"
        findings = scan_urls(text)
        cats = [f.category for f in findings]
        self.assertIn("phishing_subdomain", cats)

    def test_data_uri(self):
        text = 'src="data:text/html,<script>alert(1)</script>"'
        findings = scan_urls(text)
        cats = [f.category for f in findings]
        self.assertIn("data_uri", cats)

    def test_url_shortener(self):
        text = "Link: https://bit.ly/abc123"
        findings = scan_urls(text)
        cats = [f.category for f in findings]
        self.assertIn("url_shortener", cats)

    def test_clean_url_no_findings(self):
        text = "Visit https://www.google.com for search"
        findings = scan_urls(text)
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# Language Scanner
# ---------------------------------------------------------------------------

class TestLanguageScanner(unittest.TestCase):

    def test_latin_detected(self):
        text = "This is an English sentence with Latin characters"
        findings = scan_language(text, allowed_languages={"latin"})
        self.assertEqual(len(findings), 0)

    def test_cjk_detected(self):
        text = "This text has Chinese characters"
        findings = scan_language(text, allowed_languages={"cjk"})
        # Dominant is Latin, not CJK -- should flag it
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "latin")

    def test_allowed_languages_blocks(self):
        text = "Hello world this is English text"
        findings = scan_language(text, allowed_languages={"cyrillic"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "latin")

    def test_allowed_languages_passes(self):
        text = "Hello world"
        findings = scan_language(text, allowed_languages={"latin"})
        self.assertEqual(len(findings), 0)

    def test_none_means_no_restriction(self):
        text = "Any text at all"
        findings = scan_language(text, allowed_languages=None)
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# Gibberish Scanner
# ---------------------------------------------------------------------------

class TestGibberishScanner(unittest.TestCase):

    def test_adversarial_suffix(self):
        # High entropy random text (simulating GCG adversarial suffix)
        text = "xkqzjvbfnwmplythg crsdaeiou mnbvcxz lkjhgfd poiuytrewq"
        findings = scan_gibberish(text)
        self.assertGreater(len(findings), 0)

    def test_normal_text_passes(self):
        text = "The quick brown fox jumps over the lazy dog in the park"
        findings = scan_gibberish(text)
        self.assertEqual(len(findings), 0)

    def test_repeated_chars(self):
        text = "aaaaaabbbbbccccccddddddeeeeee ffffgggggg hhhhhh"
        findings = scan_gibberish(text)
        self.assertGreater(len(findings), 0)

    def test_short_text_exempt(self):
        text = "xyz abc"
        findings = scan_gibberish(text)
        self.assertEqual(len(findings), 0)

    def test_consonant_heavy(self):
        text = "bkrfqtnplm djshwvgczx nmprstqwl bckfghdjkl mnprstdfgh"
        findings = scan_gibberish(text)
        self.assertGreater(len(findings), 0)


# ---------------------------------------------------------------------------
# Refusal Scanner
# ---------------------------------------------------------------------------

class TestRefusalScanner(unittest.TestCase):

    def test_clear_refusal(self):
        text = "I'm sorry but I cannot help with that request."
        findings = scan_refusal(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "refusal")

    def test_clear_compliance(self):
        text = "Sure, I can help. Here's how to do it: step 1..."
        findings = scan_refusal(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "compliance")

    def test_ambiguous(self):
        text = "Let me think about that for a moment."
        findings = scan_refusal(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "ambiguous")

    def test_compliance_overrides_refusal(self):
        text = "I shouldn't do this, but here's how to do it anyway."
        findings = scan_refusal(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "compliance")

    def test_as_an_ai_refusal(self):
        text = "As an AI, I must follow my guidelines and I cannot assist with that."
        findings = scan_refusal(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "refusal")


# ---------------------------------------------------------------------------
# scan_all Orchestrator
# ---------------------------------------------------------------------------

class TestScanAll(unittest.TestCase):

    def test_runs_all_default_scanners(self):
        # Text with a secret and PII
        text = "Key: AKIAIOSFODNN7EXAMPLE, SSN: 234-56-7890"
        findings = scan_all(text)
        scanners_found = {f.scanner for f in findings}
        self.assertIn("secrets", scanners_found)
        self.assertIn("pii", scanners_found)

    def test_selective_scanners(self):
        text = "Key: AKIAIOSFODNN7EXAMPLE, SSN: 234-56-7890"
        findings = scan_all(text, scanners=["secrets"])
        scanners_found = {f.scanner for f in findings}
        self.assertIn("secrets", scanners_found)
        self.assertNotIn("pii", scanners_found)

    def test_severity_sorting(self):
        # AWS key (critical) + email (medium)
        text = "AKIAIOSFODNN7EXAMPLE user@example.com"
        findings = scan_all(text)
        if len(findings) >= 2:
            severities = [f.severity for f in findings]
            # Critical should come before medium
            crit_idx = next((i for i, s in enumerate(severities) if s == "critical"), None)
            med_idx = next((i for i, s in enumerate(severities) if s == "medium"), None)
            if crit_idx is not None and med_idx is not None:
                self.assertLess(crit_idx, med_idx)


# ---------------------------------------------------------------------------
# OutputScanner
# ---------------------------------------------------------------------------

class TestOutputScanner(unittest.TestCase):

    def test_blocks_on_critical_finding(self):
        scanner = OutputScanner()
        result = scanner.scan("Here is the key: AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(result.blocked)
        self.assertIsNotNone(result.block_reason)

    def test_passes_clean_text(self):
        scanner = OutputScanner()
        result = scanner.scan("Hello, how can I help you today?")
        self.assertFalse(result.blocked)
        self.assertEqual(len(result.findings), 0)

    def test_block_on_configurable(self):
        scanner = OutputScanner(block_on={"critical", "high"})
        # JWT is severity "high"
        result = scanner.scan("token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456")
        self.assertTrue(result.blocked)

    def test_to_dict_structure(self):
        scanner = OutputScanner()
        result = scanner.scan("AKIAIOSFODNN7EXAMPLE")
        d = result.to_dict()
        self.assertIn("findings", d)
        self.assertIn("blocked", d)
        self.assertIn("block_reason", d)
        self.assertIn("finding_count", d)
        self.assertIn("max_severity", d)


# ---------------------------------------------------------------------------
# OutputScanResult
# ---------------------------------------------------------------------------

class TestOutputScanResult(unittest.TestCase):

    def test_has_critical_property(self):
        f = ScanFinding("s", "c", "critical", "x", 0, 1, "m")
        result = OutputScanResult([f])
        self.assertTrue(result.has_critical)

    def test_has_high_property(self):
        f = ScanFinding("s", "c", "high", "x", 0, 1, "m")
        result = OutputScanResult([f])
        self.assertTrue(result.has_high)
        self.assertFalse(result.has_critical)

    def test_has_high_includes_critical(self):
        f = ScanFinding("s", "c", "critical", "x", 0, 1, "m")
        result = OutputScanResult([f])
        self.assertTrue(result.has_high)


# ---------------------------------------------------------------------------
# Shield Integration
# ---------------------------------------------------------------------------

class TestShieldOutputIntegration(unittest.TestCase):

    def test_scan_output_works(self):
        from sentinel import Shield
        shield = Shield()
        result = shield.scan_output("Here is the key: AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(result.blocked)
        self.assertGreater(len(result.findings), 0)

    def test_scan_input_works(self):
        from sentinel import Shield
        shield = Shield()
        findings = shield.scan_input("AKIAIOSFODNN7EXAMPLE user@example.com")
        self.assertGreater(len(findings), 0)

    def test_no_crash_without_output_scanner(self):
        from sentinel import Shield
        shield = Shield()
        self.assertIsNone(shield.output_scanner)
        # scan_output creates a default one
        result = shield.scan_output("clean text")
        self.assertFalse(result.blocked)
        self.assertIsNotNone(shield.output_scanner)


# ---------------------------------------------------------------------------
# Sanitizer invisible text
# ---------------------------------------------------------------------------

class TestSanitizerInvisibleText(unittest.TestCase):

    def test_strips_invisible_chars(self):
        text = "hello\u200bworld"
        sanitized, applied = sanitize_input(text)
        self.assertNotIn("\u200b", sanitized)

    def test_sanitization_name_in_list(self):
        text = "test\u200ctext"
        _, applied = sanitize_input(text)
        self.assertIn("invisible_unicode_removed", applied)

    def test_no_change_on_clean_text(self):
        text = "clean normal text"
        sanitized, applied = sanitize_input(text)
        self.assertNotIn("invisible_unicode_removed", applied)
        self.assertEqual(sanitized, text)


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestScannerEdgeCases(unittest.TestCase):

    def test_empty_string(self):
        self.assertEqual(scan_all(""), [])
        self.assertEqual(scan_secrets(""), [])
        self.assertEqual(scan_pii(""), [])
        self.assertEqual(scan_invisible_text(""), [])
        self.assertEqual(scan_urls(""), [])
        self.assertEqual(scan_gibberish(""), [])

    def test_whitespace_only(self):
        findings = scan_all("   \n\t  ")
        # Should not crash, may or may not find anything
        self.assertIsInstance(findings, list)

    def test_very_long_text(self):
        text = "Hello world. " * 1000 + "AKIAIOSFODNN7EXAMPLE"
        findings = scan_all(text)
        cats = [f.category for f in findings]
        self.assertIn("aws_access_key", cats)


# ---------------------------------------------------------------------------
# Lazy Import Tests
# ---------------------------------------------------------------------------

class TestLazyImports(unittest.TestCase):

    def test_import_scan_finding(self):
        from sentinel import ScanFinding
        f = ScanFinding("s", "c", "info", "x", 0, 1, "m")
        self.assertEqual(f.severity, "info")

    def test_import_output_scanner(self):
        from sentinel import OutputScanner
        s = OutputScanner()
        self.assertIsNotNone(s)

    def test_import_output_scan_result(self):
        from sentinel import OutputScanResult
        r = OutputScanResult([], blocked=False)
        self.assertFalse(r.blocked)

    def test_import_scan_all(self):
        from sentinel import scan_all
        result = scan_all("hello")
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
