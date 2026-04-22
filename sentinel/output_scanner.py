"""
Sentinel - Output Scanner
===================================
Scans LLM responses before they reach the user, detecting
secrets, PII, suspicious URLs, and other content safety issues.

Usage:
    from sentinel.output_scanner import OutputScanner

    scanner = OutputScanner(block_on={"critical", "high"})
    result = scanner.scan("Here is the AWS key: AKIA...")
    if result.blocked:
        print(f"Blocked: {result.block_reason}")
"""

import dataclasses

from .scanners import ScanFinding, scan_all


class OutputScanResult:
    """Result of scanning LLM output text."""

    __slots__ = ("block_reason", "blocked", "findings")

    def __init__(self, findings: list[ScanFinding], blocked: bool = False,
                 block_reason: str | None = None):
        self.findings = findings
        self.blocked = blocked
        self.block_reason = block_reason

    def to_dict(self) -> dict:
        return {
            "findings": [dataclasses.asdict(f) for f in self.findings],
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "finding_count": len(self.findings),
            "max_severity": self.findings[0].severity if self.findings else None,
        }

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity in ("critical", "high") for f in self.findings)


class OutputScanner:
    """Scans LLM output text through configured content scanners.

    Args:
        scanners: List of scanner names to enable, or None for all defaults
        block_on: Set of severities that trigger blocking (default: {"critical"})
        allowed_languages: Passed to language scanner
    """

    def __init__(self, scanners: list[str] | None = None,
                 block_on: set[str] | None = None,
                 allowed_languages: set[str] | None = None):
        self.scanners = scanners
        self.block_on = block_on or {"critical"}
        self.allowed_languages = allowed_languages

    def scan(self, text: str) -> OutputScanResult:
        """Scan text and return OutputScanResult."""
        findings = scan_all(
            text,
            scanners=self.scanners,
            allowed_languages=self.allowed_languages,
        )
        blocked = any(f.severity in self.block_on for f in findings)
        block_reason = findings[0].message if blocked and findings else None
        return OutputScanResult(findings, blocked, block_reason)
