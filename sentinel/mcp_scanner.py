"""
Sentinel - MCP Argument Scanner
========================================
Specialized scanning of MCP tool call arguments for injection attacks,
path traversal, SSRF, credential leaks, encoding attacks, and prompt
injection embedded in tool arguments.

All scanners are pure Python with zero external dependencies and
designed for <2ms execution.

Usage:
    from sentinel.mcp_scanner import scan_mcp_arguments

    findings = scan_mcp_arguments("execute_code", {"code": "rm -rf /"})
    for f in findings:
        print(f.category, f.severity, f.message)
"""

import base64
import re
from dataclasses import dataclass
from typing import Any, List

from . import config


@dataclass
class MCPScanFinding:
    """A single finding from an MCP argument scan."""
    scanner: str          # Which scanner found it
    category: str         # Finding category (command_injection, path_traversal, etc.)
    severity: str         # critical, high, medium, low
    argument_key: str     # Dot-path to the argument (e.g. "args.command")
    matched_text: str     # The text fragment that matched
    message: str          # Human-readable description

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "category": self.category,
            "severity": self.severity,
            "argument_key": self.argument_key,
            "matched_text": self.matched_text[:200],
            "message": self.message,
        }


def scan_command_injection(value: str, key: str = "") -> List[MCPScanFinding]:
    """Scan a string value for shell command injection indicators."""
    findings = []
    val_lower = value.lower()

    # Check shell metacharacters
    for meta in config.MCP_SHELL_METACHARACTERS:
        if meta in value:
            findings.append(MCPScanFinding(
                scanner="mcp_command_injection",
                category="command_injection",
                severity="critical",
                argument_key=key,
                matched_text=meta,
                message=f"Shell metacharacter '{meta}' found in argument",
            ))
            break  # One finding per scanner per value

    # Check OS commands
    for cmd in config.MCP_OS_COMMANDS:
        if cmd in val_lower:
            findings.append(MCPScanFinding(
                scanner="mcp_command_injection",
                category="command_injection",
                severity="critical",
                argument_key=key,
                matched_text=cmd.strip(),
                message=f"OS command '{cmd.strip()}' found in argument",
            ))
            break

    # Check SQL injection patterns
    for pattern in config.MCP_SQL_PATTERNS:
        if pattern in val_lower:
            findings.append(MCPScanFinding(
                scanner="mcp_sql_injection",
                category="command_injection",
                severity="high",
                argument_key=key,
                matched_text=pattern,
                message=f"SQL injection pattern '{pattern}' found in argument",
            ))
            break

    return findings


def scan_path_traversal(value: str, key: str = "") -> List[MCPScanFinding]:
    """Scan a string value for path traversal attacks."""
    findings = []
    val_lower = value.lower()

    # Check traversal sequences
    for trav in config.MCP_PATH_TRAVERSAL:
        if trav in val_lower:
            findings.append(MCPScanFinding(
                scanner="mcp_path_traversal",
                category="path_traversal",
                severity="high",
                argument_key=key,
                matched_text=trav,
                message=f"Path traversal sequence '{trav}' found in argument",
            ))
            break

    # Check sensitive file paths
    for path in config.MCP_SENSITIVE_PATHS:
        if path in val_lower:
            findings.append(MCPScanFinding(
                scanner="mcp_path_traversal",
                category="path_traversal",
                severity="critical",
                argument_key=key,
                matched_text=path,
                message=f"Sensitive path '{path}' found in argument",
            ))
            break

    return findings


# Pre-compiled SSRF regexes
_IPV4_PRIVATE_RE = re.compile(
    r'(?:^|[/@])(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'  # 10.x.x.x
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'  # 172.16-31.x.x
    r'|192\.168\.\d{1,3}\.\d{1,3}'  # 192.168.x.x
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'  # 127.x.x.x
    r'|169\.254\.\d{1,3}\.\d{1,3}'  # Link-local
    r'|0\.0\.0\.0'
    r')(?:[:/\s]|$)'
)

_SSRF_HOSTS = [
    "localhost", "127.0.0.1", "0.0.0.0",
    "[::1]", "::1",
    "metadata.google.internal",
    "169.254.169.254",  # AWS/GCP metadata
    "metadata.google",
    "100.100.100.200",  # Alibaba metadata
]


def scan_ssrf(value: str, key: str = "") -> List[MCPScanFinding]:
    """Scan a string value for SSRF (Server-Side Request Forgery) indicators."""
    findings = []
    val_lower = value.lower()

    # Check known internal/metadata hostnames
    for host in _SSRF_HOSTS:
        if host in val_lower:
            findings.append(MCPScanFinding(
                scanner="mcp_ssrf",
                category="ssrf",
                severity="high",
                argument_key=key,
                matched_text=host,
                message=f"Internal/metadata host '{host}' found in argument",
            ))
            return findings  # One finding is enough

    # Check private IP ranges
    if _IPV4_PRIVATE_RE.search(value):
        match = _IPV4_PRIVATE_RE.search(value)
        findings.append(MCPScanFinding(
            scanner="mcp_ssrf",
            category="ssrf",
            severity="high",
            argument_key=key,
            matched_text=match.group(0).strip("/@"),
            message="Private/internal IP address found in argument",
        ))

    return findings


# Pre-compiled credential patterns
_CREDENTIAL_PATTERNS = [
    (re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*\S+', re.IGNORECASE), "API key"),
    (re.compile(r'(?:secret[_-]?key|secretkey)\s*[=:]\s*\S+', re.IGNORECASE), "Secret key"),
    (re.compile(r'(?:access[_-]?token|accesstoken)\s*[=:]\s*\S+', re.IGNORECASE), "Access token"),
    (re.compile(r'(?:auth[_-]?token|authorization)\s*[=:]\s*(?:Bearer\s+)?\S+', re.IGNORECASE), "Auth token"),
    (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*\S+', re.IGNORECASE), "Password"),
    (re.compile(r'(?:private[_-]?key|privatekey)\s*[=:]\s*\S+', re.IGNORECASE), "Private key"),
    (re.compile(r'(?:aws[_-]?access|aws[_-]?secret)\S*\s*[=:]\s*\S+', re.IGNORECASE), "AWS credential"),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', re.IGNORECASE), "Private key block"),
    (re.compile(r'ghp_[A-Za-z0-9_]{36}'), "GitHub personal access token"),
    (re.compile(r'sk-[A-Za-z0-9]{32,}'), "OpenAI/Stripe secret key"),
    (re.compile(r'xox[bpras]-[A-Za-z0-9-]+'), "Slack token"),
]


def scan_credentials(value: str, key: str = "") -> List[MCPScanFinding]:
    """Scan a string value for credentials, API keys, and tokens."""
    findings = []
    for pattern, desc in _CREDENTIAL_PATTERNS:
        match = pattern.search(value)
        if match:
            findings.append(MCPScanFinding(
                scanner="mcp_credentials",
                category="credential_leak",
                severity="high",
                argument_key=key,
                matched_text=match.group(0)[:50],
                message=f"{desc} detected in argument",
            ))
            return findings  # One credential finding is enough

    return findings


# Pre-compiled base64 regex (min 20 chars to avoid false positives)
_BASE64_RE = re.compile(r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
_HEX_RE = re.compile(r'(?:0x|\\x)[0-9a-fA-F]{8,}')
_UNICODE_ESCAPE_RE = re.compile(r'(?:\\u[0-9a-fA-F]{4}){3,}')


def scan_encoding_attacks(value: str, key: str = "") -> List[MCPScanFinding]:
    """Scan for encoded payloads (base64, hex, unicode escapes)."""
    findings = []

    # Base64 encoded payloads - decode and check for suspicious content
    for match in _BASE64_RE.finditer(value):
        encoded = match.group(0)
        if len(encoded) < 20:
            continue
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
            # Check decoded content for shell commands or injection
            decoded_lower = decoded.lower()
            suspicious_in_b64 = any(
                cmd in decoded_lower for cmd in
                ["rm ", "bash", "/bin/sh", "curl", "wget", "eval(", "exec(",
                 "import os", "subprocess", "system(", "drop table",
                 "ignore all", "forget everything"]
            )
            if suspicious_in_b64:
                findings.append(MCPScanFinding(
                    scanner="mcp_encoding",
                    category="encoding_attack",
                    severity="high",
                    argument_key=key,
                    matched_text=encoded[:40] + "...",
                    message="Base64-encoded suspicious payload detected",
                ))
                return findings
        except Exception:
            pass

    # Hex-encoded payloads
    if _HEX_RE.search(value):
        findings.append(MCPScanFinding(
            scanner="mcp_encoding",
            category="encoding_attack",
            severity="medium",
            argument_key=key,
            matched_text=_HEX_RE.search(value).group(0)[:40],
            message="Hex-encoded payload detected in argument",
        ))

    # Unicode escape sequences
    if _UNICODE_ESCAPE_RE.search(value):
        findings.append(MCPScanFinding(
            scanner="mcp_encoding",
            category="encoding_attack",
            severity="medium",
            argument_key=key,
            matched_text=_UNICODE_ESCAPE_RE.search(value).group(0)[:40],
            message="Unicode escape sequence payload detected",
        ))

    return findings


def scan_prompt_injection(value: str, key: str = "") -> List[MCPScanFinding]:
    """Scan for prompt injection patterns embedded in tool arguments."""
    findings = []
    val_lower = value.lower()

    # Reuse prompt injection patterns from config
    for pattern in config.DANGEROUS_PATTERNS:
        if pattern in val_lower:
            findings.append(MCPScanFinding(
                scanner="mcp_prompt_injection",
                category="prompt_injection",
                severity="critical",
                argument_key=key,
                matched_text=pattern,
                message=f"Prompt injection pattern '{pattern}' in tool argument",
            ))
            return findings

    # Check DAN jailbreak patterns
    for pattern in config.DAN_JAILBREAK_PATTERNS:
        if pattern in val_lower:
            findings.append(MCPScanFinding(
                scanner="mcp_prompt_injection",
                category="prompt_injection",
                severity="critical",
                argument_key=key,
                matched_text=pattern,
                message=f"Jailbreak pattern '{pattern}' in tool argument",
            ))
            return findings

    # Check override indicators
    for pattern in config.OVERRIDE_INDICATORS:
        if pattern in val_lower:
            findings.append(MCPScanFinding(
                scanner="mcp_prompt_injection",
                category="prompt_injection",
                severity="high",
                argument_key=key,
                matched_text=pattern,
                message=f"Instruction override '{pattern}' in tool argument",
            ))
            return findings

    # Check extraction indicators
    for pattern in config.EXTRACTION_INDICATORS:
        if pattern in val_lower:
            findings.append(MCPScanFinding(
                scanner="mcp_prompt_injection",
                category="prompt_injection",
                severity="high",
                argument_key=key,
                matched_text=pattern,
                message=f"Extraction attempt '{pattern}' in tool argument",
            ))
            return findings

    return findings


def scan_mcp_arguments(
    tool_name: str,
    arguments: Any,
    max_depth: int = 0,
) -> List[MCPScanFinding]:
    """
    Scan all string values in MCP tool arguments through all scanners.

    Recursively walks dicts and lists up to config.MCP_MAX_ARGUMENT_DEPTH.

    Args:
        tool_name: Name of the tool being called.
        arguments: The arguments dict/list/value to scan.
        max_depth: Override for max recursion depth (0 = use config).

    Returns:
        List of MCPScanFinding instances.
    """
    depth_limit = max_depth or config.MCP_MAX_ARGUMENT_DEPTH
    max_len = config.MCP_MAX_ARGUMENT_LENGTH
    findings: List[MCPScanFinding] = []

    def _walk(obj: Any, path: str, depth: int) -> None:
        if depth > depth_limit:
            findings.append(MCPScanFinding(
                scanner="mcp_depth_check",
                category="structural",
                severity="medium",
                argument_key=path,
                matched_text="",
                message=f"Argument nesting exceeds depth limit ({depth_limit})",
            ))
            return

        if isinstance(obj, dict):
            for k, v in obj.items():
                _walk(v, f"{path}.{k}" if path else k, depth + 1)
        elif isinstance(obj, (list, tuple)):
            for i, v in enumerate(obj):
                _walk(v, f"{path}[{i}]", depth + 1)
        elif isinstance(obj, str):
            # Length check
            if len(obj) > max_len:
                findings.append(MCPScanFinding(
                    scanner="mcp_length_check",
                    category="structural",
                    severity="medium",
                    argument_key=path,
                    matched_text=f"len={len(obj)}",
                    message=f"Argument value exceeds max length ({max_len})",
                ))
                # Still scan the truncated value
                obj = obj[:max_len]

            # Run all scanners on string values
            findings.extend(scan_command_injection(obj, path))
            findings.extend(scan_path_traversal(obj, path))
            findings.extend(scan_ssrf(obj, path))
            findings.extend(scan_credentials(obj, path))
            findings.extend(scan_encoding_attacks(obj, path))
            findings.extend(scan_prompt_injection(obj, path))

    _walk(arguments, "", 0)
    return findings
