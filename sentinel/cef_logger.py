"""
Sentinel - CEF (Common Event Format) Logger
Produces ArcSight CEF-compliant log lines for SIEM integration.

CEF Format:
  CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

References:
  - ArcSight CEF Format (Rev 25)
  - Severity scale: 0 (lowest) to 10 (highest)

Usage:
    from sentinel.cef_logger import CEFLogger

    logger = CEFLogger()
    logger.log_detection(verdict="MALICIOUS", user_input="...", ...)
    # Writes CEF line to configured output (file, syslog, or stdout)
"""

import datetime
import logging
import logging.handlers
import os
import socket
import threading

# CEF severity mapping from our verdict/threat types
_VERDICT_SEVERITY = {
    "MALICIOUS": 8,
    "SAFE_REVIEW": 5,
    "SAFE": 1,
    "CRITICAL_COMPROMISE": 10,
}

_THREAT_SEVERITY = {
    "critical": 9,
    "high": 7,
    "medium": 5,
    "low": 2,
    "none": 0,
}

# CEF Signature IDs for different event types
SIG_DETECTION = "100"
SIG_PRE_FILTER_BLOCK = "101"
SIG_ML_DETECTION = "102"
SIG_LLM_DETECTION = "103"
SIG_ENSEMBLE_DETECTION = "104"
SIG_SESSION_ESCALATION = "200"
SIG_HONEY_TOKEN = "300"
SIG_RATE_LIMIT = "400"
SIG_SANITIZATION = "500"

# MCP tool call event signature IDs (600-649)
SIG_MCP_TOOL_BLOCKED = "600"
SIG_MCP_COMMAND_INJECTION = "601"
SIG_MCP_PATH_TRAVERSAL = "602"
SIG_MCP_SSRF = "603"
SIG_MCP_CREDENTIAL_LEAK = "604"
SIG_MCP_PROMPT_INJECTION = "605"
SIG_MCP_HONEY_TRIGGERED = "610"
SIG_MCP_POLICY_DENIED = "620"
SIG_MCP_RATE_LIMITED = "630"
SIG_MCP_ENCODING_ATTACK = "640"

# Signature name lookup
_SIG_NAMES = {
    SIG_DETECTION: "Attack Detected",
    SIG_PRE_FILTER_BLOCK: "Pre-Filter Block",
    SIG_ML_DETECTION: "ML Detection",
    SIG_LLM_DETECTION: "LLM Detection",
    SIG_ENSEMBLE_DETECTION: "Ensemble Detection",
    SIG_SESSION_ESCALATION: "Session Escalated",
    SIG_HONEY_TOKEN: "Honey Token Triggered",
    SIG_RATE_LIMIT: "Rate Limit Exceeded",
    SIG_SANITIZATION: "Input Sanitized",
    # MCP events
    SIG_MCP_TOOL_BLOCKED: "MCP Tool Blocked",
    SIG_MCP_COMMAND_INJECTION: "MCP Command Injection",
    SIG_MCP_PATH_TRAVERSAL: "MCP Path Traversal",
    SIG_MCP_SSRF: "MCP SSRF Attempt",
    SIG_MCP_CREDENTIAL_LEAK: "MCP Credential Leak",
    SIG_MCP_PROMPT_INJECTION: "MCP Prompt Injection in Args",
    SIG_MCP_HONEY_TRIGGERED: "MCP Honey Tool Triggered",
    SIG_MCP_POLICY_DENIED: "MCP Policy Denied",
    SIG_MCP_RATE_LIMITED: "MCP Rate Limited",
    SIG_MCP_ENCODING_ATTACK: "MCP Encoding Attack",
}


def _cef_escape(value):
    """Escape special CEF characters in extension values."""
    if value is None:
        return ""
    s = str(value)
    # CEF extension values: escape backslash, equals, newlines
    s = s.replace("\\", "\\\\")
    s = s.replace("=", "\\=")
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    return s


def _cef_header_escape(value):
    """Escape special characters in CEF header fields (pipe and backslash)."""
    if value is None:
        return ""
    s = str(value)
    s = s.replace("\\", "\\\\")
    s = s.replace("|", "\\|")
    return s


class CEFLogger:
    """
    Produces CEF-formatted log lines for SIEM integration.

    Supports output to:
    - File (default: sentinel_cef.log)
    - Syslog (UDP or TCP)
    - Stdout (for container/docker environments)

    Configuration via environment variables:
        CEF_OUTPUT: "file", "syslog", "stdout" (default: "file")
        CEF_FILE: path to CEF log file (default: "sentinel_cef.log")
        CEF_SYSLOG_HOST: syslog server host (default: "127.0.0.1")
        CEF_SYSLOG_PORT: syslog server port (default: "514")
        CEF_SYSLOG_PROTOCOL: "udp" or "tcp" (default: "udp")
        CEF_FACILITY: syslog facility (default: "local0")
    """

    VENDOR = "Sentinel"
    PRODUCT = "Sentinel"
    VERSION = "1.0"

    def __init__(
        self, output=None, file_path=None, syslog_host=None, syslog_port=None, syslog_protocol=None
    ):
        self.output = output or os.getenv("CEF_OUTPUT", "file")
        import pathlib

        raw_path = file_path or os.getenv("CEF_FILE", "sentinel_cef.log")
        # Validate file path to prevent path traversal
        resolved = pathlib.Path(raw_path).resolve()
        base_dir = pathlib.Path(os.getenv("CEF_BASE_DIR", ".")).resolve()
        try:
            resolved.relative_to(base_dir)
        except ValueError:
            raise ValueError(f"CEF file path {raw_path} resolves outside base directory {base_dir}")
        self.file_path = str(resolved)
        self.syslog_host = syslog_host or os.getenv("CEF_SYSLOG_HOST", "127.0.0.1")
        self.syslog_port = int(syslog_port or os.getenv("CEF_SYSLOG_PORT", "514"))
        self.syslog_protocol = syslog_protocol or os.getenv("CEF_SYSLOG_PROTOCOL", "udp")
        self._lock = threading.Lock()
        self._logger = None

        if self.output == "syslog":
            self._init_syslog()

    def _init_syslog(self):
        """Initialize syslog handler."""
        self._logger = logging.getLogger("sentinel_cef")
        self._logger.setLevel(logging.INFO)
        if not self._logger.handlers:
            sock_type = socket.SOCK_DGRAM if self.syslog_protocol == "udp" else socket.SOCK_STREAM
            handler = logging.handlers.SysLogHandler(
                address=(self.syslog_host, self.syslog_port),
                socktype=sock_type,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def _build_cef_line(self, sig_id, name, severity, extensions):
        """
        Build a CEF-formatted log line.

        Args:
            sig_id: Signature/event ID
            name: Event name
            severity: 0-10 severity
            extensions: dict of CEF extension key=value pairs
        """
        # Clamp severity to 0-10
        severity = max(0, min(10, severity))

        header = (
            f"CEF:0|"
            f"{_cef_header_escape(self.VENDOR)}|"
            f"{_cef_header_escape(self.PRODUCT)}|"
            f"{_cef_header_escape(self.VERSION)}|"
            f"{_cef_header_escape(sig_id)}|"
            f"{_cef_header_escape(name)}|"
            f"{severity}"
        )

        ext_parts = []
        for key, value in extensions.items():
            if value is not None:
                ext_parts.append(f"{key}={_cef_escape(value)}")

        ext_str = " ".join(ext_parts)
        return f"{header}|{ext_str}"

    def _emit(self, cef_line):
        """Write CEF line to configured output."""
        timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        hostname = socket.gethostname()
        full_line = f"{timestamp} {hostname} {cef_line}"

        if self.output == "stdout":
            print(full_line)
        elif self.output == "syslog" and self._logger:
            self._logger.info(cef_line)
        else:
            # File output (default)
            with self._lock:
                with open(self.file_path, "a", encoding="utf-8") as f:
                    f.write(full_line + "\n")

    def log_detection(
        self,
        verdict,
        user_input,
        session_id,
        source_ip,
        ml_result=None,
        llm_verdict=None,
        detection_method=None,
        sanitizations=None,
        attack_patterns=None,
        threat_mapping=None,
    ):
        """
        Log a detection event in CEF format.

        This is the primary logging method called after each message analysis.

        Args:
            verdict: Detection verdict string
            user_input: Original user message
            session_id: Session identifier
            source_ip: Client IP address
            ml_result: ML classifier result dict (optional)
            llm_verdict: LLM judge verdict string (optional)
            detection_method: How the threat was detected (optional)
            sanitizations: List of sanitizations applied (optional)
            attack_patterns: List of attack patterns found (optional)
            threat_mapping: Framework mapping dict from ShieldResult (optional)
        """
        # Determine signature ID and severity
        if detection_method == "pre_filter":
            sig_id = SIG_PRE_FILTER_BLOCK
        elif detection_method == "ml_only":
            sig_id = SIG_ML_DETECTION
        elif detection_method == "llm_only":
            sig_id = SIG_LLM_DETECTION
        elif detection_method == "ensemble":
            sig_id = SIG_ENSEMBLE_DETECTION
        else:
            sig_id = SIG_DETECTION

        name = _SIG_NAMES.get(sig_id, "Detection Event")
        severity = _VERDICT_SEVERITY.get(verdict, 3)

        # If ML provides severity, use the higher of the two
        if ml_result and ml_result.get("severity"):
            ml_sev = _THREAT_SEVERITY.get(ml_result["severity"], 0)
            severity = max(severity, ml_sev)

        # Build CEF extensions using standard and custom keys
        extensions = {
            # Standard CEF keys
            "src": source_ip,
            "dhost": socket.gethostname(),
            "dpt": "5000",
            "act": verdict,
            "msg": user_input[:200],  # Truncate for log readability
            "cs1": session_id,
            "cs1Label": "SessionID",
            "cs2": detection_method or "unknown",
            "cs2Label": "DetectionMethod",
        }

        # ML-specific extensions
        if ml_result:
            extensions["cfp1"] = ml_result.get("score", 0.0)
            extensions["cfp1Label"] = "MLAnomalyScore"
            extensions["cs3"] = ml_result.get("threat_type", "")
            extensions["cs3Label"] = "ThreatType"

        # LLM verdict
        if llm_verdict:
            extensions["cs4"] = llm_verdict
            extensions["cs4Label"] = "LLMVerdict"

        # Attack patterns
        if attack_patterns:
            extensions["cs5"] = ",".join(attack_patterns)
            extensions["cs5Label"] = "AttackPatterns"

        # Sanitizations
        if sanitizations:
            extensions["cs6"] = ",".join(sanitizations)
            extensions["cs6Label"] = "Sanitizations"

        # Framework mapping fields (cs7-cs9, cfp2)
        if threat_mapping:
            owasp_ids = threat_mapping.get("owasp_llm", [])
            if owasp_ids:
                extensions["cs7"] = ",".join(owasp_ids)
                extensions["cs7Label"] = "OWASPMapping"

            mitre_ids = threat_mapping.get("mitre_atlas", [])
            if mitre_ids:
                extensions["cs8"] = ",".join(mitre_ids)
                extensions["cs8Label"] = "MITREMapping"

            cwe_ids = threat_mapping.get("cwe", [])
            if cwe_ids:
                extensions["cs9"] = ",".join(cwe_ids)
                extensions["cs9Label"] = "CWEMapping"

            cvss = threat_mapping.get("cvss_base", 0.0)
            if cvss > 0:
                extensions["cfp2"] = cvss
                extensions["cfp2Label"] = "CVSSBaseScore"

        cef_line = self._build_cef_line(sig_id, name, severity, extensions)
        self._emit(cef_line)

    def log_session_escalation(self, session_id, source_ip, reason, threat_count):
        """Log a session escalation event."""
        extensions = {
            "src": source_ip,
            "cs1": session_id,
            "cs1Label": "SessionID",
            "msg": reason,
            "cnt": threat_count,
        }
        cef_line = self._build_cef_line(SIG_SESSION_ESCALATION, "Session Escalated", 7, extensions)
        self._emit(cef_line)

    def log_honey_token(self, token_id, source_ip):
        """Log a honey token trigger (critical compromise indicator)."""
        extensions = {
            "src": source_ip,
            "msg": f"Honey token accessed: {token_id}",
            "cs1": token_id,
            "cs1Label": "TokenID",
        }
        cef_line = self._build_cef_line(SIG_HONEY_TOKEN, "Honey Token Triggered", 10, extensions)
        self._emit(cef_line)

    def log_rate_limit(self, source_ip):
        """Log a rate limit violation."""
        extensions = {
            "src": source_ip,
            "msg": "Rate limit exceeded",
        }
        cef_line = self._build_cef_line(SIG_RATE_LIMIT, "Rate Limit Exceeded", 4, extensions)
        self._emit(cef_line)

    def log_mcp_event(self, tool_name, arguments_preview, session_id, source_ip, guard_result):
        """Log an MCP tool call event in CEF format.

        Args:
            tool_name: Name of the MCP tool called.
            arguments_preview: Truncated string preview of arguments.
            session_id: Session identifier.
            source_ip: Client IP address.
            guard_result: MCPGuardResult instance or dict with result fields.
        """
        # Determine the most specific signature ID based on findings
        result = guard_result if isinstance(guard_result, dict) else guard_result.to_dict()
        findings = result.get("findings", [])

        # Category -> CEF signature mapping
        _CATEGORY_SIG = {
            "command_injection": SIG_MCP_COMMAND_INJECTION,
            "path_traversal": SIG_MCP_PATH_TRAVERSAL,
            "ssrf": SIG_MCP_SSRF,
            "credential_leak": SIG_MCP_CREDENTIAL_LEAK,
            "prompt_injection": SIG_MCP_PROMPT_INJECTION,
            "encoding_attack": SIG_MCP_ENCODING_ATTACK,
        }

        if result.get("honey_triggered"):
            sig_id = SIG_MCP_HONEY_TRIGGERED
        elif result.get("blocked_reason", "").startswith("policy"):
            sig_id = SIG_MCP_POLICY_DENIED
        elif result.get("blocked_reason", "").startswith("rate_limit"):
            sig_id = SIG_MCP_RATE_LIMITED
        elif findings:
            # Use the first finding's category
            first_cat = (
                findings[0].get("category", "")
                if isinstance(findings[0], dict)
                else findings[0].category
            )
            sig_id = _CATEGORY_SIG.get(first_cat, SIG_MCP_TOOL_BLOCKED)
        else:
            sig_id = SIG_MCP_TOOL_BLOCKED

        name = _SIG_NAMES.get(sig_id, "MCP Event")

        # Determine severity from result
        severity_str = result.get("severity", "medium")
        severity = _THREAT_SEVERITY.get(severity_str, 5)
        if result.get("honey_triggered"):
            severity = 10  # Honey tool = confirmed attack

        extensions = {
            "src": source_ip,
            "dhost": socket.gethostname(),
            "act": "blocked" if not result.get("allowed", True) else "allowed",
            "msg": arguments_preview[:200],
            "cs1": session_id,
            "cs1Label": "SessionID",
            "cs2": tool_name,
            "cs2Label": "MCPToolName",
        }

        if result.get("blocked_reason"):
            extensions["cs3"] = result["blocked_reason"]
            extensions["cs3Label"] = "BlockReason"

        if findings:
            categories = set()
            for f in findings:
                cat = f.get("category", "") if isinstance(f, dict) else f.category
                if cat:
                    categories.add(cat)
            extensions["cs4"] = ",".join(sorted(categories))
            extensions["cs4Label"] = "FindingCategories"
            extensions["cnt"] = len(findings)

        threat_mapping = result.get("threat_mapping")
        if threat_mapping:
            owasp = threat_mapping.get("owasp_llm", [])
            if owasp:
                extensions["cs7"] = ",".join(owasp)
                extensions["cs7Label"] = "OWASPMapping"
            mitre = threat_mapping.get("mitre_atlas", [])
            if mitre:
                extensions["cs8"] = ",".join(mitre)
                extensions["cs8Label"] = "MITREMapping"
            cwe = threat_mapping.get("cwe", [])
            if cwe:
                extensions["cs9"] = ",".join(cwe)
                extensions["cs9Label"] = "CWEMapping"

        cef_line = self._build_cef_line(sig_id, name, severity, extensions)
        self._emit(cef_line)
