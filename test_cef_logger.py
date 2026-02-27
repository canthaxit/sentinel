"""
Tests for sentinel.cef_logger
Run: python -m pytest test_cef_logger.py -v
"""

import os
import tempfile
import pytest
from sentinel.cef_logger import (
    CEFLogger, _cef_escape, _cef_header_escape,
    SIG_DETECTION, SIG_PRE_FILTER_BLOCK, SIG_ML_DETECTION,
    SIG_LLM_DETECTION, SIG_ENSEMBLE_DETECTION,
    SIG_SESSION_ESCALATION, SIG_HONEY_TOKEN, SIG_RATE_LIMIT,
)


class TestCEFEscaping:
    def test_escape_backslash(self):
        assert _cef_escape("a\\b") == "a\\\\b"

    def test_escape_equals(self):
        assert _cef_escape("key=value") == "key\\=value"

    def test_escape_newline(self):
        assert _cef_escape("line1\nline2") == "line1\\nline2"

    def test_escape_carriage_return(self):
        assert _cef_escape("line1\rline2") == "line1\\rline2"

    def test_escape_none(self):
        assert _cef_escape(None) == ""

    def test_header_escape_pipe(self):
        assert _cef_header_escape("a|b") == "a\\|b"

    def test_header_escape_backslash(self):
        assert _cef_header_escape("a\\b") == "a\\\\b"


class TestCEFLoggerBuild:
    def test_build_basic_line(self):
        logger = CEFLogger(output="stdout")
        line = logger._build_cef_line("100", "Test Event", 5, {"src": "1.2.3.4"})
        assert line.startswith("CEF:0|Sentinel|Sentinel|1.0|100|Test Event|5|")
        assert "src=1.2.3.4" in line

    def test_severity_clamping_high(self):
        logger = CEFLogger(output="stdout")
        line = logger._build_cef_line("100", "Test", 15, {})
        assert "|10|" in line

    def test_severity_clamping_low(self):
        logger = CEFLogger(output="stdout")
        line = logger._build_cef_line("100", "Test", -5, {})
        assert "|0|" in line

    def test_multiple_extensions(self):
        logger = CEFLogger(output="stdout")
        line = logger._build_cef_line("100", "Test", 5, {
            "src": "1.2.3.4",
            "act": "MALICIOUS",
            "msg": "test message",
        })
        assert "src=1.2.3.4" in line
        assert "act=MALICIOUS" in line
        assert "msg=test message" in line

    def test_none_extensions_skipped(self):
        logger = CEFLogger(output="stdout")
        line = logger._build_cef_line("100", "Test", 5, {
            "src": "1.2.3.4",
            "cs1": None,
        })
        assert "src=1.2.3.4" in line
        assert "cs1" not in line

    def test_header_special_chars(self):
        logger = CEFLogger(output="stdout")
        line = logger._build_cef_line("100", "Test|Event", 5, {})
        assert "Test\\|Event" in line


class TestCEFLoggerFile:
    def test_file_output(self, tmp_path):
        log_file = str(tmp_path / "test_cef.log")
        logger = CEFLogger(output="file", file_path=log_file)
        logger.log_detection(
            verdict="MALICIOUS",
            user_input="test attack",
            session_id="sess-1",
            source_ip="10.0.0.1",
            detection_method="pre_filter",
        )
        with open(log_file, "r") as f:
            content = f.read()
        assert "CEF:0" in content
        assert "MALICIOUS" in content
        assert "10.0.0.1" in content

    def test_multiple_writes(self, tmp_path):
        log_file = str(tmp_path / "test_cef.log")
        logger = CEFLogger(output="file", file_path=log_file)
        logger.log_detection(
            verdict="SAFE", user_input="hello",
            session_id="s1", source_ip="1.1.1.1", detection_method="ml_only",
        )
        logger.log_detection(
            verdict="MALICIOUS", user_input="attack",
            session_id="s2", source_ip="2.2.2.2", detection_method="pre_filter",
        )
        with open(log_file, "r") as f:
            lines = f.readlines()
        assert len(lines) == 2

    def test_honey_token_file(self, tmp_path):
        log_file = str(tmp_path / "test_cef.log")
        logger = CEFLogger(output="file", file_path=log_file)
        logger.log_honey_token("token-abc", "10.0.0.1")
        with open(log_file, "r") as f:
            content = f.read()
        assert "300" in content  # SIG_HONEY_TOKEN
        assert "token-abc" in content
        assert "|10|" in content  # severity 10

    def test_rate_limit_file(self, tmp_path):
        log_file = str(tmp_path / "test_cef.log")
        logger = CEFLogger(output="file", file_path=log_file)
        logger.log_rate_limit("10.0.0.5")
        with open(log_file, "r") as f:
            content = f.read()
        assert "400" in content  # SIG_RATE_LIMIT
        assert "10.0.0.5" in content

    def test_session_escalation_file(self, tmp_path):
        log_file = str(tmp_path / "test_cef.log")
        logger = CEFLogger(output="file", file_path=log_file)
        logger.log_session_escalation("sess-1", "10.0.0.1", "threat_count=3", 3)
        with open(log_file, "r") as f:
            content = f.read()
        assert "200" in content  # SIG_SESSION_ESCALATION
        assert "threat_count" in content


class TestCEFLoggerDetectionMethods:
    def test_pre_filter_sig(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = CEFLogger(output="file", file_path=log_file)
        logger.log_detection(
            verdict="MALICIOUS", user_input="test",
            session_id="s1", source_ip="1.1.1.1",
            detection_method="pre_filter",
        )
        with open(log_file) as f:
            content = f.read()
        assert f"|{SIG_PRE_FILTER_BLOCK}|" in content

    def test_ml_only_sig(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = CEFLogger(output="file", file_path=log_file)
        logger.log_detection(
            verdict="MALICIOUS", user_input="test",
            session_id="s1", source_ip="1.1.1.1",
            detection_method="ml_only",
            ml_result={"score": 0.95, "threat_type": "injection", "severity": "high", "processing_time_ms": 1},
        )
        with open(log_file) as f:
            content = f.read()
        assert f"|{SIG_ML_DETECTION}|" in content
        assert "cfp1=0.95" in content
        assert "cs3=injection" in content

    def test_llm_only_sig(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = CEFLogger(output="file", file_path=log_file)
        logger.log_detection(
            verdict="MALICIOUS", user_input="test",
            session_id="s1", source_ip="1.1.1.1",
            detection_method="llm_only",
            llm_verdict="UNSAFE",
        )
        with open(log_file) as f:
            content = f.read()
        assert f"|{SIG_LLM_DETECTION}|" in content
        assert "cs4=UNSAFE" in content

    def test_ensemble_sig(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = CEFLogger(output="file", file_path=log_file)
        logger.log_detection(
            verdict="MALICIOUS", user_input="test",
            session_id="s1", source_ip="1.1.1.1",
            detection_method="ensemble",
            ml_result={"score": 0.6, "threat_type": "unknown", "severity": "medium", "processing_time_ms": 2},
            llm_verdict="UNSAFE",
        )
        with open(log_file) as f:
            content = f.read()
        assert f"|{SIG_ENSEMBLE_DETECTION}|" in content


class TestCEFLoggerExtensions:
    def test_attack_patterns_logged(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = CEFLogger(output="file", file_path=log_file)
        logger.log_detection(
            verdict="MALICIOUS", user_input="test",
            session_id="s1", source_ip="1.1.1.1",
            detection_method="pre_filter",
            attack_patterns=["instruction_override", "dan_jailbreak"],
        )
        with open(log_file) as f:
            content = f.read()
        assert "instruction_override,dan_jailbreak" in content
        assert "cs5Label=AttackPatterns" in content

    def test_sanitizations_logged(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = CEFLogger(output="file", file_path=log_file)
        logger.log_detection(
            verdict="MALICIOUS", user_input="test",
            session_id="s1", source_ip="1.1.1.1",
            detection_method="pre_filter",
            sanitizations=["html_tags_removed", "whitespace_normalized"],
        )
        with open(log_file) as f:
            content = f.read()
        assert "html_tags_removed,whitespace_normalized" in content
        assert "cs6Label=Sanitizations" in content

    def test_message_truncation(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = CEFLogger(output="file", file_path=log_file)
        long_msg = "A" * 500
        logger.log_detection(
            verdict="SAFE", user_input=long_msg,
            session_id="s1", source_ip="1.1.1.1",
            detection_method="ml_only",
        )
        with open(log_file) as f:
            content = f.read()
        # Message should be truncated to 200 chars
        assert "A" * 201 not in content

    def test_ml_severity_boost(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = CEFLogger(output="file", file_path=log_file)
        # SAFE verdict normally = severity 1, but high ML severity = 7
        logger.log_detection(
            verdict="SAFE", user_input="test",
            session_id="s1", source_ip="1.1.1.1",
            detection_method="ml_only",
            ml_result={"score": 0.5, "threat_type": "unknown", "severity": "high", "processing_time_ms": 1},
        )
        with open(log_file) as f:
            content = f.read()
        # Should use the higher severity (7 from ML, not 1 from SAFE verdict)
        assert "|7|" in content
