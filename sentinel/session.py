"""
Sentinel - Session Manager
Thread-safe session state tracking with multi-turn attack detection.
"""

import datetime
import logging
import threading
import time

from . import config
from .pattern_detector import detect_attack_patterns

log = logging.getLogger(__name__)


class SessionManager:
    """
    Manages session state for multi-turn attack detection.
    Thread-safe with RLock.

    Args:
        storage_backend: Optional StorageBackend for persisting sessions.
            When provided, sessions survive restarts.
    """

    def __init__(self, ttl=None, max_count=None, cleanup_interval=None, storage_backend=None):
        self.ttl = ttl or config.SESSION_TTL_SECONDS
        self.max_count = max_count or config.SESSION_MAX_COUNT
        self.cleanup_interval = cleanup_interval or config.SESSION_CLEANUP_INTERVAL
        self._storage = storage_backend
        self._sessions = {}
        self._lock = threading.RLock()
        self._cleanup_thread = None

        # Rehydrate from storage backend if available
        if self._storage is not None:
            try:
                self._sessions = self._storage.list_sessions()
            except (OSError, Exception) as e:
                log.warning("Failed to rehydrate sessions from storage: %s", e)

    @staticmethod
    def _new_session(now, source_ip):
        """Create a fresh session state dict."""
        return {
            "interactions": [],
            "cumulative_risk_score": 0.0,
            "threat_count": 0,
            "safe_count": 0,
            "escalated": False,
            "created_at": now,
            "last_activity": now,
            "source_ip": source_ip,
            "instruction_override_attempts": 0,
            "context_switch_attempts": 0,
            "persona_override_attempts": 0,
            "hypothetical_framing_count": 0,
            "dan_jailbreak_attempts": 0,
            "logic_trap_attempts": 0,
            "rapid_escalation_detected": False,
            "attack_patterns": [],
            "sanitization_events": 0,
            "sanitization_types": [],
            # MCP tool call tracking
            "mcp_tool_calls": 0,
            "mcp_tool_calls_blocked": 0,
            "mcp_tools_used": [],
            "mcp_denied_tools": [],
            "mcp_honey_triggers": 0,
            "mcp_findings_count": 0,
            "mcp_last_tool": None,
            "mcp_attack_patterns": [],
        }

    def start_cleanup(self):
        """Start background session cleanup thread."""
        if self._cleanup_thread is not None:
            return
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def _cleanup_loop(self):
        while True:
            time.sleep(self.cleanup_interval)
            self.cleanup_expired()

    def cleanup_expired(self):
        """Remove expired sessions."""
        with self._lock:
            now = datetime.datetime.now()
            expired = [
                sid
                for sid, s in self._sessions.items()
                if (now - s.get("last_activity", now)).total_seconds() > self.ttl
            ]
            for sid in expired:
                del self._sessions[sid]
                if self._storage is not None:
                    try:
                        self._storage.delete_session(sid)
                    except (OSError, Exception) as e:
                        log.warning("Failed to delete session %s from storage: %s", sid[:8], e)
            if expired:
                log.info(
                    "Cleaned up %d expired sessions. Active: %d", len(expired), len(self._sessions)
                )

    def get(self, session_id):
        """Get session state (read-only copy)."""
        with self._lock:
            return dict(self._sessions.get(session_id, {}))

    def get_all(self):
        """Get all sessions (read-only snapshot)."""
        with self._lock:
            return {sid: dict(s) for sid, s in self._sessions.items()}

    @property
    def active_count(self):
        with self._lock:
            return len(self._sessions)

    @property
    def escalated_count(self):
        with self._lock:
            return sum(1 for s in self._sessions.values() if s.get("escalated"))

    def update(self, session_id, user_input, verdict, ml_result, source_ip, sanitizations=None):
        """
        Update session state with a new interaction.

        Returns:
            dict: Updated session state
        """
        now = datetime.datetime.now()
        with self._lock:
            return self._update_locked(
                session_id, user_input, verdict, ml_result, source_ip, now, sanitizations
            )

    def _update_locked(
        self, session_id, user_input, verdict, ml_result, source_ip, now, sanitizations=None
    ):
        """Inner update with lock held."""
        if session_id not in self._sessions:
            if len(self._sessions) >= self.max_count:
                return self._sessions.get(session_id, {})
            self._sessions[session_id] = self._new_session(now, source_ip)

        session = self._sessions[session_id]

        # Detect multi-turn attack patterns
        attack_patterns_detected = detect_attack_patterns(user_input, session)

        for pattern in attack_patterns_detected:
            if pattern not in session["attack_patterns"]:
                session["attack_patterns"].append(pattern)

            counter_map = {
                "instruction_override": "instruction_override_attempts",
                "context_switch": "context_switch_attempts",
                "persona_override": "persona_override_attempts",
                "hypothetical_framing": "hypothetical_framing_count",
                "dan_jailbreak": "dan_jailbreak_attempts",
                "logic_trap": "logic_trap_attempts",
            }
            if pattern in counter_map:
                session[counter_map[pattern]] += 1

        # Track sanitization events
        if sanitizations:
            session["sanitization_events"] += 1
            for san_type in sanitizations:
                if san_type not in session["sanitization_types"]:
                    session["sanitization_types"].append(san_type)

        # Append interaction
        log_event = {
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "user": "chat_user",
            "source_ip": source_ip,
            "dest_ip": "sentinel_server",
            "event_type": "chat",
            "action": "success" if verdict == "SAFE" else "failed",
            "message": user_input,
            "severity": ml_result.get("severity", "low") if ml_result else "low",
            "attack_patterns": attack_patterns_detected,
        }
        MAX_INTERACTIONS = 200
        if len(session["interactions"]) >= MAX_INTERACTIONS:
            session["interactions"] = session["interactions"][-(MAX_INTERACTIONS - 1) :]
        session["interactions"].append(log_event)

        # Update counters
        if verdict in ("MALICIOUS", "SAFE_REVIEW"):
            session["threat_count"] += 1
        else:
            session["safe_count"] += 1

        # Accumulate risk
        if ml_result:
            session["cumulative_risk_score"] += ml_result.get("score", 0.0)

        # Rapid escalation detection
        if len(session["interactions"]) >= 2:
            recent = session["interactions"][-5:]
            recent_threats = sum(1 for i in recent if i.get("action") == "failed")
            if recent_threats >= 3:
                session["rapid_escalation_detected"] = True

        # Escalation check
        escalation_reasons = []

        if session["threat_count"] >= config.SESSION_MAX_THREATS:
            escalation_reasons.append(f"threat_count={session['threat_count']}")
        if session["cumulative_risk_score"] >= config.SESSION_RISK_ESCALATION:
            escalation_reasons.append(f"cumulative_risk={session['cumulative_risk_score']:.2f}")
        if session["instruction_override_attempts"] >= 2:
            escalation_reasons.append(
                f"instruction_overrides={session['instruction_override_attempts']}"
            )
        if session["persona_override_attempts"] >= 2:
            escalation_reasons.append(f"persona_overrides={session['persona_override_attempts']}")
        if session["hypothetical_framing_count"] >= 2:
            escalation_reasons.append(
                f"hypothetical_attacks={session['hypothetical_framing_count']}"
            )
        if session["dan_jailbreak_attempts"] >= 1:
            escalation_reasons.append(f"dan_jailbreak={session['dan_jailbreak_attempts']}")
        if session["logic_trap_attempts"] >= 1:
            escalation_reasons.append(f"logic_traps={session['logic_trap_attempts']}")
        if session["rapid_escalation_detected"]:
            escalation_reasons.append("rapid_escalation")
        if len(session["attack_patterns"]) >= 3:
            escalation_reasons.append(f"diverse_attacks={len(session['attack_patterns'])}")

        if escalation_reasons:
            session["escalated"] = True
            session["escalation_reason"] = "; ".join(escalation_reasons)
            log.warning("Session %s escalated: %s", session_id[:8], session["escalation_reason"])

        session["last_activity"] = now

        # Persist to storage backend
        if self._storage is not None:
            try:
                self._storage.save_session(session_id, session)
            except (OSError, Exception) as e:
                log.warning("Failed to persist session %s: %s", session_id[:8], e)

        return dict(session)

    def update_mcp(
        self, session_id, tool_name, blocked, findings, source_ip, honey_triggered=False
    ):
        """
        Update session state with an MCP tool call event.

        Args:
            session_id: Session identifier.
            tool_name: Name of the tool called.
            blocked: Whether the call was blocked.
            findings: List of MCPScanFinding instances or dicts.
            source_ip: Client IP address.
            honey_triggered: Whether this was a honey tool trigger.

        Returns:
            dict: Updated session state.
        """
        now = datetime.datetime.now()
        with self._lock:
            if session_id not in self._sessions:
                if len(self._sessions) >= self.max_count:
                    return {}
                self._sessions[session_id] = self._new_session(now, source_ip)

            session = self._sessions[session_id]

            # Ensure MCP fields exist (for sessions created before MCP support)
            for field, default in [
                ("mcp_tool_calls", 0),
                ("mcp_tool_calls_blocked", 0),
                ("mcp_tools_used", []),
                ("mcp_denied_tools", []),
                ("mcp_honey_triggers", 0),
                ("mcp_findings_count", 0),
                ("mcp_last_tool", None),
                ("mcp_attack_patterns", []),
            ]:
                if field not in session:
                    session[field] = default

            # Update counters
            session["mcp_tool_calls"] += 1
            session["mcp_last_tool"] = tool_name

            if tool_name not in session["mcp_tools_used"]:
                session["mcp_tools_used"].append(tool_name)

            if blocked:
                session["mcp_tool_calls_blocked"] += 1
                if tool_name not in session["mcp_denied_tools"]:
                    session["mcp_denied_tools"].append(tool_name)

            if honey_triggered:
                session["mcp_honey_triggers"] += 1

            # Track finding categories as attack patterns
            if findings:
                session["mcp_findings_count"] += len(findings)
                for f in findings:
                    cat = f.category if hasattr(f, "category") else f.get("category", "")
                    if cat and cat not in session["mcp_attack_patterns"]:
                        session["mcp_attack_patterns"].append(cat)

            # MCP-specific escalation triggers
            escalation_reasons = []

            if session["mcp_tool_calls_blocked"] >= 3:
                escalation_reasons.append(f"mcp_blocked={session['mcp_tool_calls_blocked']}")
            if session["mcp_honey_triggers"] >= 1:
                escalation_reasons.append(f"mcp_honey_triggers={session['mcp_honey_triggers']}")
            if len(session["mcp_attack_patterns"]) >= 2:
                escalation_reasons.append(
                    f"mcp_diverse_attacks={len(session['mcp_attack_patterns'])}"
                )

            if escalation_reasons:
                session["escalated"] = True
                existing = session.get("escalation_reason", "")
                new_reasons = "; ".join(escalation_reasons)
                if existing:
                    session["escalation_reason"] = f"{existing}; {new_reasons}"
                else:
                    session["escalation_reason"] = new_reasons
                log.warning(
                    "Session %s escalated (MCP): %s",
                    session_id[:8],
                    new_reasons,
                )

            session["last_activity"] = now

            # Persist
            if self._storage is not None:
                try:
                    self._storage.save_session(session_id, session)
                except (OSError, Exception) as e:
                    log.warning("Failed to persist session %s: %s", session_id[:8], e)

            return dict(session)
