"""
Sentinel - ML Model Drift Monitor

Tracks prediction confidence distribution, OOV token rates, and feature
drift to detect when the ML classifier needs retraining.

Three detection layers:
  1. Output drift - KS test on prediction score distribution (no labels needed)
  2. Input drift  - OOV token rate against TF-IDF vocabulary
  3. Concept drift - PSI (Population Stability Index) on score bins
"""

import threading
import json
import logging
import os
import pathlib
from collections import deque
from datetime import datetime, timezone

try:
    import numpy as np
    from scipy import stats
    _HAS_DEPS = True
except ImportError:
    np = None
    stats = None
    _HAS_DEPS = False

log = logging.getLogger(__name__)
_UTC = timezone.utc


class DriftMonitor:
    """Lightweight production drift detection for the prompt injection classifier."""

    def __init__(self, window_size=1000, reference_scores=None, vocabulary=None,
                 tool_call_threshold=50, delegation_depth_threshold=5):
        """
        Args:
            window_size: Rolling window of recent predictions to compare.
            reference_scores: Array of prediction scores from training/validation.
            vocabulary: Set of tokens from the TF-IDF vectorizer vocabulary.
            tool_call_threshold: Max tool calls per window before alerting.
            delegation_depth_threshold: Max delegation depth before alerting.
        """
        self.window_size = window_size
        self._lock = threading.Lock()

        # Rolling windows
        self._scores = deque(maxlen=window_size)
        self._oov_rates = deque(maxlen=window_size)
        self._timestamps = deque(maxlen=window_size)

        # Agent anomaly tracking
        self._tool_call_threshold = tool_call_threshold
        self._delegation_depth_threshold = delegation_depth_threshold
        self._tool_calls = deque(maxlen=window_size)
        self._delegation_depths = deque(maxlen=window_size)
        self._tool_call_counts = {}  # tool_name -> count

        # Hourly accumulators (reset each hour)
        self._hourly = {
            "total": 0,
            "blocked": 0,
            "safe": 0,
            "uncertain": 0,
            "hour_start": datetime.now(tz=_UTC).isoformat(),
        }
        self._hourly_history = deque(maxlen=168)  # 7 days of hourly buckets

        # Reference distribution (set from training data)
        self._ref_scores = np.array(reference_scores) if (reference_scores is not None and _HAS_DEPS) else None
        self._vocabulary = set(vocabulary) if vocabulary else set()

        # Alert log
        self._alerts = deque(maxlen=100)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(self, score, text=None):
        """Record a single ML prediction for drift monitoring.

        Args:
            score: The model's predicted probability (0.0 - 1.0).
            text: The raw input text (optional, for OOV tracking).
        """
        with self._lock:
            self._scores.append(score)
            self._timestamps.append(datetime.now(tz=_UTC).isoformat())

            # Hourly accumulator
            self._hourly["total"] += 1
            if score >= 0.85:
                self._hourly["blocked"] += 1
            elif score <= 0.30:
                self._hourly["safe"] += 1
            else:
                self._hourly["uncertain"] += 1

            # OOV tracking
            if text and self._vocabulary:
                tokens = text.lower().split()
                if tokens:
                    oov = sum(1 for t in tokens if t not in self._vocabulary) / len(tokens)
                    self._oov_rates.append(oov)

    def set_reference(self, scores, vocabulary=None):
        """Set or update the reference distribution.

        Args:
            scores: Array-like of prediction scores from training/validation.
            vocabulary: Optional set of TF-IDF vocabulary tokens.
        """
        with self._lock:
            self._ref_scores = np.array(scores)
            if vocabulary is not None:
                self._vocabulary = set(vocabulary)

    # ------------------------------------------------------------------
    # Agent anomaly recording
    # ------------------------------------------------------------------

    def record_agent_event(self, event_type, depth=0, tool_name=None):
        """Record an agent-related event for anomaly monitoring.

        Args:
            event_type: "tool_call" or "delegation".
            depth: Delegation nesting depth (0 = top-level).
            tool_name: Name of the tool being called (for tool_call events).
        """
        with self._lock:
            ts = datetime.now(tz=_UTC).isoformat()
            if event_type == "tool_call":
                self._tool_calls.append({"tool": tool_name, "ts": ts})
                if tool_name:
                    self._tool_call_counts[tool_name] = (
                        self._tool_call_counts.get(tool_name, 0) + 1
                    )
            elif event_type == "delegation":
                self._delegation_depths.append({"depth": depth, "ts": ts})

    # ------------------------------------------------------------------
    # Drift checks
    # ------------------------------------------------------------------

    def check(self):
        """Run all drift checks. Returns a dict with results and overall status."""
        with self._lock:
            if len(self._scores) < 50:
                return {
                    "status": "insufficient_data",
                    "predictions_in_window": len(self._scores),
                }

            scores = np.array(self._scores)
            results = {}
            any_drift = False

            # 1. Output drift (KS test)
            if self._ref_scores is not None and len(self._ref_scores) >= 50:
                ks_stat, ks_p = stats.ks_2samp(self._ref_scores, scores)
                drifted = ks_p < 0.05
                results["confidence_drift"] = {
                    "ks_statistic": round(float(ks_stat), 4),
                    "p_value": round(float(ks_p), 6),
                    "drifted": drifted,
                    "ref_mean": round(float(np.mean(self._ref_scores)), 4),
                    "current_mean": round(float(np.mean(scores)), 4),
                }
                if drifted:
                    any_drift = True

            # 2. Uncertain rate (borderline predictions)
            uncertain_rate = float(np.sum((scores > 0.30) & (scores < 0.70)) / len(scores))
            uncertain_alert = uncertain_rate > 0.25
            results["uncertain_rate"] = {
                "value": round(uncertain_rate, 4),
                "alert": uncertain_alert,
                "threshold": 0.25,
            }
            if uncertain_alert:
                any_drift = True

            # 3. OOV token rate
            if len(self._oov_rates) >= 20:
                oov_arr = np.array(self._oov_rates)
                mean_oov = float(np.mean(oov_arr))
                oov_alert = mean_oov > 0.20
                results["oov_rate"] = {
                    "mean": round(mean_oov, 4),
                    "p95": round(float(np.percentile(oov_arr, 95)), 4),
                    "alert": oov_alert,
                    "threshold": 0.20,
                    "sample_size": len(oov_arr),
                }
                if oov_alert:
                    any_drift = True

            # 4. PSI (Population Stability Index)
            if self._ref_scores is not None and len(self._ref_scores) >= 50:
                psi = self._compute_psi(self._ref_scores, scores)
                psi_drifted = psi >= 0.20
                results["psi"] = {
                    "value": round(float(psi), 4),
                    "interpretation": (
                        "stable" if psi < 0.10 else
                        "moderate_drift" if psi < 0.25 else
                        "significant_drift"
                    ),
                    "drifted": psi_drifted,
                }
                if psi_drifted:
                    any_drift = True

            # 5. Blocked rate anomaly
            total = self._hourly["total"]
            if total > 0:
                blocked_rate = self._hourly["blocked"] / total
                blocked_anomaly = blocked_rate > 0.95 or blocked_rate < 0.01
                results["blocked_rate"] = {
                    "value": round(blocked_rate, 4),
                    "alert": blocked_anomaly,
                    "hourly_total": total,
                }
                if blocked_anomaly:
                    any_drift = True

            # 6. Agent tool call rate anomaly
            if len(self._tool_calls) > 0:
                tc_count = len(self._tool_calls)
                tc_alert = tc_count > self._tool_call_threshold
                results["agent_tool_calls"] = {
                    "count_in_window": tc_count,
                    "threshold": self._tool_call_threshold,
                    "alert": tc_alert,
                    "top_tools": dict(sorted(
                        self._tool_call_counts.items(),
                        key=lambda x: x[1], reverse=True,
                    )[:5]),
                }
                if tc_alert:
                    any_drift = True

            # 7. Agent delegation depth anomaly
            if len(self._delegation_depths) > 0:
                depths = [d["depth"] for d in self._delegation_depths]
                max_depth = max(depths)
                avg_depth = sum(depths) / len(depths)
                depth_alert = max_depth > self._delegation_depth_threshold
                results["agent_delegation"] = {
                    "max_depth": max_depth,
                    "avg_depth": round(avg_depth, 2),
                    "threshold": self._delegation_depth_threshold,
                    "alert": depth_alert,
                    "events": len(depths),
                }
                if depth_alert:
                    any_drift = True

            status = "DRIFT_DETECTED" if any_drift else "STABLE"
            report = {
                "status": status,
                "timestamp": datetime.now(tz=_UTC).isoformat(),
                "predictions_in_window": len(scores),
                **results,
            }

            if any_drift:
                self._alerts.append(report)

            return report

    def get_health(self):
        """Compact health metrics for the /health endpoint."""
        report = self.check()
        health = {
            "drift_status": report.get("status", "unknown"),
            "predictions_in_window": report.get("predictions_in_window", 0),
            "uncertain_rate": report.get("uncertain_rate", {}).get("value", 0),
            "oov_rate": report.get("oov_rate", {}).get("mean", 0),
        }
        if "agent_tool_calls" in report:
            health["agent_tool_calls"] = report["agent_tool_calls"]["count_in_window"]
        if "agent_delegation" in report:
            health["agent_max_depth"] = report["agent_delegation"]["max_depth"]
        return health

    def get_alerts(self, limit=20):
        """Return recent drift alerts."""
        with self._lock:
            return list(self._alerts)[-limit:]

    def flush_hourly(self):
        """Rotate hourly accumulator. Call from a periodic timer."""
        with self._lock:
            if self._hourly["total"] > 0:
                self._hourly_history.append(dict(self._hourly))
            self._hourly = {
                "total": 0,
                "blocked": 0,
                "safe": 0,
                "uncertain": 0,
                "hour_start": datetime.now(tz=_UTC).isoformat(),
            }

    def get_hourly_history(self):
        """Return hourly metric buckets."""
        with self._lock:
            return list(self._hourly_history)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_reference(self, path):
        """Save reference distribution to disk."""
        if not _HAS_DEPS:
            return
        if self._ref_scores is not None:
            data = {
                "scores": self._ref_scores.tolist(),
                "vocabulary_size": len(self._vocabulary),
                "saved_at": datetime.now(tz=_UTC).isoformat(),
            }
            with open(path, "w") as f:
                json.dump(data, f)

    def load_reference(self, path):
        """Load reference distribution from disk."""
        if not _HAS_DEPS:
            log.warning("numpy/scipy not installed; drift monitoring disabled")
            return False
        resolved = pathlib.Path(path).resolve()
        if not resolved.exists():
            return False
        if resolved.stat().st_size > 50 * 1024 * 1024:
            log.warning("Drift reference file too large: %d bytes", resolved.stat().st_size)
            return False
        with open(resolved, "r") as f:
            data = json.load(f)
        scores = data.get("scores", [])
        if not isinstance(scores, list) or len(scores) > 1_000_000:
            log.warning("Drift reference scores invalid or too large")
            return False
        self._ref_scores = np.array(scores)
        return True

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_psi(expected, actual, bins=10):
        """Compute Population Stability Index between two distributions."""
        breakpoints = np.percentile(expected, np.linspace(0, 100, bins + 1))
        breakpoints[0] = -np.inf
        breakpoints[-1] = np.inf

        exp_counts = np.histogram(expected, bins=breakpoints)[0]
        act_counts = np.histogram(actual, bins=breakpoints)[0]

        eps = 1e-4
        exp_pct = exp_counts / len(expected) + eps
        act_pct = act_counts / len(actual) + eps

        return float(np.sum((act_pct - exp_pct) * np.log(act_pct / exp_pct)))
