"""Tests for sentinel.drift_monitor."""

import json
import os
import tempfile

import numpy as np
import pytest

from sentinel.drift_monitor import DriftMonitor


class TestDriftMonitorBasic:
    """Basic recording and state tracking."""

    def test_init_defaults(self):
        dm = DriftMonitor()
        assert dm.window_size == 1000
        assert len(dm._scores) == 0

    def test_record_score(self):
        dm = DriftMonitor()
        dm.record(0.5)
        assert len(dm._scores) == 1
        assert dm._hourly["total"] == 1

    def test_record_categorization(self):
        dm = DriftMonitor()
        dm.record(0.90)  # blocked
        dm.record(0.20)  # safe
        dm.record(0.50)  # uncertain
        assert dm._hourly["blocked"] == 1
        assert dm._hourly["safe"] == 1
        assert dm._hourly["uncertain"] == 1

    def test_record_with_text_oov(self):
        vocab = {"hello", "world", "the"}
        dm = DriftMonitor(vocabulary=vocab)
        dm.record(0.5, text="hello unknown_token the")
        assert len(dm._oov_rates) == 1
        # "unknown_token" is OOV, so rate = 1/3
        assert abs(dm._oov_rates[0] - 1/3) < 0.01

    def test_window_limit(self):
        dm = DriftMonitor(window_size=5)
        for i in range(10):
            dm.record(float(i) / 10)
        assert len(dm._scores) == 5


class TestDriftChecks:
    """Drift detection logic."""

    def test_insufficient_data(self):
        dm = DriftMonitor()
        for _ in range(10):
            dm.record(0.5)
        result = dm.check()
        assert result["status"] == "insufficient_data"

    def test_stable_same_distribution(self):
        ref = np.random.uniform(0.0, 1.0, 200).tolist()
        dm = DriftMonitor(window_size=200, reference_scores=ref)
        # Feed same distribution
        for s in np.random.uniform(0.0, 1.0, 100):
            dm.record(float(s))
        result = dm.check()
        # With random data from same uniform, should usually be stable
        assert "confidence_drift" in result
        assert result["predictions_in_window"] == 100

    def test_drift_detected_shifted_distribution(self):
        ref = np.random.uniform(0.0, 0.3, 200).tolist()
        dm = DriftMonitor(window_size=200, reference_scores=ref)
        # Feed shifted distribution (high scores)
        for _ in range(100):
            dm.record(np.random.uniform(0.7, 1.0))
        result = dm.check()
        assert result["status"] == "DRIFT_DETECTED"
        assert result["confidence_drift"]["drifted"] == True

    def test_uncertain_rate_alert(self):
        dm = DriftMonitor(window_size=100)
        # All scores in uncertain range
        for _ in range(60):
            dm.record(0.50)
        result = dm.check()
        assert result["uncertain_rate"]["alert"] is True

    def test_oov_alert(self):
        vocab = {"hello", "world"}
        dm = DriftMonitor(vocabulary=vocab, window_size=100)
        # Feed text with high OOV
        for _ in range(60):
            dm.record(0.5, text="foo bar baz qux")
        result = dm.check()
        assert "oov_rate" in result
        assert result["oov_rate"]["alert"] is True

    def test_psi_stable(self):
        # Flake fix: the two uniform-distribution samples produce a PSI that
        # is usually but not always under 0.25 -- occasionally (roughly
        # 1-in-50 runs) the random draws diverge enough to trip the
        # threshold. Seed the RNG for deterministic, reproducible draws so
        # the test measures the PSI computation, not the RNG tail.
        rng = np.random.default_rng(seed=12345)
        ref = rng.uniform(0, 1, 200).tolist()
        dm = DriftMonitor(window_size=200, reference_scores=ref)
        for s in rng.uniform(0, 1, 100):
            dm.record(float(s))
        result = dm.check()
        if "psi" in result:
            assert result["psi"]["value"] < 0.25  # should be stable

    def test_blocked_rate_anomaly(self):
        dm = DriftMonitor(window_size=200)
        # All scores above 0.85 -> 100% blocked rate
        for _ in range(60):
            dm.record(0.95)
        result = dm.check()
        assert result["blocked_rate"]["alert"] is True


class TestHealthAndAlerts:
    """Health endpoint and alert logging."""

    def test_get_health_compact(self):
        dm = DriftMonitor()
        for _ in range(60):
            dm.record(0.2)
        health = dm.get_health()
        assert "drift_status" in health
        assert "predictions_in_window" in health

    def test_alerts_logged_on_drift(self):
        ref = np.random.uniform(0.0, 0.2, 200).tolist()
        dm = DriftMonitor(window_size=200, reference_scores=ref)
        for _ in range(60):
            dm.record(0.95)
        dm.check()
        alerts = dm.get_alerts()
        assert len(alerts) >= 1
        assert alerts[-1]["status"] == "DRIFT_DETECTED"

    def test_alerts_limit(self):
        dm = DriftMonitor()
        # Manually add alerts
        for i in range(50):
            dm._alerts.append({"id": i})
        alerts = dm.get_alerts(limit=5)
        assert len(alerts) == 5


class TestHourlyAccumulator:
    """Hourly bucket rotation."""

    def test_flush_hourly(self):
        dm = DriftMonitor()
        dm.record(0.5)
        dm.record(0.9)
        dm.flush_hourly()
        assert dm._hourly["total"] == 0
        history = dm.get_hourly_history()
        assert len(history) == 1
        assert history[0]["total"] == 2

    def test_flush_empty_no_append(self):
        dm = DriftMonitor()
        dm.flush_hourly()
        assert len(dm.get_hourly_history()) == 0


class TestPersistence:
    """Save/load reference distribution."""

    def test_save_and_load(self):
        ref = [0.1, 0.2, 0.3, 0.8, 0.9]
        dm1 = DriftMonitor(reference_scores=ref)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        try:
            dm1.save_reference(path)

            dm2 = DriftMonitor()
            assert dm2.load_reference(path) is True
            np.testing.assert_array_almost_equal(dm2._ref_scores, ref)
        finally:
            os.unlink(path)

    def test_load_missing_file(self):
        dm = DriftMonitor()
        assert dm.load_reference("/nonexistent/path.json") is False


class TestPSI:
    """Population Stability Index computation."""

    def test_psi_identical(self):
        data = np.random.uniform(0, 1, 500)
        psi = DriftMonitor._compute_psi(data, data)
        assert psi < 0.01

    def test_psi_shifted(self):
        expected = np.random.uniform(0, 0.5, 500)
        actual = np.random.uniform(0.5, 1.0, 500)
        psi = DriftMonitor._compute_psi(expected, actual)
        assert psi > 0.2  # significant drift


class TestSetReference:
    """Dynamic reference update."""

    def test_set_reference(self):
        dm = DriftMonitor()
        dm.set_reference([0.1, 0.5, 0.9])
        assert len(dm._ref_scores) == 3

    def test_set_reference_with_vocab(self):
        dm = DriftMonitor()
        dm.set_reference([0.5], vocabulary=["hello", "world"])
        assert "hello" in dm._vocabulary
