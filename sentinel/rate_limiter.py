"""
Sentinel - Rate Limiter
Thread-safe IP-based rate limiting with periodic stale IP cleanup.
"""

import threading
import time

from . import config


class RateLimiter:
    """
    IP-based rate limiter with automatic stale entry cleanup.
    """

    def __init__(self, limit_per_minute=None, window=60, cleanup_interval=300):
        self.limit = limit_per_minute or config.RATE_LIMIT_PER_MINUTE
        self.window = window
        self.cleanup_interval = cleanup_interval
        self._store = {}  # ip -> [timestamps]
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def check(self, ip: str) -> bool:
        """
        Check if the IP is within rate limits.

        Returns:
            True if allowed, False if rate limited.
        """
        now = time.time()
        with self._lock:
            # Periodic cleanup of stale IPs
            if now - self._last_cleanup > self.cleanup_interval:
                stale = [
                    k for k, v in self._store.items()
                    if not v or now - v[-1] > self.window
                ]
                for k in stale:
                    del self._store[k]
                self._last_cleanup = now

            if ip not in self._store:
                self._store[ip] = []
            self._store[ip] = [t for t in self._store[ip] if now - t < self.window]
            if len(self._store[ip]) >= self.limit:
                return False
            self._store[ip].append(now)
            return True
