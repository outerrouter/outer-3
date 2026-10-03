"""Sliding-window per-minute rate limiter for LLM API calls."""
from __future__ import annotations

import threading
import time
from collections import deque

from .config import MAX_REQUESTS_PER_MINUTE, DEFAULT_RATE_LIMIT


class RateLimiter:
    """Sliding-window limiter. Blocks (async-friendly via sleep) until a slot frees."""

    def __init__(self, limit_per_minute: int = 60) -> None:
        self._lock = threading.Lock()
        self._events: deque[float] = deque()
        self.set_limit(limit_per_minute)

    def set_limit(self, limit_per_minute: int) -> None:
        limit_per_minute = max(1, min(int(limit_per_minute), MAX_REQUESTS_PER_MINUTE))
        with self._lock:
            self._limit = limit_per_minute

    @property
    def limit(self) -> int:
        with self._lock:
            return self._limit

    def _prune(self, now: float) -> None:
        cutoff = now - 60.0
        while self._events and self._events[0] <= cutoff:
            self._events.popleft()

    def acquire(self) -> float:
        """Reserve a slot. Returns the number of seconds the caller had to wait."""
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                self._prune(now)
                if len(self._events) < self._limit:
                    self._events.append(now)
                    return waited
                # Earliest event will expire at this time.
                sleep_for = 60.0 - (now - self._events[0]) + 0.01
            sleep_for = max(sleep_for, 0.01)
            waited += sleep_for
            time.sleep(sleep_for)

    def snapshot(self) -> dict:
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            used = len(self._events)
            reset_in = 60.0 - (now - self._events[0]) if self._events else 0.0
            return {
                "limit_per_minute": self._limit,
                "used_last_minute": used,
                "remaining": max(0, self._limit - used),
                "reset_in_seconds": round(max(0.0, reset_in), 2),
            }


# Single shared limiter for the configured LLM endpoint.
llm_limiter = RateLimiter(limit_per_minute=DEFAULT_RATE_LIMIT)
