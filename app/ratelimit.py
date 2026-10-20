import time
from collections import defaultdict, deque


class SlidingWindow:
    """In-memory limiter: at most `limit` hits per key within `seconds`."""

    def __init__(self, limit: int, seconds: int):
        self.limit = limit
        self.seconds = seconds
        self._hits: dict[str, deque] = defaultdict(deque)

    def hit(self, key: str) -> bool:
        """Record a hit. Returns False if the key is over its limit."""
        window = self._hits[key]
        now = time.time()
        while window and now - window[0] > self.seconds:
            window.popleft()
        if len(window) >= self.limit:
            return False
        window.append(now)
        return True
