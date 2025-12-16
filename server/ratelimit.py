#!/usr/bin/env python3
"""
Rate limiting module
"""

import time
import threading
from collections import defaultdict
from typing import Dict, Tuple

class RateLimiter:
    """Simple rate limiter for sessions"""
    
    def __init__(self, max_rate: int = 100, window: float = 1.0):
        self.max_rate = max_rate  # packets per second
        self.window = window  # time window in seconds
        self.counts: Dict[Tuple, list] = defaultdict(list)
        self.lock = threading.Lock()
    
    def check(self, key: Tuple) -> bool:
        """Check if rate limit is exceeded"""
        with self.lock:
            now = time.time()
            timestamps = self.counts[key]
            
            # Remove old timestamps
            timestamps = [ts for ts in timestamps if now - ts < self.window]
            
            if len(timestamps) >= self.max_rate:
                return False
            
            timestamps.append(now)
            self.counts[key] = timestamps[-self.max_rate:]  # Keep only recent
            
            return True
    
    def cleanup(self, max_age: float = 300.0):
        """Cleanup old entries"""
        with self.lock:
            now = time.time()
            to_delete = []
            
            for key, timestamps in self.counts.items():
                # Remove empty entries
                if not timestamps:
                    to_delete.append(key)
                    continue
                
                # Remove old timestamps
                timestamps = [ts for ts in timestamps if now - ts < max_age]
                if timestamps:
                    self.counts[key] = timestamps
                else:
                    to_delete.append(key)
            
            for key in to_delete:
                del self.counts[key]

class AdaptiveRateLimiter(RateLimiter):
    """Rate limiter with adaptive window"""
    
    def __init__(self, max_rate: int = 100):
        super().__init__(max_rate)
        self.slow_starts: Dict[Tuple, int] = defaultdict(int)
    
    def check(self, key: Tuple) -> bool:
        """Adaptive rate limiting with slow start"""
        with self.lock:
            now = time.time()
            timestamps = self.counts.get(key, [])
            
            # Slow start: increase limit gradually
            slow_start_factor = min(1.0, self.slow_starts[key] / 10.0)
            effective_max_rate = int(self.max_rate * slow_start_factor)
            
            # Count recent packets
            recent = sum(1 for ts in timestamps if now - ts < self.window)
            
            if recent >= max(10, effective_max_rate):
                return False
            
            # Update timestamps
            timestamps.append(now)
            timestamps = [ts for ts in timestamps if now - ts < 300.0]
            self.counts[key] = timestamps
            
            # Increment slow start counter
            if self.slow_starts[key] < 10:
                self.slow_starts[key] += 1
            
            return True
