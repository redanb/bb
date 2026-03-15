import time
import logging
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)

class SafeScheduler:
    """
    15 Commandments Safety Scheduler:
    - Strictly runs active tests between 2:00 AM - 6:00 AM IST (Commandment 13).
    - Enforces an absolute 1-second global rate limit (Commandment 11).
    """

    def __init__(self):
        self._lock = threading.Lock()
        
        # IST offset is UTC + 5:30
        self.ist_offset = timedelta(hours=5, minutes=30)
        self.allowed_start_hour = 2
        self.allowed_end_hour = 6

    def current_ist_time(self) -> datetime:
        return datetime.utcnow() + self.ist_offset

    def is_safe_window(self) -> bool:
        """Returns True if the current IST time is between 2am and 6am."""
        ist_now = self.current_ist_time()
        # For testing purposes, we can override this, but legally we restrict
        return self.allowed_start_hour <= ist_now.hour < self.allowed_end_hour

    def blocking_rate_limit(self):
        """Forces a 1-second delay globally to prevent platform DoS."""
        with self._lock:
            time.sleep(1)

    def execute_payload(self, target: str, payload_type: str, bypass_window: bool = False):
        if not bypass_window and not self.is_safe_window():
            ist_time = self.current_ist_time().strftime('%H:%M:%S IST')
            logger.warning(f"BLOCKED: Attempted to scan {target} outside safe window (Current time: {ist_time}). Only 2AM-6AM IST allowed.")
            return False

        logger.info(f"Applying strict 1-second rate limit before scanning {target}...")
        self.blocking_rate_limit()
        logger.info(f"EXECUTING: {payload_type} test against {target}")
        return True

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    scheduler = SafeScheduler()
    
    print(f"Current IST Time internally calculated: {scheduler.current_ist_time().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Is within safe window (2AM-6AM IST)? {scheduler.is_safe_window()}")
    
    # Try a normal scan
    scheduler.execute_payload("api.target.com", "idor", bypass_window=False)
    
    # Force a bypass for demo
    print("\n--- Bypassing window for local demo ---")
    scheduler.execute_payload("api.target.com", "idor", bypass_window=True)
    scheduler.execute_payload("dev.target.com", "xss", bypass_window=True)
