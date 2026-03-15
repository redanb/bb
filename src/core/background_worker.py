import time
import logging
from datetime import datetime, timedelta
import threading
from src.core.target_selector import TargetSelector
from src.core.recon_pipeline import ReconPipeline
from src.core.safe_scheduler import SafeScheduler
from src.core.notifier import notifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("BackgroundWorker")

class BackgroundWorker:
    """
    The persistent hunting engine designed to run 24/7 in the cloud.
    """
    def __init__(self):
        self.selector = TargetSelector()
        self.pipeline = ReconPipeline()
        self.scheduler = SafeScheduler()
        self.current_targets = []
        self.last_target_update = 0.0

    def refresh_targets(self):
        """Mock refresh logic - in production this would query HackerOne/BugBase APIs."""
        logger.info("Refreshing target list via GRAIN methodology...")
        # Real-World Candidates (Indian-focused / High-probability)
        candidates = [
            {"id": "bb_quickwork", "name": "Quickwork (BugBase)", "platform": "bugbase", "reports_resolved": 85, "last_report_date": "2026-03-14T10:00:00", "scopes": ["*.quickwork.co"], "allows_scanners": True, "is_indian": True},
            {"id": "h1_swiggy", "name": "Swiggy (H1)", "platform": "hackerone", "reports_resolved": 450, "last_report_date": "2026-03-12T15:00:00", "scopes": ["*.swiggy.com"], "allows_scanners": True, "is_indian": True},
            {"id": "bb_upstox", "name": "Upstox (BugBase)", "platform": "bugbase", "reports_resolved": 210, "last_report_date": "2026-03-15T09:00:00", "scopes": ["*.upstox.com"], "allows_scanners": True, "is_indian": True},
        ]
        self.current_targets = self.selector.select_targets(candidates)
        self.last_target_update = time.time()
        logger.info(f"Targets updated. Currently monitoring: {[t['name'] for t in self.current_targets]}")

    def run(self):
        logger.info("Background Worker started. God-Level Perpetual Execution Engaged.")
        
        # Initial target fetch
        self.refresh_targets()

        try:
            while True:
                # 1. Refresh targets every 24 hours
                if time.time() - self.last_target_update > 86400:
                    self.refresh_targets()

                # 2. Check if we are in the safe hunting window (2AM - 6AM IST)
                if self.scheduler.is_safe_window():
                    logger.info("Safe Hunting Window ACTIVE. Processing targets...")
                    notifier.send_alert("Hunting Session Started", f"Engine activated for {len(self.current_targets)} targets.")
                    
                    for target in self.current_targets:
                        domain = target["scopes"][0].replace("*.", "")
                        
                        logger.info(f"Starting safe recon on {domain}")
                        subdomains = self.pipeline.passive_recon(domain)
                        
                        for sub in subdomains:
                            # Apply rate limit and window check for every action
                            # We simulate an IDOR check as it's a allowed bug class
                            self.scheduler.execute_payload(sub, "idor")
                            
                else:
                    # Not in window, sleep for 15 minutes and check again
                    logger.info("Outside safe hunting window (2AM-6AM IST). Idling...")
                    time.sleep(900) # 15 minutes
                
                # Preventive sleep to prevent CPU spiking in the main loop
                time.sleep(60)
                
        except KeyboardInterrupt:
            logger.info("Worker shutting down gracefully...")

if __name__ == "__main__":
    worker = BackgroundWorker()
    worker.run()
