import time
import logging
from datetime import datetime, timedelta
import threading
import json
import os
from src.core.target_selector import TargetSelector
from src.core.recon_pipeline import ReconPipeline
from src.core.safe_scheduler import SafeScheduler
from src.core.notifier import notifier
from src.core.findings_ledger import FindingsLedger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("BackgroundWorker")

# Resolve root path
root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

class BackgroundWorker:
    """
    The persistent hunting engine designed to run 24/7 in the cloud.
    """
    def __init__(self):
        self.selector = TargetSelector()
        self.pipeline = ReconPipeline()
        self.scheduler = SafeScheduler()
        self.ledger = FindingsLedger(os.path.join(root_path, "findings_ledger.jsonl"))
        self.current_targets = []
        self.last_target_update = 0.0
        self.status_file = os.path.join(root_path, "worker_status.json")
        self.practice_mode = os.environ.get("PRACTICE_MODE", "false").lower() == "true"

    def update_status(self, phase, message, target=None):
        status_data = {
            "phase": phase,
            "message": message,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "practice_mode": self.practice_mode
        }
        try:
            with open(self.status_file, "w") as f:
                json.dump(status_data, f)
        except Exception as e:
            logger.error(f"Failed to update status file: {e}")

    def refresh_targets(self):
        """Refresh target list via GRAIN methodology."""
        logger.info("Refreshing target list...")
        self.update_status("REFRESHING_TARGETS", "Refreshing targets from GRAIN database...")
        
        if self.practice_mode:
            logger.info("PRACTICE_MODE: Using Sandbox targets.")
            candidates = [
                {"id": "sandbox_juice", "name": "Sandbox: Juice Shop (OWASP)", "platform": "sandbox", "reports_resolved": 10, "last_report_date": "2026-03-15T00:00:00", "scopes": ["*.juice-shop.herokuapp.com"], "allows_scanners": True, "is_indian": False},
                {"id": "sandbox_bank", "name": "Sandbox: Vulnerable Bank", "platform": "sandbox", "reports_resolved": 5, "last_report_date": "2026-03-15T00:00:00", "scopes": ["*.vulnerable-bank.com"], "allows_scanners": True, "is_indian": False},
            ]
        else:
            # Real-World Candidates
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
                is_safe = self.scheduler.is_safe_window() or self.practice_mode
                
                try:
                    if is_safe:
                        logger.info("Hunting window ACTIVE. Processing targets...")
                        if self.practice_mode:
                            logger.info("PRACTICE_MODE: Bypassing window check.")
                            
                        # Send periodic heartbeat to confirm worker is alive
                        self.update_status("ACTIVE", f"Hunting engine processing {len(self.current_targets)} targets.")
                        
                        for target in self.current_targets:
                            domain = target["scopes"][0].replace("*.", "")
                            self.update_status("HUNTING", f"Active recon and scanning on {domain}", target["name"])
                            
                            logger.info(f"Starting actual recon on {domain}")
                            subdomains = self.pipeline.passive_recon(domain)
                            
                            for sub in subdomains:
                                # Apply rate limit and window check for every action
                                self.scheduler.execute_payload(sub, "active_scan", bypass_window=self.practice_mode)
                                
                                # Perform real-world active scan using python requests probes
                                findings = self.pipeline.active_scan(sub)
                                for finding in findings:
                                    is_new = self.ledger.record_finding(
                                        target=sub,
                                        bug_class=finding["bug_class"],
                                        severity=finding["severity"],
                                        evidence=finding["evidence"],
                                        poc_log=finding["poc_log"]
                                    )
                                    if is_new:
                                        notifier.send_alert(
                                            f"NEW VULNERABILITY: {finding['bug_class'].upper()} on {sub}",
                                            f"Severity: {finding['severity']}\nEvidence: {finding['evidence']}"
                                        )
                    else:
                        # Not in window, sleep for 15 minutes and check again
                        logger.info("Outside safe hunting window (2AM-6AM IST). Idling...")
                        self.update_status("IDLING", "Outside safe hunting window (2AM-6AM IST). Engaged passive mode.")
                        time.sleep(900) # 15 minutes
                except Exception as e:
                    logger.error(f"Error in hunting loop: {e}")
                    self.update_status("ERROR", f"Loop recovered from error: {str(e)[:100]}")
                    time.sleep(60) # Cooling off after error
                
                # Preventive sleep to prevent CPU spiking in the main loop
                time.sleep(60)
                
        except KeyboardInterrupt:
            logger.info("Worker shutting down gracefully...")

if __name__ == "__main__":
    worker = BackgroundWorker()
    worker.run()
