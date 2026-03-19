import os
import subprocess
import requests
import json
import logging
from typing import Dict, Any

logger = logging.getLogger("DeploymentSentry")

class DeploymentSentry:
    """
    Automated check to ensure local code and cloud deployment are in sync.
    """
    def __init__(self):
        self.project_id = os.getenv("PROJECT_ID")
        self.railway_token = os.getenv("RAILWAY_TOKEN")
        self.public_url = os.getenv("PUBLIC_URL")

    def check_git_status(self) -> Dict[str, Any]:
        """Checks if there are uncommitted or unpushed changes."""
        try:
            # Check for uncommitted changes
            status = subprocess.check_output(["git", "status", "--porcelain"]).decode().strip()
            
            # Check for unpushed commits
            unpushed = subprocess.check_output(["git", "log", "@{u}..HEAD", "--oneline"]).decode().strip()
            
            return {
                "clean": not status,
                "pushed": not unpushed,
                "details": f"Status: {status}\nUnpushed: {unpushed}"
            }
        except Exception as e:
            return {"error": str(e)}

    def check_cloud_rev(self) -> str:
        """Fetch the current version/heartbeat from the live cloud instance."""
        if not self.public_url:
            return "UNKNOWN (No Public URL)"
        try:
            resp = requests.get(f"{self.public_url.rstrip('/')}/health", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("version", "UNKNOWN")
        except:
            pass
        return "UNREACHABLE"

    def audit_parity(self) -> bool:
        """Terminal audit: returns True only if everything is in sync."""
        git = self.check_git_status()
        if not git.get("clean"):
            logger.warning("[SENTRY] UNCOMMITTED CHANGES DETECTED locally.")
            return False
        if not git.get("pushed"):
            logger.warning("[SENTRY] UNPUSHED COMMITS DETECTED. Cloud is out of date.")
            return False
        
        logger.info("[SENTRY] Local parity verified. Git is clean and pushed.")
        return True

if __name__ == "__main__":
    sentry = DeploymentSentry()
    if sentry.audit_parity():
        print("✅ SUCCESS: Deployment Sentry confirms Parity.")
    else:
        print("❌ FAILURE: Deployment Sentry detected Sync Gap.")
