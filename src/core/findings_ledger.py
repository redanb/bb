import json
import logging
import os
from datetime import datetime
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class FindingsLedger:
    """
    Persistent storage for confirmed vulnerabilities discovered during active
    reconnaissance. This prevents re-reporting and tracks real-world proof.
    """
    
    def __init__(self, filepath: str = "findings_ledger.jsonl"):
        self.filepath = filepath
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        if not os.path.exists(self.filepath):
            with open(self.filepath, 'w', encoding='utf-8') as f:
                pass
            logger.info(f"Created new FindingsLedger at {self.filepath}")

    def record_finding(self, target: str, bug_class: str, severity: str, evidence: str, poc_log: str) -> bool:
        """
        Record a finding if it hasn't been recorded for this target/class before.
        Returns True if newly recorded, False if duplicate.
        """
        # Deduplication check
        if self.has_finding(target, bug_class):
            logger.info(f"Duplicate finding blocked: {target} - {bug_class}")
            return False

        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "target": target,
            "bug_class": bug_class,
            "severity": severity,
            "evidence": evidence,
            "poc_log": poc_log
        }

        with open(self.filepath, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record) + "\n")
            
        logger.info(f"Recorded NEW finding: {target} [{bug_class}]")
        return True

    def has_finding(self, target: str, bug_class: str) -> bool:
        """Check if a specific bug class was already found on the target."""
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip(): continue
                    record = json.loads(line)
                    if record.get("target") == target and record.get("bug_class") == bug_class:
                        return True
        except Exception as e:
            logger.error(f"Error reading ledger: {e}")
            
        return False
        
    def get_all_findings(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        findings.append(json.loads(line))
        except FileNotFoundError:
            pass
        return findings
