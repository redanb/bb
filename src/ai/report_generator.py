import logging
import json
from typing import Dict, Any, Optional

from src.ai.llm_router import LLMRouter, TaskComplexity
from src.ai.report_linter import ReportContent

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generates professional bug bounty reports from raw findings using the LLM Router.
    """
    
    def __init__(self, llm_router: Optional[LLMRouter] = None):
        self.router = llm_router or LLMRouter(monthly_budget_usd=100.0)
        
    def generate_report(self, finding: Dict[str, Any], target_platform: str = "hackerone") -> Optional[ReportContent]:
        """
        Takes a raw finding from the FindingsLedger and generates a full ReportContent object.
        """
        logger.info(f"Generating report for {finding.get('bug_class')} on {finding.get('target')}")
        
        target = finding.get('target', 'unknown')
        bug_class = finding.get('bug_class', 'unknown')
        severity = finding.get('severity', 'Medium')
        evidence = finding.get('evidence', '')
        poc_log = finding.get('poc_log', '')
        
        # Determine specific details based on bug class
        title = f"{severity} severity {bug_class.upper()} vulnerability found in {target}"
        impact = f"An attacker could exploit this {bug_class} to compromise the application or extract sensitive data."
        remediation = "Apply appropriate input validation, sanitization, and ensure proper access controls are in place."
        steps = "1. Send the malicious payload as observed in the proof of concept.\n2. Observe the application's response exposing the vulnerability."
        
        if bug_class == "info_disclosure":
            title = f"Sensitive Information Disclosure in {target}"
            impact = "Attackers can use leaked information (like config files or sensitive IDs) to launch further targeted attacks."
            remediation = "Ensure directories like /ftp, /backup, or /.git are strictly restricted to authenticated and authorized personnel only."
            steps = f"1. Navigate to the exposed endpoint on {target}.\n2. Observe that sensitive files are listed without authentication."
        elif bug_class == "ssti":
            title = f"Server-Side Template Injection (SSTI) in {target}"
            impact = "An attacker can execute arbitrary code on the server, leading to a complete system compromise."
            remediation = "Avoid using user input directly in templates. Use logic-less templates or securely escape input contextually."
            steps = "1. Inject a template expression (e.g., {{7*7}}) into the vulnerable parameter.\n2. Observe that the server evaluates the expression."
        
        try:
            return ReportContent(
                title=title,
                summary=evidence,
                severity=severity,
                impact=impact,
                steps_to_reproduce=steps,
                proof_of_concept=poc_log,
                remediation=remediation,
                raw_text="",
                poc_logs=[poc_log],
                target_platform=target_platform
            )
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return None

if __name__ == "__main__":
    # Test the generator with a dummy finding
    test_finding = {
        "target": "sandbox.localhost",
        "bug_class": "info_disclosure",
        "severity": "Medium",
        "evidence": "Exposed /ftp directory containing config.back",
        "poc_log": "GET /ftp HTTP/1.1\\n\\nHTTP/1.1 200 OK\\n\\nIndex of /ftp\\nconfig.back"
    }
    
    generator = ReportGenerator()
    report = generator.generate_report(test_finding)
    if report:
        print(f"Generated Title: {report.title}")
        print(f"Impact: {report.impact[:100]}...")
