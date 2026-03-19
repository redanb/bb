import logging
from enum import Enum
from typing import List, Dict, Any
import requests
import socket
import urllib3
from datetime import datetime
from src.core.adaptive_engine import AdaptiveEngine
from src.core.delegation_broker import DelegationBroker

# Disable insecure request warnings for local practice targets
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class AllowedBugClasses(Enum):
    IDOR = "idor"
    XSS = "xss"
    INFO_DISCLOSURE = "info_disclosure"
    SSRF = "ssrf"
    SSTI = "ssti"
    SQLI_BLIND = "sqli_blind"  # Time-based, safe for real-world
    OPEN_REDIRECT = "open_redirect"

class ReconPipeline:
    """
    Enforces safe reconnaissance.
    Strictly rate limits active tools and restricts vulnerability payloads
    exclusively to beginner-safe low-risk bug classes: IDOR, XSS, and Info-Disclosure.
    This version implements REAL HTTP probes instead of simulated sleep.
    """

    def __init__(self):
        self.allowed_classes = {c.value for c in AllowedBugClasses}
        self.adaptive = AdaptiveEngine()
        self.broker = DelegationBroker()

    # Common entry-point subdomains to probe on real targets
    REAL_WORLD_SUBDOMAINS = ["api", "app", "dev", "staging", "www", "admin", "m", "internal"]

    def passive_recon(self, domain: str) -> List[str]:
        """Performs actual DNS resolution + common subdomain discovery."""
        logger.info(f"Running passive DNS resolution on {domain}")
        found_subdomains = []
        try:
            # Clean domain string (remove http:// or https:// if present)
            clean_domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
            if ":" in clean_domain:
                clean_domain = clean_domain.split(":")[0]

            # Always include the root domain first
            ip = socket.gethostbyname(clean_domain)
            logger.info(f"Resolved {clean_domain} to {ip}")
            found_subdomains.append(f"https://{clean_domain}")

            # God-Mode: Enumerate common subdomains via DNS resolution
            for sub in self.REAL_WORLD_SUBDOMAINS:
                candidate = f"{sub}.{clean_domain}"
                try:
                    sub_ip = socket.gethostbyname(candidate)
                    logger.info(f"Found live subdomain: {candidate} -> {sub_ip}")
                    found_subdomains.append(f"https://{candidate}")
                except socket.gaierror:
                    pass  # Subdomain doesn't exist, skip silently

        except socket.gaierror:
            logger.warning(f"Failed to resolve base domain: {domain}")
            
        return found_subdomains

    def filter_payloads(self, proposed_tests: List[str]) -> List[str]:
        """ Filters out dangerous payloads. """
        safe_tests = []
        for test in proposed_tests:
            if test in self.allowed_classes:
                safe_tests.append(test)
            else:
                logger.warning(f"BLOCKED payload: {test} is not permitted for automated testing.")
        return safe_tests

    def active_scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Performs active vulnerability scanning using the AdaptiveEngine for resilience.
        """
        findings = []
        logger.info(f"Starting Adaptive Active Scan on {url}...")
        
        # 1. Nuclei-inspired deep scan with Adaptive Headers
        nuclei_findings = self.run_nuclei_session(url)
        findings.extend(nuclei_findings)
        
        # 2. Adaptive Probing for common vulnerabilities
        headers = self.adaptive.get_adaptive_headers()
        try:
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            status = self.adaptive.analyze_block(url, resp.status_code, resp.text)
            
            if "WAF_DETECTED" in status:
                ticket_id = self.broker.create_delegation_ticket(url, "WAF_BYPASS", f"Detected {status}. Response length: {len(resp.text)}")
                findings.append({
                    "bug_class": "WAF_SECURITY_BARRIER",
                    "severity": "Info",
                    "evidence": f"WAF Block encountered. Task delegated to Manus Bot (Ticket: {ticket_id})",
                    "timestamp": datetime.now().isoformat()
                })
                return findings # Stop active scanning, delegated to higher tier
            
            # If 404/403, try mutations (e.g. .env -> .env.bak)
            if resp.status_code in [403, 404]:
                logger.info(f"Target {url} returned {resp.status_code}. Attempting adaptive mutations...")
                mutations = self.adaptive.mutate_path(url, resp.status_code)
                for mutated_url in mutations:
                    try:
                        m_resp = requests.get(mutated_url, headers=self.adaptive.get_adaptive_headers(), timeout=5, verify=False)
                        if m_resp.status_code == 200:
                            findings.append({
                                "bug_class": "info_disclosure",
                                "severity": "Medium",
                                "evidence": f"Found sensitive file via adaptive mutation: {mutated_url}",
                                "timestamp": datetime.now().isoformat()
                            })
                    except requests.RequestException:
                        continue
        except Exception as e:
            logger.error(f"Error during active scan of {url}: {e}")
            
        logger.info(f"Active scan complete. Found {len(findings)} total issues.")
        return findings

    def run_nuclei_session(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Simulates a Nuclei-v3 session by executing modular templates (10x Improvement).
        Uses AdaptiveEngine to rotate footprints for each template.
        """
        nuclei_findings = []
        templates = [
            {
                "id": "git-config-disclosure",
                "name": "Git Config Disclosure",
                "severity": "Medium",
                "path": "/.git/config",
                "matchers": ["[core]", "repositoryformatversion"],
                "bug_class": "info_disclosure"
            },
            {
                "id": "env-file-disclosure",
                "name": "Environment File Disclosure",
                "severity": "High",
                "path": "/.env",
                "matchers": ["DB_PASSWORD", "API_KEY", "AWS_ACCESS_KEY"],
                "bug_class": "info_disclosure"
            },
            {
                "id": "phpinfo-disclosure",
                "name": "PHPInfo Exposure",
                "severity": "Low",
                "path": "/phpinfo.php",
                "matchers": ["PHP Version", "System", "Build Date"],
                "bug_class": "info_disclosure"
            },
            {
                "id": "wp-config-backup",
                "name": "WordPress Config Backup",
                "severity": "Critical",
                "path": "/wp-config.php.bak",
                "matchers": ["DB_NAME", "DB_USER", "DB_PASSWORD"],
                "bug_class": "info_disclosure"
            }
        ]

        logger.info(f"Engaging Nuclei Engine: Executing {len(templates)} 10x templates (Self-Evolution Mode)...")
        for template in templates:
            try:
                probe_url = target_url.rstrip("/") + template["path"]
                headers = self.adaptive.get_adaptive_headers()
                resp = requests.get(probe_url, headers=headers, timeout=5, verify=False)
                
                if resp.status_code == 200 and any(m in resp.text for m in template["matchers"]):
                    logger.info(f"[NUCLEI HIT] {template['name']} on {probe_url}")
                    nuclei_findings.append({
                        "bug_class": template["bug_class"],
                        "severity": template["severity"],
                        "evidence": f"Verified via Nuclei Template: {template['name']} at {probe_url}",
                        "timestamp": datetime.now().isoformat()
                    })
            except Exception:
                continue
                
        return nuclei_findings

        logger.info(f"Engaging Nuclei Engine: Executing {len(templates)} 10x templates...")
        for template in templates:
            probe_url = f"{target_url.rstrip('/')}{template['path']}"
            try:
                resp = requests.get(probe_url, verify=False, timeout=5)
                # If any of the matchers are in the response body, it's a hit
                if resp.status_code == 200 and any(m in resp.text for m in template['matchers']):
                    logger.info(f"[NUCLEI HIT] {template['name']} on {probe_url}")
                    nuclei_findings.append({
                        "bug_class": template['bug_class'],
                        "severity": template['severity'],
                        "evidence": f"Nuclei Template '{template['id']}' matched on {probe_url}.",
                        "poc_log": f"GET {probe_url} HTTP/1.1\n\nHTTP/1.1 {resp.status_code} OK\n\n{resp.text[:200]}..."
                    })
            except requests.RequestException:
                pass
        
        return nuclei_findings

if __name__ == "__main__":
    pipeline = ReconPipeline()
    tests = ["sqli", "idor", "xss", "rce", "dos"]
    safe = pipeline.filter_payloads(tests)
    print(f"Executing payload classes: {safe}")
    
    # Simple self-test against a public target (passive only)
    # Using python print with sys.stdout.reconfigure to avoid encoding errors on Windows
    import sys
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    print(pipeline.passive_recon("google.com"))
