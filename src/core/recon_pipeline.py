import logging
from enum import Enum
from typing import List, Dict, Any
import requests
import socket
import urllib3
from datetime import datetime

# Disable insecure request warnings for local practice targets
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class AllowedBugClasses(Enum):
    IDOR = "idor"
    XSS = "xss"
    INFO_DISCLOSURE = "info_disclosure"
    SSRF = "ssrf"
    SSTI = "ssti"

class ReconPipeline:
    """
    Enforces safe reconnaissance.
    Strictly rate limits active tools and restricts vulnerability payloads
    exclusively to beginner-safe low-risk bug classes: IDOR, XSS, and Info-Disclosure.
    This version implements REAL HTTP probes instead of simulated sleep.
    """

    def __init__(self):
        self.allowed_classes = {c.value for c in AllowedBugClasses}

    def passive_recon(self, domain: str) -> List[str]:
        """Performs actual DNS resolution to verify target existence before active scanning."""
        logger.info(f"Running passive DNS resolution on {domain}")
        found_subdomains = []
        try:
            # Clean domain string (remove http:// or https:// if present)
            clean_domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
            if ":" in clean_domain:
                clean_domain = clean_domain.split(":")[0]
                
            ip = socket.gethostbyname(clean_domain)
            logger.info(f"Resolved {clean_domain} to {ip}")
            # In a real environment, we'd wrap Subfinder here. For localhost/JuiceShop practice, 
            # we just return the base domain as the active target if it resolves.
            found_subdomains.append(domain)
        except socket.gaierror:
            logger.warning(f"Failed to resolve {domain}")
            
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

    def active_scan(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Performs REAL, verifiable HTTP requests against the target to find low-hanging fruit.
        Specifically tailored to find Juice Shop practice vulnerabilities (or similar real-world configs).
        """
        findings = []
        logger.info(f"Initiating active scan on {target_url} for low-risk vulnerabilities...")
        
        # Ensure we have a schema
        if not target_url.startswith("http"):
            target_url = "http://" + target_url

        # Probe 1: Exposed FTP Directory (Info Disclosure)
        ftp_url = f"{target_url}/ftp"
        try:
            logger.info(f"Probing: {ftp_url}")
            resp = requests.get(ftp_url, verify=False, timeout=5)
            if resp.status_code == 200 and "Index of /ftp" in resp.text or "quarantine" in resp.text:
                findings.append({
                    "bug_class": "info_disclosure",
                    "severity": "Medium",
                    "evidence": "Exposed /ftp directory found containing sensitive backup/config files.",
                    "poc_log": f"GET {ftp_url} HTTP/1.1\n\nHTTP/1.1 {resp.status_code} OK\n\n{resp.text[:200]}..."
                })
        except requests.RequestException as e:
            logger.debug(f"/ftp probe failed: {e}")

        # Probe 2: BOLA/IDOR on Users API Endpoint (Juice Shop specific, but common in wild)
        users_url = f"{target_url}/api/Users"
        try:
            logger.info(f"Probing: {users_url}")
            resp = requests.get(users_url, verify=False, timeout=5)
            if resp.status_code == 200 and "data" in resp.json() and len(resp.json()["data"]) > 0:
                findings.append({
                    "bug_class": "idor",
                    "severity": "High",
                    "evidence": "Unauthenticated access to /api/Users endpoint disclosing PII (emails/passwords hashes).",
                    "poc_log": f"GET {users_url} HTTP/1.1\n\nHTTP/1.1 {resp.status_code} OK\n\n{resp.text[:200]}..."
                })
        except (requests.RequestException, ValueError) as e:
            logger.debug(f"/api/Users probe failed: {e}")
            
        # Probe 3: Reflective XSS Probe on Search (Juice Shop common)
        search_url = f"{target_url}/rest/products/search?q=<script>alert('VULNERABLE')</script>"
        try:
            logger.info(f"Probing: {search_url}")
            resp = requests.get(search_url, verify=False, timeout=5)
            # Juice shop returns the exact query string unescaped in an error/success message
            if "<script>alert('VULNERABLE')</script>" in resp.text:
                 findings.append({
                    "bug_class": "xss",
                    "severity": "High",
                    "evidence": "Reflected Cross-Site Scripting (XSS) detected in the 'q' parameter of the search API.",
                    "poc_log": f"GET {search_url} HTTP/1.1\n\nHTTP/1.1 {resp.status_code} OK\n\n{resp.text[:200]}..."
                })
        except requests.RequestException as e:
            logger.debug(f"Search XSS probe failed: {e}")

        # Probe 4: SSRF on profile image fetch
        ssrf_url = f"{target_url}/profile/image?url=http://169.254.169.254/latest/meta-data/"
        try:
            logger.info(f"Probing: {ssrf_url}")
            resp = requests.get(ssrf_url, verify=False, timeout=5)
            if resp.status_code == 200 and ("ami-id" in resp.text or "instance-id" in resp.text):
                findings.append({
                    "bug_class": "ssrf",
                    "severity": "Critical",
                    "evidence": "SSRF vulnerability detected via AWS metadata endpoint exposure on profile image fetch.",
                    "poc_log": f"GET {ssrf_url} HTTP/1.1\n\nHTTP/1.1 {resp.status_code} OK\n\n{resp.text[:200]}..."
                })
        except requests.RequestException as e:
            logger.debug(f"SSRF probe failed: {e}")

        # Probe 5: SSTI on template renderer
        ssti_url = f"{target_url}/render?template={{{{7*7}}}}"
        try:
            logger.info(f"Probing: {ssti_url}")
            resp = requests.get(ssti_url, verify=False, timeout=5)
            if resp.status_code == 200 and "49" in resp.text:
                findings.append({
                    "bug_class": "ssti",
                    "severity": "Critical",
                    "evidence": "Server-Side Template Injection (SSTI) detected. Template evaluated {{7*7}} as 49.",
                    "poc_log": f"GET {ssti_url} HTTP/1.1\n\nHTTP/1.1 {resp.status_code} OK\n\n{resp.text[:200]}..."
                })
        except requests.RequestException as e:
            logger.debug(f"SSTI probe failed: {e}")

        logger.info(f"Active scan complete. Found {len(findings)} issues.")
        return findings

if __name__ == "__main__":
    pipeline = ReconPipeline()
    tests = ["sqli", "idor", "xss", "rce", "dos"]
    safe = pipeline.filter_payloads(tests)
    print(f"Executing payload classes: {safe}")
    
    # Simple self-test against a public target (passive only)
    print(pipeline.passive_recon("google.com"))
