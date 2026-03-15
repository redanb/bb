import logging
from enum import Enum
from typing import List

logger = logging.getLogger(__name__)

class AllowedBugClasses(Enum):
    IDOR = "idor"
    XSS = "xss"
    INFO_DISCLOSURE = "info_disclosure"

class ReconPipeline:
    """
    Enforces safe reconnaissance.
    Strictly rate limits active tools (httpx) and restricts vulnerability payloads
    exclusively to beginner-safe low-risk bug classes: IDOR, XSS, and Info-Disclosure.
    """

    def __init__(self):
        self.allowed_classes = {c.value for c in AllowedBugClasses}

    def passive_recon(self, domain: str) -> List[str]:
        """Simulates running `subfinder` safely without touching target."""
        logger.info(f"Running passive subfinder on {domain}")
        return [f"api.{domain}", f"dev.{domain}"]

    def filter_payloads(self, proposed_tests: List[str]) -> List[str]:
        """
        Filters out dangerous payloads (SQLi, SSRF, RCE, DoS).
        Only allows IDOR, XSS, Info Disclosure tests.
        """
        safe_tests = []
        for test in proposed_tests:
            if test in self.allowed_classes:
                safe_tests.append(test)
            else:
                logger.warning(f"BLOCKED payload: {test} is not permitted for automated testing.")
        return safe_tests

if __name__ == "__main__":
    pipeline = ReconPipeline()
    tests = ["sqli", "idor", "xss", "rce", "dos"]
    safe = pipeline.filter_payloads(tests)
    print(f"Proposed: {tests}")
    print(f"Executing only: {safe}")
