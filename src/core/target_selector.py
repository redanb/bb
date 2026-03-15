import logging
from typing import TypedDict, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ProgramData(TypedDict):
    id: str
    name: str
    platform: str
    reports_resolved: int
    last_report_date: str
    scopes: List[str]
    allows_scanners: bool
    is_indian: bool

class TargetSelector:
    """
    GRAIN Methodology Target Selector:
    G - Green scope (wide, not just www.com)
    R - Recent activity (resolved < 6 months)
    A - Avoid Huge (< 500 lifetime reports)
    I - Indian/Growing (prioritized)
    N - No Scanner Ban
    """

    def __init__(self):
        self.max_reports = 500
        self.stale_days = 180

    def select_targets(self, candidates: List[ProgramData]) -> List[ProgramData]:
        selected = []
        now = datetime.utcnow()

        for prog in candidates:
            # R: Recent
            last_date = datetime.fromisoformat(prog["last_report_date"])
            if (now - last_date).days > self.stale_days:
                logger.debug(f"{prog['id']} dropped: Discarded due to stale activity.")
                continue

            # A: Avoid Huge
            if prog["reports_resolved"] > self.max_reports:
                logger.debug(f"{prog['id']} dropped: Discarded due to saturation (>500 reports).")
                continue

            # N: No scanner ban
            if not prog["allows_scanners"]:
                logger.debug(f"{prog['id']} dropped: Scanners explicitly banned.")
                continue

            # G: Green scope (must have wildcards or deep paths, simplified check here)
            if not any(scope.startswith("*.") for scope in prog["scopes"]):
                logger.debug(f"{prog['id']} dropped: Scope too narrow.")
                continue

            selected.append(prog)

        # I: Prioritize Indian/Growing startups
        selected.sort(key=lambda p: (p["is_indian"], -p["reports_resolved"]), reverse=True)
        return selected[:5]

if __name__ == "__main__":
    selector = TargetSelector()
    
    mock_programs = [
        {"id": "p1", "name": "BigCorp", "platform": "hackerone", "reports_resolved": 15000, "last_report_date": "2026-03-01T00:00:00", "scopes": ["*.bigcorp.com"], "allows_scanners": True, "is_indian": False},
        {"id": "p2", "name": "DeadApp", "platform": "bugcrowd", "reports_resolved": 40, "last_report_date": "2024-01-01T00:00:00", "scopes": ["*.deadapp.com"], "allows_scanners": True, "is_indian": False},
        {"id": "p3", "name": "IndianFintech", "platform": "bugbase", "reports_resolved": 120, "last_report_date": "2026-03-10T00:00:00", "scopes": ["*.indianfintech.in"], "allows_scanners": True, "is_indian": True},
        {"id": "p4", "name": "StrictBank", "platform": "intigriti", "reports_resolved": 200, "last_report_date": "2026-03-12T00:00:00", "scopes": ["strictbank.com"], "allows_scanners": False, "is_indian": False},
    ]

    best = selector.select_targets(mock_programs)
    print("Top Approved Targets:")
    for b in best:
        print(f"- {b['name']} ({b['platform']})")
