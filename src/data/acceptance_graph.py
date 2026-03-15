"""
Bug Bounty Co-Pilot -- Acceptance Intelligence Graph
=====================================================
The CORE DATA MOAT -- a proprietary, time-evolving dataset that records
the outcomes of vulnerability submissions across platforms.

What it tracks:
  - Which vulnerability types are accepted/rejected by specific triage teams.
  - Which report formats, severity assessments, and writing styles succeed.
  - Which platforms/programs have higher acceptance rates at which times.
  - Dup rates per target, per vulnerability class.

Why it's a moat:
  - Exponentially more valuable over time (network effect on data).
  - Cannot be replicated without equivalent submission volume.
  - Powers the Income Guarantee (v4.0) and Bounty/Hour optimization.

Patentable Method #1: "A system for predicting vulnerability report
acceptance using cross-platform triage outcome data."
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class SubmissionOutcome(Enum):
    """The outcome of a vulnerability submission."""
    ACCEPTED = auto()
    REJECTED = auto()
    DUPLICATE = auto()
    INFORMATIVE = auto()   # Valid but not a vulnerability
    NOT_APPLICABLE = auto()
    PENDING = auto()


class VulnerabilityClass(Enum):
    """Common vulnerability classifications."""
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SQLI = "sql_injection"
    SSRF = "ssrf"
    IDOR = "idor"
    RCE = "rce"
    AUTH_BYPASS = "auth_bypass"
    CSRF = "csrf"
    INFO_DISCLOSURE = "info_disclosure"
    OPEN_REDIRECT = "open_redirect"
    RATE_LIMITING = "rate_limiting"
    BUSINESS_LOGIC = "business_logic"
    OTHER = "other"


@dataclass
class SubmissionRecord:
    """A single submission outcome record for the graph."""
    record_id: str = ""
    platform: str = ""            # hackerone, bugcrowd, etc.
    program_id: str = ""
    vulnerability_class: VulnerabilityClass = VulnerabilityClass.OTHER
    severity_claimed: str = ""    # What the researcher claimed
    severity_resolved: str = ""   # What the triage team resolved
    outcome: SubmissionOutcome = SubmissionOutcome.PENDING
    bounty_amount_usd: float = 0.0
    report_quality_score: float = 0.0  # From Report Linter
    llm_model_used: str = ""
    time_to_resolution_hours: float = 0.0
    submitted_at: float = field(default_factory=time.time)
    resolved_at: float | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class AcceptancePrediction:
    """Prediction of acceptance likelihood for a proposed submission."""
    acceptance_probability: float  # 0.0-1.0
    dup_probability: float         # 0.0-1.0
    estimated_bounty_usd: float
    confidence: float              # 0.0-1.0 -- higher with more data
    similar_submissions: int       # Number of data points used
    recommendation: str            # Human-readable recommendation


class AcceptanceGraph:
    """
    The Cross-Platform Acceptance Intelligence Graph.

    This is the irreproducible competitive advantage. Every submission
    outcome feeds into this graph, making predictions more accurate
    over time.

    Usage:
        graph = AcceptanceGraph()
        graph.record(SubmissionRecord(
            platform="hackerone",
            program_id="prog_1",
            vulnerability_class=VulnerabilityClass.XSS_STORED,
            severity_claimed="High",
            outcome=SubmissionOutcome.ACCEPTED,
            bounty_amount_usd=500.0,
        ))
        prediction = graph.predict("hackerone", "prog_1", VulnerabilityClass.XSS_STORED, "High")
    """

    def __init__(self):
        self._records: list[SubmissionRecord] = []
        # Indexes for fast lookup
        self._by_platform: dict[str, list[SubmissionRecord]] = defaultdict(list)
        self._by_program: dict[str, list[SubmissionRecord]] = defaultdict(list)
        self._by_vuln_class: dict[VulnerabilityClass, list[SubmissionRecord]] = defaultdict(list)
        self._by_platform_vuln: dict[tuple[str, VulnerabilityClass], list[SubmissionRecord]] = defaultdict(list)
        logger.info("AcceptanceGraph initialized.")

    def record(self, submission: SubmissionRecord) -> None:
        """Record a submission outcome into the graph."""
        self._records.append(submission)
        self._by_platform[submission.platform].append(submission)
        self._by_program[submission.program_id].append(submission)
        self._by_vuln_class[submission.vulnerability_class].append(submission)
        self._by_platform_vuln[(submission.platform, submission.vulnerability_class)].append(submission)

        logger.info(
            "Graph record: platform=%s program=%s vuln=%s outcome=%s bounty=$%.0f",
            submission.platform, submission.program_id,
            submission.vulnerability_class.value,
            submission.outcome.name, submission.bounty_amount_usd,
        )

    def predict(
        self,
        platform: str,
        program_id: str,
        vulnerability_class: VulnerabilityClass,
        severity: str,
    ) -> AcceptancePrediction:
        """
        Predict the acceptance likelihood of a proposed submission.

        Uses hierarchical matching:
          1. Exact match: same program + same vuln class (highest confidence)
          2. Platform match: same platform + same vuln class
          3. Vuln class match: same vuln class across all platforms
          4. Global average: fallback when no specific data exists
        """
        # Level 1: Exact program match
        program_records = [
            r for r in self._by_program[program_id]
            if r.vulnerability_class == vulnerability_class
            and r.outcome != SubmissionOutcome.PENDING
        ]

        if len(program_records) >= 3:
            return self._compute_prediction(program_records, confidence_base=0.9)

        # Level 2: Platform + vuln class match
        platform_records = [
            r for r in self._by_platform_vuln[(platform, vulnerability_class)]
            if r.outcome != SubmissionOutcome.PENDING
        ]

        if len(platform_records) >= 5:
            return self._compute_prediction(platform_records, confidence_base=0.7)

        # Level 3: Vuln class match across all platforms
        vuln_records = [
            r for r in self._by_vuln_class[vulnerability_class]
            if r.outcome != SubmissionOutcome.PENDING
        ]

        if len(vuln_records) >= 5:
            return self._compute_prediction(vuln_records, confidence_base=0.5)

        # Level 4: Global average (low confidence)
        all_resolved = [
            r for r in self._records
            if r.outcome != SubmissionOutcome.PENDING
        ]

        if all_resolved:
            return self._compute_prediction(all_resolved, confidence_base=0.2)

        # No data at all
        return AcceptancePrediction(
            acceptance_probability=0.5,
            dup_probability=0.3,
            estimated_bounty_usd=0.0,
            confidence=0.0,
            similar_submissions=0,
            recommendation="Insufficient data. Proceed with caution.",
        )

    def _compute_prediction(
        self,
        records: list[SubmissionRecord],
        confidence_base: float,
    ) -> AcceptancePrediction:
        """Compute prediction from a set of matching records."""
        total = len(records)
        accepted = sum(1 for r in records if r.outcome == SubmissionOutcome.ACCEPTED)
        duplicates = sum(1 for r in records if r.outcome == SubmissionOutcome.DUPLICATE)
        bounties = [r.bounty_amount_usd for r in records if r.bounty_amount_usd > 0]

        acceptance_prob = accepted / total if total > 0 else 0.0
        dup_prob = duplicates / total if total > 0 else 0.0
        avg_bounty = sum(bounties) / len(bounties) if bounties else 0.0

        # Confidence increases with more data points (log scale)
        import math
        confidence = min(confidence_base * (1 + math.log10(max(total, 1)) / 3), 1.0)

        # Generate recommendation
        if acceptance_prob >= 0.7:
            rec = f"High acceptance rate ({acceptance_prob:.0%}). Strong submission target."
        elif acceptance_prob >= 0.4:
            rec = f"Moderate acceptance rate ({acceptance_prob:.0%}). Review report quality."
        else:
            rec = f"Low acceptance rate ({acceptance_prob:.0%}). Consider alternative targets."

        if dup_prob >= 0.3:
            rec += f" WARNING: High dup rate ({dup_prob:.0%})."

        return AcceptancePrediction(
            acceptance_probability=acceptance_prob,
            dup_probability=dup_prob,
            estimated_bounty_usd=avg_bounty,
            confidence=confidence,
            similar_submissions=total,
            recommendation=rec,
        )

    def get_stats(self) -> dict[str, Any]:
        """Get summary statistics of the graph."""
        total = len(self._records)
        resolved = [r for r in self._records if r.outcome != SubmissionOutcome.PENDING]
        return {
            "total_records": total,
            "resolved_records": len(resolved),
            "platforms": len(self._by_platform),
            "programs": len(self._by_program),
            "vuln_classes": len(self._by_vuln_class),
            "overall_acceptance_rate": (
                sum(1 for r in resolved if r.outcome == SubmissionOutcome.ACCEPTED) / len(resolved)
                if resolved else 0.0
            ),
            "total_bounty_earned": sum(r.bounty_amount_usd for r in resolved),
        }

    @property
    def total_records(self) -> int:
        return len(self._records)
