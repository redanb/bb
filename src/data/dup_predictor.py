"""
Bug Bounty Co-Pilot -- Duplicate Prediction System
====================================================
Predicts the likelihood of a vulnerability submission being marked as a
duplicate, saving hunters from wasted effort.

Uses the Acceptance Intelligence Graph data to compare current findings
against historically reported vulnerabilities for the same target.

Patentable Method #2: "A method for predicting duplicate vulnerability
reports using historical submission pattern analysis."
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

from src.data.acceptance_graph import (
    AcceptanceGraph, SubmissionOutcome, SubmissionRecord, VulnerabilityClass,
)

logger = logging.getLogger(__name__)


@dataclass
class DupCheckResult:
    """Result of a duplicate prediction check."""
    dup_probability: float         # 0.0-1.0
    confidence: float              # 0.0-1.0
    similar_reports_count: int     # Number of similar historical reports
    most_similar_vuln_class: VulnerabilityClass | None = None
    recommendation: str = ""
    should_proceed: bool = True    # False if dup_probability > threshold


@dataclass
class VulnerabilityFingerprint:
    """A fingerprint of a vulnerability for deduplication matching."""
    target_domain: str
    endpoint: str               # e.g., /api/users
    vulnerability_class: VulnerabilityClass
    parameter: str = ""         # e.g., "search_query"
    payload_hash: str = ""      # Hash of the exploit payload

    @property
    def fingerprint_hash(self) -> str:
        """Unique hash for this vulnerability fingerprint."""
        data = f"{self.target_domain}|{self.endpoint}|{self.vulnerability_class.value}|{self.parameter}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


class DupPredictor:
    """
    Predicts duplicate vulnerability submissions.

    Uses three layers of matching:
      1. Exact fingerprint match -- same domain+endpoint+vuln_class+param
      2. Fuzzy fingerprint match -- same domain+vuln_class (different endpoint)
      3. Statistical match -- same program+vuln_class from Acceptance Graph

    Usage:
        predictor = DupPredictor(acceptance_graph=graph)
        fingerprint = VulnerabilityFingerprint(
            target_domain="example.com",
            endpoint="/api/search",
            vulnerability_class=VulnerabilityClass.XSS_REFLECTED,
            parameter="q",
        )
        result = predictor.check(fingerprint, program_id="prog_1", platform="hackerone")
        if not result.should_proceed:
            print("WARNING: High dup probability, consider different target")
    """

    def __init__(
        self,
        acceptance_graph: AcceptanceGraph,
        dup_threshold: float = 0.6,
    ):
        self._graph = acceptance_graph
        self._dup_threshold = dup_threshold
        self._known_fingerprints: dict[str, list[VulnerabilityFingerprint]] = {}
        logger.info("DupPredictor initialized. Threshold: %.2f", dup_threshold)

    def register_fingerprint(self, fingerprint: VulnerabilityFingerprint) -> None:
        """Register a known vulnerability fingerprint (from past submissions)."""
        key = f"{fingerprint.target_domain}|{fingerprint.vulnerability_class.value}"
        self._known_fingerprints.setdefault(key, []).append(fingerprint)

    def check(
        self,
        fingerprint: VulnerabilityFingerprint,
        program_id: str = "",
        platform: str = "",
    ) -> DupCheckResult:
        """
        Check if a proposed vulnerability is likely a duplicate.

        Returns:
            DupCheckResult with probability, confidence, and recommendation.
        """
        scores: list[tuple[str, float]] = []

        # Layer 1: Exact fingerprint match
        exact_key = f"{fingerprint.target_domain}|{fingerprint.vulnerability_class.value}"
        known = self._known_fingerprints.get(exact_key, [])
        exact_matches = [
            k for k in known
            if k.endpoint == fingerprint.endpoint and k.parameter == fingerprint.parameter
        ]
        if exact_matches:
            scores.append(("exact_match", 0.95))

        # Layer 2: Fuzzy match (same domain + vuln class, different endpoint)
        fuzzy_matches = [
            k for k in known
            if k.endpoint != fingerprint.endpoint
        ]
        if fuzzy_matches:
            # More fuzzy matches = higher dup probability
            fuzzy_score = min(len(fuzzy_matches) * 0.15, 0.7)
            scores.append(("fuzzy_match", fuzzy_score))

        # Layer 3: Statistical match from Acceptance Graph
        prediction = self._graph.predict(
            platform=platform,
            program_id=program_id,
            vulnerability_class=fingerprint.vulnerability_class,
            severity="",
        )
        if prediction.dup_probability > 0:
            scores.append(("graph_prediction", prediction.dup_probability))

        # Combine scores (weighted average with max cap)
        if scores:
            dup_probability = min(
                sum(s for _, s in scores) / len(scores) * 1.2,  # Slight upward bias for safety
                1.0,
            )
            confidence = min(len(scores) * 0.3, 0.9)
        else:
            dup_probability = 0.1  # Low base rate
            confidence = 0.1

        should_proceed = dup_probability < self._dup_threshold

        # Generate recommendation
        if dup_probability >= 0.8:
            rec = "VERY HIGH dup probability. Strongly recommend choosing a different target."
        elif dup_probability >= 0.5:
            rec = "Moderate dup risk. Ensure your finding has a unique angle or deeper impact."
        elif dup_probability >= 0.3:
            rec = "Some dup risk exists. Proceed but document unique aspects carefully."
        else:
            rec = "Low dup risk. Good target for submission."

        result = DupCheckResult(
            dup_probability=dup_probability,
            confidence=confidence,
            similar_reports_count=len(exact_matches) + len(fuzzy_matches),
            most_similar_vuln_class=fingerprint.vulnerability_class,
            recommendation=rec,
            should_proceed=should_proceed,
        )

        logger.info(
            "Dup check: domain=%s vuln=%s dup_prob=%.2f proceed=%s",
            fingerprint.target_domain, fingerprint.vulnerability_class.value,
            dup_probability, should_proceed,
        )

        return result
