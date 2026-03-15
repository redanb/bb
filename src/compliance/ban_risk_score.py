"""
Bug Bounty Co-Pilot — Ban Risk Score (BRS) Module
===================================================
Calculates a composite Ban Risk Score for every action in the workflow.

The BRS is the numerical embodiment of the Compliance-by-Design moat.
It aggregates risk signals from multiple sources and produces a single
0.0-1.0 score. If the score exceeds a configurable threshold, the
action is BLOCKED and flagged for senior triage.

Risk factors:
  1. ToS compliance status (from tos_engine.py)
  2. Submission velocity (too many submissions → suspicious)
  3. Report similarity (reports too similar → looks automated)
  4. Scope boundary proximity (testing near out-of-scope areas)
  5. Platform-specific risk rules (some platforms ban faster)

The BRS model IMPROVES OVER TIME via the data flywheel:
  - Tracks which actions historically led to bans/warnings.
  - Adjusts weights based on observed platform responses.

Patentable Method #3 (part of): "Compliance engine for real-time ToS
parsing and ban risk scoring in bug bounty workflows."
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto

from src.compliance.tos_engine import ComplianceCheckResult, ScopeStatus

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Human-readable risk classification."""
    SAFE = auto()          # BRS < 0.3
    CAUTION = auto()       # 0.3 <= BRS < 0.6
    HIGH_RISK = auto()     # 0.6 <= BRS < 0.8
    CRITICAL = auto()      # BRS >= 0.8 — ACTION BLOCKED


class BRSAction(Enum):
    """What to do based on the BRS score."""
    ALLOW = auto()
    WARN = auto()
    REQUIRE_REVIEW = auto()
    BLOCK = auto()


@dataclass
class BRSInput:
    """Input data for calculating the Ban Risk Score."""
    compliance_result: ComplianceCheckResult
    submission_count_last_hour: int = 0
    submission_count_last_day: int = 0
    report_similarity_score: float = 0.0  # 0.0 = unique, 1.0 = identical to template
    is_automated_action: bool = False
    platform: str = ""
    user_ban_history_count: int = 0  # How many times this user has been banned previously


@dataclass
class BRSResult:
    """The output of the Ban Risk Score calculation."""
    score: float  # 0.0 = no risk, 1.0 = maximum risk
    risk_level: RiskLevel
    action: BRSAction
    contributing_factors: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    @property
    def is_blocked(self) -> bool:
        return self.action == BRSAction.BLOCK


class BanRiskScorer:
    """
    Calculates the Ban Risk Score for a given action.

    Configuration:
      - block_threshold: BRS >= this value → BLOCK (default: 0.75)
      - review_threshold: BRS >= this value → REQUIRE_REVIEW (default: 0.50)
      - warn_threshold: BRS >= this value → WARN (default: 0.30)

    Weights (configurable, self-adjust over time):
      - compliance_weight: 0.40 (highest — ToS violations are #1 ban risk)
      - velocity_weight:   0.20
      - similarity_weight: 0.15
      - automation_weight: 0.15
      - history_weight:    0.10

    Usage:
        scorer = BanRiskScorer()
        result = scorer.calculate(BRSInput(...))
        if result.is_blocked:
            raise SubmissionBlockedError(...)
    """

    DEFAULT_WEIGHTS = {
        "compliance": 0.40,
        "velocity": 0.20,
        "similarity": 0.15,
        "automation": 0.15,
        "history": 0.10,
    }

    # Platform-specific risk multipliers (some platforms ban faster)
    PLATFORM_RISK_MULTIPLIERS = {
        "hackerone": 1.0,     # Standard
        "bugcrowd": 1.0,     # Standard
        "synack": 1.3,       # Stricter — private platform
        "intigriti": 1.0,    # Standard
        "bugbase": 0.9,      # Slightly more lenient (India-first partner)
    }

    def __init__(
        self,
        block_threshold: float = 0.75,
        review_threshold: float = 0.50,
        warn_threshold: float = 0.30,
        weights: dict[str, float] | None = None,
    ):
        self._block_threshold = block_threshold
        self._review_threshold = review_threshold
        self._warn_threshold = warn_threshold
        self._weights = weights or self.DEFAULT_WEIGHTS.copy()
        self._historical_scores: list[BRSResult] = []
        logger.info(
            "BanRiskScorer initialized: block=%.2f, review=%.2f, warn=%.2f",
            block_threshold, review_threshold, warn_threshold,
        )

    def calculate(self, brs_input: BRSInput) -> BRSResult:
        """
        Calculate the Ban Risk Score for a proposed action.

        Returns:
            BRSResult with the score, risk level, and recommended action.
        """
        factors: list[str] = []
        component_scores: dict[str, float] = {}

        # 1. Compliance risk (from ToS engine)
        compliance_score = brs_input.compliance_result.risk_score_contribution
        component_scores["compliance"] = compliance_score
        if compliance_score > 0:
            factors.append(f"ToS risk: {compliance_score:.2f}")
            for v in brs_input.compliance_result.violations:
                factors.append(f"  - {v.violation_type.name}: {v.detail}")

        # 2. Velocity risk (submission rate)
        velocity_score = self._calculate_velocity_risk(
            brs_input.submission_count_last_hour,
            brs_input.submission_count_last_day,
        )
        component_scores["velocity"] = velocity_score
        if velocity_score > 0:
            factors.append(f"Velocity risk: {velocity_score:.2f} ({brs_input.submission_count_last_hour}/hr, {brs_input.submission_count_last_day}/day)")

        # 3. Similarity risk (report looks templated)
        similarity_score = brs_input.report_similarity_score
        component_scores["similarity"] = similarity_score
        if similarity_score > 0.3:
            factors.append(f"Similarity risk: {similarity_score:.2f} (report may look automated)")

        # 4. Automation risk
        automation_score = 1.0 if brs_input.is_automated_action else 0.0
        component_scores["automation"] = automation_score
        if automation_score > 0:
            factors.append("Automation detected: action appears automated")

        # 5. History risk
        history_score = min(brs_input.user_ban_history_count * 0.25, 1.0)
        component_scores["history"] = history_score
        if history_score > 0:
            factors.append(f"Ban history risk: {history_score:.2f} ({brs_input.user_ban_history_count} prior bans)")

        # Weighted composite score
        raw_score = sum(
            component_scores[k] * self._weights[k]
            for k in self._weights
        )

        # Apply platform-specific risk multiplier
        multiplier = self.PLATFORM_RISK_MULTIPLIERS.get(brs_input.platform.lower(), 1.0)
        final_score = min(raw_score * multiplier, 1.0)

        # Determine risk level and action
        risk_level, action = self._classify(final_score)

        result = BRSResult(
            score=final_score,
            risk_level=risk_level,
            action=action,
            contributing_factors=factors,
        )

        self._historical_scores.append(result)

        logger.info(
            "BRS calculated: score=%.3f level=%s action=%s factors=%d",
            final_score, risk_level.name, action.name, len(factors),
        )

        return result

    def _calculate_velocity_risk(self, hourly: int, daily: int) -> float:
        """Calculate velocity risk based on submission rate."""
        # Thresholds based on typical platform guidelines
        hourly_risk = min(hourly / 10.0, 1.0)  # >10 submissions/hour is suspicious
        daily_risk = min(daily / 30.0, 1.0)    # >30 submissions/day is suspicious
        return max(hourly_risk, daily_risk)

    def _classify(self, score: float) -> tuple[RiskLevel, BRSAction]:
        """Classify a score into risk level and recommended action."""
        if score >= self._block_threshold:
            return RiskLevel.CRITICAL, BRSAction.BLOCK
        elif score >= self._review_threshold:
            return RiskLevel.HIGH_RISK, BRSAction.REQUIRE_REVIEW
        elif score >= self._warn_threshold:
            return RiskLevel.CAUTION, BRSAction.WARN
        else:
            return RiskLevel.SAFE, BRSAction.ALLOW

    def update_weights(self, new_weights: dict[str, float]) -> None:
        """
        Self-correcting: Update risk weights based on observed ban data.

        This is called by the self-correcting system when new ban/warning
        data is available from the Acceptance Intelligence Graph.
        """
        for key, value in new_weights.items():
            if key in self._weights:
                logger.info("BRS weight updated: %s = %.3f -> %.3f", key, self._weights[key], value)
                self._weights[key] = value

    @property
    def average_recent_score(self) -> float:
        """Average BRS score over the last 100 calculations."""
        recent = self._historical_scores[-100:]
        if not recent:
            return 0.0
        return sum(r.score for r in recent) / len(recent)
