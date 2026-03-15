"""
Bug Bounty Co-Pilot — Terms of Service Compliance Engine
=========================================================
Parses and enforces per-program Terms of Service (ToS) constraints.

This is the PRIMARY DEFENSIVE MOAT and risk mitigation against platform bans.
(v2 Gold Standard: Compliance-by-Design)

Key features:
  - Maintains a registry of platform program scopes (in-scope vs. out-of-scope assets).
  - Blocks all actions targeting out-of-scope assets BEFORE they execute.
  - Tracks rate limits per-program to prevent velocity-based bans.
  - Outputs a compliance_status for every action, consumable by the BRS module.

Patentable Method #3: "Compliance engine for real-time ToS parsing and
ban risk scoring in bug bounty workflows."
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger(__name__)


class ScopeStatus(Enum):
    """Whether a target asset is in-scope for testing under the program's ToS."""
    IN_SCOPE = auto()
    OUT_OF_SCOPE = auto()
    UNKNOWN = auto()  # Not in the program registry — treat as OUT_OF_SCOPE (safe default)


class ComplianceViolationType(Enum):
    """Types of ToS violations the engine can detect."""
    OUT_OF_SCOPE_ASSET = auto()
    RATE_LIMIT_EXCEEDED = auto()
    PROHIBITED_TESTING_METHOD = auto()
    UNAUTHORIZED_AUTOMATION = auto()
    SCOPE_BOUNDARY_PROXIMITY = auto()  # Asset is dangerously close to scope boundary


class ComplianceViolation(Exception):
    """Raised when a proposed action violates the program's ToS."""

    def __init__(self, violation_type: ComplianceViolationType, detail: str, program_id: str):
        self.violation_type = violation_type
        self.detail = detail
        self.program_id = program_id
        super().__init__(f"ToS VIOLATION [{program_id}] {violation_type.name}: {detail}")


@dataclass
class ProgramScope:
    """Defines the testing scope for a single bug bounty program."""
    program_id: str
    platform: str  # "hackerone", "bugcrowd", "synack", "intigriti", "bugbase"
    in_scope_domains: list[str] = field(default_factory=list)
    in_scope_patterns: list[str] = field(default_factory=list)  # Regex patterns
    out_of_scope_domains: list[str] = field(default_factory=list)
    out_of_scope_patterns: list[str] = field(default_factory=list)
    max_requests_per_minute: int = 60  # Rate limit (conservative default)
    prohibited_methods: list[str] = field(default_factory=list)  # e.g., ["ddos", "social_engineering"]
    allows_automated_scanning: bool = False  # Most programs DON'T — safe default
    bounty_range_usd: tuple[float, float] = (0.0, 0.0)
    last_updated: float = field(default_factory=time.time)


@dataclass
class ComplianceCheckResult:
    """The result of checking an action against the program's ToS."""
    is_compliant: bool
    violations: list[ComplianceViolation] = field(default_factory=list)
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN
    risk_score_contribution: float = 0.0  # 0.0 = no risk, 1.0 = maximum risk


class ToSEngine:
    """
    The Per-Program Terms of Service Compliance Engine.

    Usage:
        engine = ToSEngine()
        engine.register_program(ProgramScope(
            program_id="hackerone_prog_1",
            platform="hackerone",
            in_scope_domains=["*.example.com"],
            out_of_scope_domains=["admin.example.com"],
        ))
        result = engine.check_compliance("hackerone_prog_1", target="api.example.com", method="scan")
        if not result.is_compliant:
            # Block the action
            ...
    """

    def __init__(self):
        self._programs: dict[str, ProgramScope] = {}
        self._request_counts: dict[str, list[float]] = {}  # program_id -> list of timestamps
        logger.info("ToSEngine initialized.")

    def register_program(self, scope: ProgramScope) -> None:
        """Register or update a program's scope definition."""
        self._programs[scope.program_id] = scope
        self._request_counts.setdefault(scope.program_id, [])
        logger.info("Program registered: %s (%s)", scope.program_id, scope.platform)

    def check_compliance(
        self,
        program_id: str,
        target: str,
        method: str = "manual",
        is_automated: bool = False,
    ) -> ComplianceCheckResult:
        """
        Check whether a proposed action is compliant with the program's ToS.

        Args:
            program_id: The bug bounty program identifier.
            target: The target asset (domain, URL, IP, etc.).
            method: The testing method being used.
            is_automated: Whether this action is automated (most programs prohibit this).

        Returns:
            ComplianceCheckResult with is_compliant flag and any violations.
        """
        scope = self._programs.get(program_id)
        if scope is None:
            # Unknown program — block everything (safe default)
            return ComplianceCheckResult(
                is_compliant=False,
                violations=[ComplianceViolation(
                    ComplianceViolationType.OUT_OF_SCOPE_ASSET,
                    f"Program '{program_id}' not registered. All actions blocked.",
                    program_id,
                )],
                scope_status=ScopeStatus.UNKNOWN,
                risk_score_contribution=1.0,
            )

        violations: list[ComplianceViolation] = []
        risk_score = 0.0

        # 1. Check scope
        scope_status = self._check_scope(scope, target)
        if scope_status == ScopeStatus.OUT_OF_SCOPE:
            violations.append(ComplianceViolation(
                ComplianceViolationType.OUT_OF_SCOPE_ASSET,
                f"Target '{target}' is explicitly out-of-scope.",
                program_id,
            ))
            risk_score = 1.0  # Maximum risk
        elif scope_status == ScopeStatus.UNKNOWN:
            # Not explicitly listed — treat as high risk
            violations.append(ComplianceViolation(
                ComplianceViolationType.SCOPE_BOUNDARY_PROXIMITY,
                f"Target '{target}' is not explicitly in-scope. Treating as out-of-scope.",
                program_id,
            ))
            risk_score = 0.8

        # 2. Check automation rules
        if is_automated and not scope.allows_automated_scanning:
            violations.append(ComplianceViolation(
                ComplianceViolationType.UNAUTHORIZED_AUTOMATION,
                "This program does not allow automated scanning.",
                program_id,
            ))
            risk_score = max(risk_score, 0.9)

        # 3. Check prohibited methods
        method_lower = method.lower()
        if method_lower in [m.lower() for m in scope.prohibited_methods]:
            violations.append(ComplianceViolation(
                ComplianceViolationType.PROHIBITED_TESTING_METHOD,
                f"Method '{method}' is prohibited by this program.",
                program_id,
            ))
            risk_score = max(risk_score, 0.95)

        # 4. Check rate limits
        if self._is_rate_limited(program_id, scope.max_requests_per_minute):
            violations.append(ComplianceViolation(
                ComplianceViolationType.RATE_LIMIT_EXCEEDED,
                f"Rate limit of {scope.max_requests_per_minute} req/min exceeded.",
                program_id,
            ))
            risk_score = max(risk_score, 0.7)

        # Record this request
        self._request_counts[program_id].append(time.time())

        return ComplianceCheckResult(
            is_compliant=len(violations) == 0,
            violations=violations,
            scope_status=scope_status,
            risk_score_contribution=risk_score,
        )

    def _check_scope(self, scope: ProgramScope, target: str) -> ScopeStatus:
        """Determine if a target is in-scope, out-of-scope, or unknown."""
        target_lower = target.lower().strip()

        # First check out-of-scope (takes priority — safety first)
        for domain in scope.out_of_scope_domains:
            if self._domain_matches(target_lower, domain.lower()):
                return ScopeStatus.OUT_OF_SCOPE

        for pattern in scope.out_of_scope_patterns:
            if re.match(pattern, target_lower):
                return ScopeStatus.OUT_OF_SCOPE

        # Then check in-scope
        for domain in scope.in_scope_domains:
            if self._domain_matches(target_lower, domain.lower()):
                return ScopeStatus.IN_SCOPE

        for pattern in scope.in_scope_patterns:
            if re.match(pattern, target_lower):
                return ScopeStatus.IN_SCOPE

        # Not explicitly listed in either — unknown (treated as dangerous)
        return ScopeStatus.UNKNOWN

    @staticmethod
    def _domain_matches(target: str, scope_domain: str) -> bool:
        """Check if a target matches a scope domain (supports wildcard *.example.com)."""
        if scope_domain.startswith("*."):
            # Wildcard: *.example.com matches sub.example.com, api.example.com, etc.
            base = scope_domain[2:]
            return target == base or target.endswith("." + base)
        return target == scope_domain

    def _is_rate_limited(self, program_id: str, max_rpm: int) -> bool:
        """Check if the rate limit has been exceeded in the last 60 seconds."""
        now = time.time()
        timestamps = self._request_counts.get(program_id, [])
        # Keep only last 60 seconds
        recent = [t for t in timestamps if now - t < 60]
        self._request_counts[program_id] = recent
        return len(recent) >= max_rpm

    def get_program(self, program_id: str) -> ProgramScope | None:
        return self._programs.get(program_id)
