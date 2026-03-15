"""
Bug Bounty Co-Pilot -- Report Linter (Anti-Hallucination Engine)
================================================================
Validates AI-generated vulnerability reports against real evidence.

Key Functions:
  1. Structural validation -- report has all required sections.
  2. PoC cross-reference -- every claim must be backed by a PoC log entry.
  3. Tone/formatting checks -- matches platform-specific standards.
  4. Quality scoring -- score feeds into the Acceptance Intelligence Graph.

This module is the SECONDARY hallucination guard (the HITL gate is primary).
It catches issues BEFORE the human reviewer sees them, reducing cognitive load
and increasing the chance of acceptance.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger(__name__)


class LintSeverity(Enum):
    """Severity of a lint finding."""
    INFO = auto()
    WARNING = auto()
    ERROR = auto()      # Must fix before submission
    CRITICAL = auto()   # Report cannot be submitted


class LintCategory(Enum):
    """Categories of lint findings."""
    STRUCTURE = auto()          # Missing sections
    POC_MISMATCH = auto()       # Claim not backed by PoC
    TONE = auto()               # Unprofessional language
    FORMATTING = auto()         # Platform-specific formatting issues
    HALLUCINATION = auto()      # AI-generated claim with no evidence
    SEVERITY_MISMATCH = auto()  # Claimed severity doesn't match impact
    DUPLICATE_CONTENT = auto()  # Repeated/boilerplate content


REQUIRED_SECTIONS = [
    "title",
    "summary",
    "severity",
    "impact",
    "steps_to_reproduce",
    "proof_of_concept",
    "remediation",
]


@dataclass
class LintFinding:
    """A single lint finding in the report."""
    category: LintCategory
    severity: LintSeverity
    message: str
    section: str = ""
    line_hint: int = 0


@dataclass
class ReportContent:
    """A vulnerability report to be linted."""
    title: str = ""
    summary: str = ""
    severity: str = ""
    impact: str = ""
    steps_to_reproduce: str = ""
    proof_of_concept: str = ""
    remediation: str = ""
    raw_text: str = ""
    poc_logs: list[str] = field(default_factory=list)  # Raw PoC log entries
    target_platform: str = "hackerone"

    @property
    def report_hash(self) -> str:
        """SHA-256 hash of the report content for signing."""
        content = f"{self.title}|{self.summary}|{self.steps_to_reproduce}|{self.proof_of_concept}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @property
    def sections(self) -> dict[str, str]:
        return {
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity,
            "impact": self.impact,
            "steps_to_reproduce": self.steps_to_reproduce,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
        }


@dataclass
class LintResult:
    """The result of linting a report."""
    findings: list[LintFinding] = field(default_factory=list)
    quality_score: float = 0.0  # 0.0 = terrible, 1.0 = perfect
    can_submit: bool = False    # True only if no ERROR/CRITICAL findings
    report_hash: str = ""

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in (LintSeverity.ERROR, LintSeverity.CRITICAL))

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == LintSeverity.WARNING)


class ReportLinter:
    """
    Validates vulnerability reports before HITL Gate 3 (final submission).

    The linter runs BEFORE the human reviewer sees the report, catching
    obvious issues and hallucinations to reduce review burden.

    Usage:
        linter = ReportLinter()
        result = linter.lint(ReportContent(
            title="XSS in /api/search",
            summary="...",
            severity="High",
            steps_to_reproduce="1. Navigate to...",
            proof_of_concept="<script>alert(1)</script>",
            poc_logs=["HTTP/1.1 200 OK ... <script>alert(1)</script>"],
        ))
        if result.can_submit:
            # Proceed to HITL Gate 3
            ...
    """

    # Hallucination indicator patterns
    HALLUCINATION_PATTERNS = [
        r"(?i)as shown (in|by) the (screenshot|image|figure|diagram)",  # No images in text reports
        r"(?i)we (tested|verified|confirmed) (on|in) production",       # Never test in prod
        r"(?i)CVE-\d{4}-\d+",   # AI may hallucinate CVE numbers
        r"(?i)this affects? \d+[,.]?\d* (million|billion) users?",      # Inflated impact
    ]

    # Unprofessional tone patterns
    UNPROFESSIONAL_PATTERNS = [
        r"(?i)\b(lol|lmao|rofl|omg|wtf)\b",
        r"(?i)\b(easy|trivial|obvious|stupid|dumb)\b.*\b(bug|vuln|flaw)\b",
        r"(?i)you guys",
        r"(?i)this is (really|very|super) (bad|terrible|awful)",
    ]

    def __init__(self):
        logger.info("ReportLinter initialized.")

    def lint(self, report: ReportContent) -> LintResult:
        """Run all lint checks on a report."""
        findings: list[LintFinding] = []

        # 1. Structural validation
        findings.extend(self._check_structure(report))

        # 2. PoC cross-reference (anti-hallucination)
        findings.extend(self._check_poc_evidence(report))

        # 3. Hallucination detection
        findings.extend(self._check_hallucination_patterns(report))

        # 4. Tone check
        findings.extend(self._check_tone(report))

        # 5. Severity validation
        findings.extend(self._check_severity(report))

        # Calculate quality score
        quality = self._calculate_quality(findings)

        # Can submit only if no ERROR/CRITICAL findings
        can_submit = not any(
            f.severity in (LintSeverity.ERROR, LintSeverity.CRITICAL)
            for f in findings
        )

        result = LintResult(
            findings=findings,
            quality_score=quality,
            can_submit=can_submit,
            report_hash=report.report_hash,
        )

        logger.info(
            "Lint complete: findings=%d errors=%d quality=%.2f can_submit=%s",
            len(findings), result.error_count, quality, can_submit,
        )
        return result

    def _check_structure(self, report: ReportContent) -> list[LintFinding]:
        """Verify all required sections are present and non-empty."""
        findings = []
        for section_name in REQUIRED_SECTIONS:
            value = report.sections.get(section_name, "")
            if not value or not value.strip():
                findings.append(LintFinding(
                    category=LintCategory.STRUCTURE,
                    severity=LintSeverity.ERROR,
                    message=f"Required section '{section_name}' is missing or empty.",
                    section=section_name,
                ))
            elif len(value.strip()) < 10:
                findings.append(LintFinding(
                    category=LintCategory.STRUCTURE,
                    severity=LintSeverity.WARNING,
                    message=f"Section '{section_name}' is suspiciously short ({len(value.strip())} chars).",
                    section=section_name,
                ))
        return findings

    def _check_poc_evidence(self, report: ReportContent) -> list[LintFinding]:
        """Cross-reference report claims against PoC logs."""
        findings = []

        if not report.poc_logs:
            findings.append(LintFinding(
                category=LintCategory.POC_MISMATCH,
                severity=LintSeverity.CRITICAL,
                message="No PoC logs provided. Report claims CANNOT be verified.",
                section="proof_of_concept",
            ))
            return findings

        # Check that the PoC section references content from actual logs
        poc_text = report.proof_of_concept.lower()
        logs_combined = " ".join(report.poc_logs).lower()

        # Extract key technical terms from PoC section
        technical_terms = re.findall(r'[a-z0-9_.\-/]{4,}', poc_text)
        matched_terms = sum(1 for term in technical_terms if term in logs_combined)

        if technical_terms:
            match_ratio = matched_terms / len(technical_terms)
            if match_ratio < 0.3:
                findings.append(LintFinding(
                    category=LintCategory.HALLUCINATION,
                    severity=LintSeverity.ERROR,
                    message=f"Only {match_ratio:.0%} of PoC claims match actual log evidence. Possible hallucination.",
                    section="proof_of_concept",
                ))
            elif match_ratio < 0.6:
                findings.append(LintFinding(
                    category=LintCategory.POC_MISMATCH,
                    severity=LintSeverity.WARNING,
                    message=f"Only {match_ratio:.0%} evidence match. Review PoC claims carefully.",
                    section="proof_of_concept",
                ))

        return findings

    def _check_hallucination_patterns(self, report: ReportContent) -> list[LintFinding]:
        """Detect common LLM hallucination patterns."""
        findings = []
        full_text = report.raw_text or " ".join(report.sections.values())

        for pattern in self.HALLUCINATION_PATTERNS:
            matches = re.findall(pattern, full_text)
            if matches:
                findings.append(LintFinding(
                    category=LintCategory.HALLUCINATION,
                    severity=LintSeverity.WARNING,
                    message=f"Possible hallucination pattern detected: '{pattern}'",
                ))
        return findings

    def _check_tone(self, report: ReportContent) -> list[LintFinding]:
        """Check for unprofessional language."""
        findings = []
        full_text = report.raw_text or " ".join(report.sections.values())

        for pattern in self.UNPROFESSIONAL_PATTERNS:
            if re.search(pattern, full_text):
                findings.append(LintFinding(
                    category=LintCategory.TONE,
                    severity=LintSeverity.WARNING,
                    message=f"Unprofessional tone detected: '{pattern}'",
                ))
        return findings

    def _check_severity(self, report: ReportContent) -> list[LintFinding]:
        """Basic severity validation."""
        findings = []
        valid_severities = {"none", "low", "medium", "high", "critical"}
        if report.severity.lower().strip() not in valid_severities:
            findings.append(LintFinding(
                category=LintCategory.SEVERITY_MISMATCH,
                severity=LintSeverity.WARNING,
                message=f"Severity '{report.severity}' is non-standard. Use: {', '.join(sorted(valid_severities))}",
                section="severity",
            ))
        return findings

    @staticmethod
    def _calculate_quality(findings: list[LintFinding]) -> float:
        """Calculate a 0.0-1.0 quality score based on findings."""
        if not findings:
            return 1.0

        deductions = {
            LintSeverity.CRITICAL: 0.40,
            LintSeverity.ERROR: 0.20,
            LintSeverity.WARNING: 0.05,
            LintSeverity.INFO: 0.01,
        }

        total_deduction = sum(deductions.get(f.severity, 0) for f in findings)
        return max(0.0, 1.0 - total_deduction)
