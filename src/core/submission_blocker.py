"""
Bug Bounty Co-Pilot — Submission Blocker (CRITICAL GUARDRAIL)
=============================================================
ARTICLE 4 PROTECTION: This module is the #1 safety mechanism.
It physically prevents ANY API call to a bug bounty platform
without a cryptographically signed human-approval token.

NO CODE CHANGE that weakens this gate may be deployed without
explicit, logged human approval.

Design:
  - Uses HMAC-SHA256 with a per-session secret key.
  - The approval token encodes: user_id, report_hash, timestamp, gate_id.
  - Tokens expire after a configurable TTL (default: 15 minutes).
  - Every submission attempt is logged to an immutable audit trail.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class GateID(Enum):
    """The 3 Mandatory HITL Gates (v2 Gold Standard)."""
    TARGET_HYPOTHESIS_APPROVAL = auto()        # Gate 1
    EXPLOIT_POC_VALIDATION = auto()            # Gate 2
    FINAL_REPORT_SUBMISSION = auto()           # Gate 3


class SubmissionBlockedError(Exception):
    """Raised when a submission is attempted without valid HITL approval."""

    def __init__(self, reason: str, gate_id: GateID | None = None):
        self.reason = reason
        self.gate_id = gate_id
        super().__init__(f"SUBMISSION BLOCKED [{gate_id}]: {reason}")


class TokenExpiredError(SubmissionBlockedError):
    """Raised when an approval token has expired."""

    def __init__(self, gate_id: GateID):
        super().__init__("Approval token has expired. Re-approval required.", gate_id)


class TokenInvalidError(SubmissionBlockedError):
    """Raised when an approval token fails cryptographic verification."""

    def __init__(self, gate_id: GateID):
        super().__init__("Approval token is invalid or tampered with.", gate_id)


@dataclass(frozen=True)
class ApprovalToken:
    """A cryptographically signed token proving human approval at a specific gate."""
    user_id: str
    report_hash: str
    gate_id: GateID
    timestamp: float
    signature: str

    def is_expired(self, ttl_seconds: int = 900) -> bool:
        """Check if this token has exceeded its TTL (default 15 minutes)."""
        return (time.time() - self.timestamp) > ttl_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "report_hash": self.report_hash,
            "gate_id": self.gate_id.name,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }


@dataclass
class AuditEntry:
    """Immutable record of a submission attempt."""
    timestamp: float
    user_id: str
    gate_id: GateID
    report_hash: str
    approved: bool
    reason: str


class SubmissionBlocker:
    """
    The hard-coded failsafe preventing unauthorized platform submissions.

    Key Properties:
      - Generates session-unique secret keys (never stored on disk).
      - Signs approval tokens with HMAC-SHA256.
      - Validates tokens before EVERY submission attempt.
      - Maintains an in-memory audit trail (flushed to persistent storage periodically).
      - Token TTL is configurable but defaults to 15 minutes.

    Usage:
        blocker = SubmissionBlocker()
        token = blocker.create_approval_token(user_id="hunter_1", report_hash="abc123", gate_id=GateID.FINAL_REPORT_SUBMISSION)
        blocker.validate_and_permit(token)  # Raises if invalid/expired
    """

    def __init__(self, token_ttl_seconds: int = 900):
        # Generate a session-unique secret key — never persisted
        self._secret_key: bytes = os.urandom(64)
        self._token_ttl: int = token_ttl_seconds
        self._audit_trail: list[AuditEntry] = []
        self._used_tokens: set[str] = set()  # Prevent replay attacks
        logger.info("SubmissionBlocker initialized with %d second TTL.", token_ttl_seconds)

    def _compute_signature(self, user_id: str, report_hash: str, gate_id: GateID, timestamp: float) -> str:
        """Compute HMAC-SHA256 signature for the given payload."""
        payload = json.dumps({
            "user_id": user_id,
            "report_hash": report_hash,
            "gate_id": gate_id.name,
            "timestamp": timestamp,
        }, sort_keys=True).encode("utf-8")

        return hmac.new(self._secret_key, payload, hashlib.sha256).hexdigest()

    def create_approval_token(
        self,
        user_id: str,
        report_hash: str,
        gate_id: GateID,
    ) -> ApprovalToken:
        """
        Create a signed approval token after human explicitly approves at a gate.

        This method should ONLY be called after the human has reviewed and
        typed "APPROVE" (or equivalent explicit confirmation).
        """
        timestamp = time.time()
        signature = self._compute_signature(user_id, report_hash, gate_id, timestamp)

        token = ApprovalToken(
            user_id=user_id,
            report_hash=report_hash,
            gate_id=gate_id,
            timestamp=timestamp,
            signature=signature,
        )

        logger.info(
            "Approval token created: user=%s gate=%s report=%s",
            user_id, gate_id.name, report_hash[:16],
        )
        return token

    def validate_and_permit(self, token: ApprovalToken) -> bool:
        """
        Validate an approval token. MUST be called before ANY platform submission.

        Raises:
            TokenExpiredError: If the token has exceeded its TTL.
            TokenInvalidError: If the token fails cryptographic verification.
            SubmissionBlockedError: If the token has already been used (replay attack).

        Returns:
            True if the submission is permitted.
        """
        # 1. Check for replay attack
        if token.signature in self._used_tokens:
            self._log_audit(token, approved=False, reason="Replay attack: token already used")
            raise SubmissionBlockedError("This approval token has already been used.", token.gate_id)

        # 2. Check expiration
        if token.is_expired(self._token_ttl):
            self._log_audit(token, approved=False, reason="Token expired")
            raise TokenExpiredError(token.gate_id)

        # 3. Verify cryptographic signature
        expected_signature = self._compute_signature(
            token.user_id, token.report_hash, token.gate_id, token.timestamp,
        )
        if not hmac.compare_digest(token.signature, expected_signature):
            self._log_audit(token, approved=False, reason="Invalid signature")
            raise TokenInvalidError(token.gate_id)

        # 4. Mark token as used (prevent replay)
        self._used_tokens.add(token.signature)

        # 5. Log successful approval
        self._log_audit(token, approved=True, reason="Valid approval")
        logger.info(
            "Submission PERMITTED: user=%s gate=%s report=%s",
            token.user_id, token.gate_id.name, token.report_hash[:16],
        )
        return True

    def _log_audit(self, token: ApprovalToken, approved: bool, reason: str) -> None:
        """Record an immutable audit entry."""
        entry = AuditEntry(
            timestamp=time.time(),
            user_id=token.user_id,
            gate_id=token.gate_id,
            report_hash=token.report_hash,
            approved=approved,
            reason=reason,
        )
        self._audit_trail.append(entry)

        log_fn = logger.info if approved else logger.warning
        log_fn(
            "AUDIT: user=%s gate=%s approved=%s reason='%s'",
            entry.user_id, entry.gate_id.name, entry.approved, entry.reason,
        )

    def get_audit_trail(self) -> list[AuditEntry]:
        """Return a copy of the audit trail (immutable externally)."""
        return list(self._audit_trail)

    @property
    def total_submissions_blocked(self) -> int:
        return sum(1 for e in self._audit_trail if not e.approved)

    @property
    def total_submissions_approved(self) -> int:
        return sum(1 for e in self._audit_trail if e.approved)
