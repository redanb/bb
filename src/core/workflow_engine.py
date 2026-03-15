"""
Bug Bounty Co-Pilot — 9-Station Workflow Engine
=================================================
Implements the State Machine for the Hunter Workflow (v2 Gold Standard).

The 9 Stations:
  1. Program Selection — AI recommends high-bounty programs based on user skill profile.
  2. Reconnaissance — Automated subdomain/asset discovery (Subfinder, Amass, httpx).
  3. Target Analysis — AI analyzes attack surface, prioritizes targets by Bounty/Hour potential.
  4. [HITL GATE 1] Target/Hypothesis Approval — Hunter MUST approve before any testing.
  5. Vulnerability Discovery — AI-guided testing based on approved hypotheses.
  6. [HITL GATE 2] Exploit/PoC Validation — Hunter MUST validate findings before report.
  7. Report Generation — AI drafts platform-specific report (checked by Report Linter).
  8. [HITL GATE 3] Final Report Submission — Hunter cryptographically signs and submits.
  9. Feedback Loop — Outcome (accepted/rejected/dup) feeds the Acceptance Intelligence Graph.

Key Design Principles:
  - The workflow CANNOT skip or bypass any HITL gate.
  - Each station emits events tracked by the Data Moat (Acceptance Graph, Bounty/Hour).
  - Compliance checks (BRS) run at EVERY station transition.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable

from src.core.submission_blocker import ApprovalToken, GateID, SubmissionBlocker, SubmissionBlockedError

logger = logging.getLogger(__name__)


class WorkflowStation(Enum):
    """The 9 stations of the hunter workflow."""
    PROGRAM_SELECTION = 1
    RECONNAISSANCE = 2
    TARGET_ANALYSIS = 3
    HITL_GATE_TARGET_APPROVAL = 4          # Gate 1
    VULNERABILITY_DISCOVERY = 5
    HITL_GATE_EXPLOIT_VALIDATION = 6       # Gate 2
    REPORT_GENERATION = 7
    HITL_GATE_REPORT_SUBMISSION = 8        # Gate 3
    FEEDBACK_LOOP = 9


class WorkflowStatus(Enum):
    """Status of a workflow session."""
    ACTIVE = auto()
    PAUSED_AT_GATE = auto()
    COMPLETED = auto()
    ABORTED = auto()


# Map each HITL gate station to its corresponding GateID for token signing
GATE_STATION_MAP: dict[WorkflowStation, GateID] = {
    WorkflowStation.HITL_GATE_TARGET_APPROVAL: GateID.TARGET_HYPOTHESIS_APPROVAL,
    WorkflowStation.HITL_GATE_EXPLOIT_VALIDATION: GateID.EXPLOIT_POC_VALIDATION,
    WorkflowStation.HITL_GATE_REPORT_SUBMISSION: GateID.FINAL_REPORT_SUBMISSION,
}

# Stations that are HITL gates — workflow PAUSES here until human approves
HITL_GATE_STATIONS: set[WorkflowStation] = set(GATE_STATION_MAP.keys())


@dataclass
class WorkflowEvent:
    """An event emitted when a station transition occurs."""
    session_id: str
    from_station: WorkflowStation | None
    to_station: WorkflowStation
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowSession:
    """A single workflow session for one vulnerability hunt."""
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    user_id: str = ""
    program_id: str = ""
    current_station: WorkflowStation = WorkflowStation.PROGRAM_SELECTION
    status: WorkflowStatus = WorkflowStatus.ACTIVE
    events: list[WorkflowEvent] = field(default_factory=list)
    report_hash: str = ""
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    bounty_amount: float | None = None

    @property
    def is_at_hitl_gate(self) -> bool:
        return self.current_station in HITL_GATE_STATIONS

    @property
    def elapsed_hours(self) -> float:
        end = self.completed_at or time.time()
        return (end - self.started_at) / 3600

    @property
    def bounty_per_hour(self) -> float | None:
        """North Star KPI (v2 Gold Standard)."""
        if self.bounty_amount is not None and self.elapsed_hours > 0:
            return self.bounty_amount / self.elapsed_hours
        return None


class WorkflowEngine:
    """
    The 9-Station State Machine controlling the hunter workflow.

    Key Properties:
      - Enforces strict station ordering — no skipping allowed.
      - Pauses at HITL gates until human provides a valid ApprovalToken.
      - Runs compliance checks (via callback) at every transition.
      - Emits events consumed by the Data Moat subsystem.

    Usage:
        blocker = SubmissionBlocker()
        engine = WorkflowEngine(submission_blocker=blocker)
        session = engine.create_session(user_id="hunter_1", program_id="hackerone_prog_1")
        engine.advance(session)  # Advances to next station
        # ... at HITL gate, engine.approve_gate(session, "APPROVE")
    """

    def __init__(
        self,
        submission_blocker: SubmissionBlocker,
        compliance_check: Callable[[WorkflowSession, WorkflowStation], bool] | None = None,
        event_listeners: list[Callable[[WorkflowEvent], None]] | None = None,
    ):
        self._blocker = submission_blocker
        self._compliance_check = compliance_check
        self._event_listeners = event_listeners or []
        self._sessions: dict[str, WorkflowSession] = {}
        logger.info("WorkflowEngine initialized with %d event listeners.", len(self._event_listeners))

    def create_session(self, user_id: str, program_id: str) -> WorkflowSession:
        """Create a new workflow session."""
        session = WorkflowSession(user_id=user_id, program_id=program_id)
        self._sessions[session.session_id] = session
        self._emit_event(WorkflowEvent(
            session_id=session.session_id,
            from_station=None,
            to_station=session.current_station,
            metadata={"action": "session_created", "program_id": program_id},
        ))
        logger.info("Session created: %s for user=%s program=%s", session.session_id, user_id, program_id)
        return session

    def advance(self, session: WorkflowSession) -> WorkflowStation:
        """
        Advance the workflow to the next station.

        At HITL gates, the workflow PAUSES and requires approve_gate() to proceed.

        Raises:
            SubmissionBlockedError: If attempting to advance past a gate without approval.
            ValueError: If session is not in ACTIVE state.
        """
        if session.status not in (WorkflowStatus.ACTIVE,):
            raise ValueError(f"Cannot advance session in {session.status.name} state.")

        # Get the ordered list of stations
        stations = list(WorkflowStation)
        current_idx = stations.index(session.current_station)

        if current_idx >= len(stations) - 1:
            # At the last station — complete the session
            session.status = WorkflowStatus.COMPLETED
            session.completed_at = time.time()
            logger.info("Session %s COMPLETED. Bounty/Hour: %s", session.session_id, session.bounty_per_hour)
            return session.current_station

        next_station = stations[current_idx + 1]

        # If current station is a HITL gate, block advancement
        if session.is_at_hitl_gate and session.status != WorkflowStatus.ACTIVE:
            raise SubmissionBlockedError(
                f"Cannot advance past HITL gate {session.current_station.name} without approval.",
                GATE_STATION_MAP.get(session.current_station),
            )

        # Run compliance check before transition
        if self._compliance_check:
            is_compliant = self._compliance_check(session, next_station)
            if not is_compliant:
                session.status = WorkflowStatus.ABORTED
                logger.warning(
                    "Session %s ABORTED: compliance check failed at transition %s -> %s",
                    session.session_id, session.current_station.name, next_station.name,
                )
                raise SubmissionBlockedError(
                    f"Compliance check failed for transition to {next_station.name}",
                )

        # Perform transition
        from_station = session.current_station
        session.current_station = next_station

        # If we've arrived at a HITL gate, pause
        if session.is_at_hitl_gate:
            session.status = WorkflowStatus.PAUSED_AT_GATE
            logger.info(
                "Session %s PAUSED at HITL gate: %s",
                session.session_id, session.current_station.name,
            )

        # Emit transition event
        self._emit_event(WorkflowEvent(
            session_id=session.session_id,
            from_station=from_station,
            to_station=next_station,
            metadata={"action": "station_transition"},
        ))

        return session.current_station

    def approve_gate(
        self,
        session: WorkflowSession,
        approval_input: str,
        report_hash: str = "",
    ) -> ApprovalToken:
        """
        Approve a HITL gate. The human must type "APPROVE" to proceed.

        This creates a cryptographically signed ApprovalToken via the SubmissionBlocker,
        then advances the workflow past the gate.

        Args:
            session: The workflow session paused at a gate.
            approval_input: Must be exactly "APPROVE" (case-sensitive).
            report_hash: Hash of the report content (required for Gate 3).

        Raises:
            ValueError: If not at a HITL gate or input is not "APPROVE".
        """
        if session.status != WorkflowStatus.PAUSED_AT_GATE:
            raise ValueError("Session is not paused at a HITL gate.")

        if not session.is_at_hitl_gate:
            raise ValueError(f"Station {session.current_station.name} is not a HITL gate.")

        if approval_input != "APPROVE":
            raise ValueError(
                f"Invalid approval input: '{approval_input}'. "
                "You must type exactly 'APPROVE' to proceed."
            )

        gate_id = GATE_STATION_MAP[session.current_station]

        # For Gate 3 (final submission), require report_hash
        if gate_id == GateID.FINAL_REPORT_SUBMISSION and not report_hash:
            raise ValueError("Report hash is required for final submission approval.")

        hash_to_use = report_hash or session.session_id

        # Create cryptographically signed approval token
        token = self._blocker.create_approval_token(
            user_id=session.user_id,
            report_hash=hash_to_use,
            gate_id=gate_id,
        )

        # Validate the token (this also records it in the audit trail)
        self._blocker.validate_and_permit(token)

        # Resume the workflow
        session.status = WorkflowStatus.ACTIVE
        session.report_hash = hash_to_use

        logger.info(
            "Gate %s APPROVED for session %s by user %s",
            gate_id.name, session.session_id, session.user_id,
        )

        self._emit_event(WorkflowEvent(
            session_id=session.session_id,
            from_station=session.current_station,
            to_station=session.current_station,
            metadata={"action": "gate_approved", "gate_id": gate_id.name},
        ))

        return token

    def _emit_event(self, event: WorkflowEvent) -> None:
        """Emit an event to all registered listeners (Data Moat, analytics, etc.)."""
        for listener in self._event_listeners:
            try:
                listener(event)
            except Exception:
                logger.exception("Event listener failed for event: %s", event)

    def get_session(self, session_id: str) -> WorkflowSession | None:
        return self._sessions.get(session_id)
