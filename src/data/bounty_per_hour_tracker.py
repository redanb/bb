"""
Bug Bounty Co-Pilot -- Bounty/Hour Tracker (North Star KPI)
============================================================
Tracks and reports the Bounty per Hour metric for every user session.

This is THE single metric that drives all product decisions (v2 Gold Standard).
Every feature must ultimately improve Bounty/Hour for the hunter.

The tracker also powers:
  - Income Guarantee system (v4.0): triggers alerts when a user's B/H drops
  - Training upsells: identifies skill gaps based on B/H per vuln class
  - Tier upgrades: suggests tier changes when B/H justifies the investment
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class HuntingSession:
    """A single hunting session with timing and bounty data."""
    session_id: str
    user_id: str
    program_id: str
    started_at: float = field(default_factory=time.time)
    ended_at: float | None = None
    bounty_earned_usd: float = 0.0
    submissions_made: int = 0
    submissions_accepted: int = 0
    vulnerability_classes: list[str] = field(default_factory=list)

    @property
    def duration_hours(self) -> float:
        end = self.ended_at or time.time()
        return max((end - self.started_at) / 3600, 0.001)  # Avoid div/0

    @property
    def bounty_per_hour(self) -> float:
        return self.bounty_earned_usd / self.duration_hours

    @property
    def is_active(self) -> bool:
        return self.ended_at is None


@dataclass
class UserPerformance:
    """Aggregated performance metrics for a user."""
    user_id: str
    total_sessions: int = 0
    total_hours: float = 0.0
    total_bounty_usd: float = 0.0
    total_submissions: int = 0
    total_accepted: int = 0
    sessions: list[HuntingSession] = field(default_factory=list)

    @property
    def overall_bounty_per_hour(self) -> float:
        return self.total_bounty_usd / max(self.total_hours, 0.001)

    @property
    def acceptance_rate(self) -> float:
        return self.total_accepted / max(self.total_submissions, 1)

    @property
    def avg_bounty_per_session(self) -> float:
        return self.total_bounty_usd / max(self.total_sessions, 1)


class BountyPerHourTracker:
    """
    Tracks Bounty/Hour across all users and sessions.

    Key Capabilities:
      - Real-time session tracking with start/end markers
      - Per-user performance aggregation
      - Income Guarantee monitoring (v4.0)
      - Skill gap identification by vulnerability class
      - Leaderboard generation for social proof (psychological pricing)

    Usage:
        tracker = BountyPerHourTracker(income_guarantee_threshold=16.67)
        session_id = tracker.start_session(user_id="hunter_1", program_id="prog_1")
        tracker.record_bounty(session_id, 500.0, vuln_class="xss_stored")
        tracker.end_session(session_id)
        performance = tracker.get_user_performance("hunter_1")
    """

    def __init__(self, income_guarantee_threshold: float = 16.67):
        """
        Args:
            income_guarantee_threshold: Minimum B/H in USD to meet the Income
                Guarantee. Default $16.67/hr = $50K/year at 60 hr/week = approx
                INR 50K/90 days per v4.0 Income Guarantee.
        """
        self._sessions: dict[str, HuntingSession] = {}
        self._user_data: dict[str, UserPerformance] = {}
        self._guarantee_threshold = income_guarantee_threshold
        self._guarantee_alerts: list[dict[str, Any]] = []
        logger.info(
            "BountyPerHourTracker initialized. Income guarantee threshold: $%.2f/hr",
            income_guarantee_threshold,
        )

    def start_session(self, user_id: str, program_id: str, session_id: str = "") -> str:
        """Start a new hunting session."""
        import uuid
        sid = session_id or uuid.uuid4().hex
        session = HuntingSession(
            session_id=sid,
            user_id=user_id,
            program_id=program_id,
        )
        self._sessions[sid] = session

        # Ensure user performance record exists
        if user_id not in self._user_data:
            self._user_data[user_id] = UserPerformance(user_id=user_id)

        logger.info("Session started: %s for user=%s program=%s", sid, user_id, program_id)
        return sid

    def record_bounty(
        self,
        session_id: str,
        amount_usd: float,
        vuln_class: str = "",
        accepted: bool = True,
    ) -> None:
        """Record a bounty earned in a session."""
        session = self._sessions.get(session_id)
        if not session:
            logger.warning("Session %s not found.", session_id)
            return

        session.bounty_earned_usd += amount_usd
        session.submissions_made += 1
        if accepted:
            session.submissions_accepted += 1
        if vuln_class:
            session.vulnerability_classes.append(vuln_class)

        logger.info(
            "Bounty recorded: session=%s amount=$%.2f B/H=$%.2f",
            session_id, amount_usd, session.bounty_per_hour,
        )

    def end_session(self, session_id: str) -> HuntingSession | None:
        """End a hunting session and update user performance."""
        session = self._sessions.get(session_id)
        if not session:
            return None

        session.ended_at = time.time()

        # Update user performance
        user = self._user_data.get(session.user_id)
        if user:
            user.total_sessions += 1
            user.total_hours += session.duration_hours
            user.total_bounty_usd += session.bounty_earned_usd
            user.total_submissions += session.submissions_made
            user.total_accepted += session.submissions_accepted
            user.sessions.append(session)

            # Income Guarantee check
            self._check_income_guarantee(user, session)

        logger.info(
            "Session ended: %s B/H=$%.2f duration=%.1fh bounty=$%.2f",
            session_id, session.bounty_per_hour,
            session.duration_hours, session.bounty_earned_usd,
        )

        return session

    def _check_income_guarantee(self, user: UserPerformance, session: HuntingSession) -> None:
        """
        Income Guarantee System (v4.0):
        If a user's rolling B/H drops below threshold, trigger an alert
        with recommendations (training, target changes, etc.)
        """
        # Use rolling average of last 5 sessions
        recent = user.sessions[-5:]
        if len(recent) < 3:
            return  # Need minimum data

        recent_bph = sum(s.bounty_per_hour for s in recent) / len(recent)

        if recent_bph < self._guarantee_threshold:
            alert = {
                "user_id": user.user_id,
                "timestamp": time.time(),
                "rolling_bph": recent_bph,
                "threshold": self._guarantee_threshold,
                "sessions_analyzed": len(recent),
                "recommendation": self._generate_improvement_recommendation(user, recent),
            }
            self._guarantee_alerts.append(alert)
            logger.warning(
                "INCOME GUARANTEE ALERT: user=%s rolling_B/H=$%.2f (threshold=$%.2f)",
                user.user_id, recent_bph, self._guarantee_threshold,
            )

    def _generate_improvement_recommendation(
        self,
        user: UserPerformance,
        recent_sessions: list[HuntingSession],
    ) -> str:
        """Generate personalized improvement recommendations."""
        recs = []

        # Check acceptance rate
        recent_accepted = sum(s.submissions_accepted for s in recent_sessions)
        recent_submitted = sum(s.submissions_made for s in recent_sessions)
        if recent_submitted > 0:
            rate = recent_accepted / recent_submitted
            if rate < 0.5:
                recs.append("Low acceptance rate. Consider using the Report Linter more actively.")

        # Check session duration
        avg_duration = sum(s.duration_hours for s in recent_sessions) / len(recent_sessions)
        if avg_duration < 1.0:
            recs.append("Sessions too short. Deeper research typically yields higher bounties.")
        elif avg_duration > 8.0:
            recs.append("Very long sessions may indicate diminishing returns. Try fresh targets.")

        if not recs:
            recs.append("Consider exploring higher-value programs or new vulnerability classes.")

        return " | ".join(recs)

    def get_user_performance(self, user_id: str) -> UserPerformance | None:
        return self._user_data.get(user_id)

    def get_leaderboard(self, top_n: int = 10) -> list[dict[str, Any]]:
        """Generate leaderboard for social proof (psychological pricing)."""
        users = sorted(
            self._user_data.values(),
            key=lambda u: u.overall_bounty_per_hour,
            reverse=True,
        )
        return [
            {
                "rank": i + 1,
                "user_id": u.user_id,
                "bounty_per_hour": round(u.overall_bounty_per_hour, 2),
                "total_bounty": round(u.total_bounty_usd, 2),
                "acceptance_rate": round(u.acceptance_rate, 3),
                "sessions": u.total_sessions,
            }
            for i, u in enumerate(users[:top_n])
        ]

    @property
    def guarantee_alerts(self) -> list[dict[str, Any]]:
        return list(self._guarantee_alerts)
