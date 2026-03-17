"""
Bug Bounty Co-Pilot -- FastAPI Application
============================================
The main API layer that exposes all modules as REST endpoints.

Key Endpoints:
  POST /api/v1/workflow/start     -- Start a hunting session
  POST /api/v1/workflow/advance   -- Advance workflow (pauses at HITL gates)
  POST /api/v1/workflow/approve   -- Human approval at HITL gate
  POST /api/v1/reports/lint       -- Lint a vulnerability report
  GET  /api/v1/predict/acceptance -- Get acceptance prediction
  GET  /api/v1/predict/dup        -- Get dup prediction
  POST /api/v1/payments/subscribe -- Subscribe to a tier
  GET  /api/v1/dashboard/bph      -- Bounty/Hour dashboard
  GET  /api/v1/health             -- Health check
"""

from __future__ import annotations

import logging
import time
import json
import os
from typing import Any

from src.core.notifier import notifier

from src.core.submission_blocker import SubmissionBlocker
from src.core.workflow_engine import WorkflowEngine, WorkflowStation, WorkflowStatus
from src.compliance.tos_engine import ToSEngine, ProgramScope
from src.compliance.ban_risk_score import BanRiskScorer
from src.ai.llm_router import LLMRouter, TaskComplexity
from src.ai.report_linter import ReportLinter, ReportContent
from src.data.acceptance_graph import AcceptanceGraph, VulnerabilityClass
from src.data.dup_predictor import DupPredictor, VulnerabilityFingerprint
from src.data.bounty_per_hour_tracker import BountyPerHourTracker
from src.revenue.subscription_engine import SubscriptionEngine, SubscriptionTier
from src.revenue.revenue_share import RevenueShareCalculator
from src.revenue.payment_gateway import PaymentGateway

logger = logging.getLogger(__name__)


class CoPilotApp:
    """
    The main application that wires all modules together.

    This is the "controller" that coordinates between:
      - Foundation layer (blocker, workflow, ToS, BRS)
      - AI layer (router, linter, acceptance graph, dup predictor, B/H)
      - Revenue layer (subscriptions, rev share, payments)

    In production, this would be wrapped by FastAPI routes.
    For now, it serves as the integration hub and test target.

    Usage:
        app = CoPilotApp()
        session = app.start_session("hunter_1", "hackerone_prog_1")
        app.advance_workflow(session.session_id)
        app.approve_gate(session.session_id, "APPROVE")
    """

    def __init__(self, monthly_llm_budget: float = 100.0):
        # Foundation Layer
        self.blocker = SubmissionBlocker()
        self.workflow = WorkflowEngine(submission_blocker=self.blocker)
        self.tos_engine = ToSEngine()
        self.ban_scorer = BanRiskScorer()

        # AI Layer
        self.llm_router = LLMRouter(monthly_budget_usd=monthly_llm_budget)
        self.report_linter = ReportLinter()
        self.acceptance_graph = AcceptanceGraph()
        self.dup_predictor = DupPredictor(acceptance_graph=self.acceptance_graph)
        self.bph_tracker = BountyPerHourTracker()

        # Revenue Layer
        self.subscriptions = SubscriptionEngine()
        self.rev_share = RevenueShareCalculator()
        self.payments = PaymentGateway(sandbox=True)

        logger.info("CoPilotApp initialized with all 12 modules.")

    # ================================================================
    # Workflow Operations
    # ================================================================

    def start_session(self, user_id: str, program_id: str) -> dict[str, Any]:
        """Start a new hunting session."""
        session = self.workflow.create_session(user_id=user_id, program_id=program_id)
        bph_session_id = self.bph_tracker.start_session(user_id=user_id, program_id=program_id)

        return {
            "workflow_session_id": session.session_id,
            "bph_session_id": bph_session_id,
            "current_station": session.current_station.name,
            "status": session.status.name,
        }

    def advance_workflow(self, session_id: str) -> dict[str, Any]:
        """Advance the workflow to the next station."""
        session = self.workflow.get_session(session_id)
        if not session:
            return {"error": "Session not found"}

        try:
            self.workflow.advance(session)
            return {
                "current_station": session.current_station.name,
                "status": session.status.name,
                "requires_approval": session.status == WorkflowStatus.PAUSED_AT_GATE,
            }
        except ValueError as e:
            return {"error": str(e), "status": session.status.name}

    def approve_gate(self, session_id: str, approval: str, report_hash: str = "") -> dict[str, Any]:
        """Approve a HITL gate."""
        session = self.workflow.get_session(session_id)
        if not session:
            return {"error": "Session not found"}

        try:
            token = self.workflow.approve_gate(session, approval, report_hash=report_hash)
            return {
                "approved": True,
                "current_station": session.current_station.name,
                "status": session.status.name,
            }
        except ValueError as e:
            return {"error": str(e), "approved": False}

    # ================================================================
    # AI Operations
    # ================================================================

    def lint_report(self, report: ReportContent) -> dict[str, Any]:
        """Lint a vulnerability report."""
        result = self.report_linter.lint(report)
        return {
            "can_submit": result.can_submit,
            "quality_score": result.quality_score,
            "error_count": result.error_count,
            "warning_count": result.warning_count,
            "report_hash": result.report_hash,
            "findings": [
                {
                    "category": f.category.name,
                    "severity": f.severity.name,
                    "message": f.message,
                }
                for f in result.findings
            ],
        }

    def predict_acceptance(
        self,
        platform: str,
        program_id: str,
        vuln_class: str,
        severity: str,
    ) -> dict[str, Any]:
        """Get acceptance prediction for a vulnerability."""
        try:
            vc = VulnerabilityClass(vuln_class)
        except ValueError:
            vc = VulnerabilityClass.OTHER

        prediction = self.acceptance_graph.predict(platform, program_id, vc, severity)
        return {
            "acceptance_probability": prediction.acceptance_probability,
            "dup_probability": prediction.dup_probability,
            "estimated_bounty_usd": prediction.estimated_bounty_usd,
            "confidence": prediction.confidence,
            "similar_submissions": prediction.similar_submissions,
            "recommendation": prediction.recommendation,
        }

    # ================================================================
    # Revenue Operations
    # ================================================================

    def subscribe(self, user_id: str, tier: str, is_annual: bool = False) -> dict[str, Any]:
        """Subscribe a user to a tier."""
        try:
            tier_enum = SubscriptionTier(tier)
        except ValueError:
            return {"error": f"Invalid tier: {tier}"}

        sub = self.subscriptions.create_subscription(user_id, tier_enum, is_annual)

        # Create payment order if not free
        order_info = None
        if tier_enum != SubscriptionTier.FREE:
            config = sub.config
            amount = config.price_inr_annual if is_annual else config.price_inr_monthly
            order = self.payments.create_order(
                user_id=user_id,
                amount_inr=amount * 100,  # Convert to paise
                description=f"{config.display_name} Plan - {'Annual' if is_annual else 'Monthly'}",
            )
            order_info = {
                "order_id": order.order_id,
                "amount_inr": order.amount_rupees,
                "razorpay_order_id": order.razorpay_order_id,
            }

        return {
            "user_id": user_id,
            "tier": sub.config.display_name,
            "reports_remaining": sub.reports_remaining,
            "features": self.subscriptions.get_available_features(sub),
            "payment_order": order_info,
        }

    # ================================================================
    # Dashboard
    # ================================================================

    def get_dashboard(self, user_id: str) -> dict[str, Any]:
        """Get the main dashboard data for a user."""
        perf = self.bph_tracker.get_user_performance(user_id)
        sub = self.subscriptions.get_subscription(user_id)
        payout = self.rev_share.get_user_payout_summary(user_id)

        return {
            "user_id": user_id,
            "subscription": {
                "tier": sub.config.display_name if sub else "None",
                "reports_remaining": sub.reports_remaining if sub else 0,
            } if sub else None,
            "performance": {
                "bounty_per_hour": round(perf.overall_bounty_per_hour, 2) if perf else 0,
                "total_bounty_usd": round(perf.total_bounty_usd, 2) if perf else 0,
                "sessions": perf.total_sessions if perf else 0,
                "acceptance_rate": round(perf.acceptance_rate, 3) if perf else 0,
            },
            "payouts": {
                "total_earned": round(payout.total_bounty_usd, 2),
                "platform_cut": round(payout.total_platform_cut_usd, 2),
                "your_payout": round(payout.total_user_payout_usd, 2),
            },
            "graph_stats": self.acceptance_graph.get_stats(),
        }

    def get_system_status(self) -> dict[str, Any]:
        """Get the current hunting engine status."""
        root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
        status_file = os.path.join(root_path, "worker_status.json")
        
        worker_data = {"phase": "UNKNOWN", "message": "Worker status not available"}
        if os.path.exists(status_file):
            try:
                with open(status_file, "r") as f:
                    worker_data = json.load(f)
            except Exception:
                pass
        
        smtp_ok, smtp_msg = notifier.verify_smtp()
        tg_ok, tg_msg = notifier.verify_telegram()
        
        return {
            "worker": worker_data,
            "notifications": {
                "smtp_configured": notifier.enabled,
                "smtp_healthy": smtp_ok,
                "last_smtp_message": smtp_msg,
                "telegram_configured": notifier.telegram_enabled,
                "telegram_healthy": tg_ok,
                "last_telegram_message": tg_msg
            },
            "timestamp": time.time()
        }

    def test_email(self) -> dict[str, Any]:
        """Trigger a test email."""
        ok, msg = notifier.send_alert("System Test", "This is a diagnostic email from your Bug Bounty Co-Pilot.")
        return {"success": ok, "message": msg}

    def test_telegram(self) -> dict[str, Any]:
        """Trigger a test telegram message."""
        ok, msg = notifier.send_telegram("System Test: This is a diagnostic message from your Bug Bounty Co-Pilot.")
        return {"success": ok, "message": msg}

    def get_health(self) -> dict[str, Any]:
        """Health check endpoint."""
        smtp_ok, _ = notifier.verify_smtp()
        tg_ok, _ = notifier.verify_telegram()
        return {
            "status": "healthy",
            "modules": {
                "submission_blocker": True,
                "workflow_engine": True,
                "tos_engine": True,
                "ban_risk_scorer": True,
                "llm_router": True,
                "report_linter": True,
                "acceptance_graph": True,
                "dup_predictor": True,
                "bounty_hour_tracker": True,
                "subscription_engine": True,
                "revenue_share": True,
                "payment_gateway": True,
                "notification_hub": smtp_ok,
                "telegram_alert": tg_ok
            },
            "payment_sandbox": self.payments.is_sandbox,
            "timestamp": time.time(),
        }
