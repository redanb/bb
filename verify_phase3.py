"""
verify_phase3.py -- Phase 3 Revenue & Integration TDD Gate
============================================================
Tests for: Subscription Engine, Revenue Share, Payment Gateway,
           CoPilotApp (full-stack integration)

Exit code 0 = PASS. Exit code 1 = FAIL (max 3 retries per Article 3).
"""

import sys
import time
import traceback


# ============================================================
# Test 10: Subscription Engine
# ============================================================
def test_subscription_engine():
    """Verify tier management, feature gating, and pricing psychology."""
    from src.revenue.subscription_engine import (
        SubscriptionEngine, SubscriptionTier, TIER_CONFIGS,
    )

    engine = SubscriptionEngine()

    # Test 10a: Free tier creation
    free_sub = engine.create_subscription("user_1", SubscriptionTier.FREE)
    assert free_sub.is_active is True
    assert free_sub.reports_remaining == 3
    assert free_sub.config.revenue_share_pct == 20.0
    print("  [PASS] Test 10a: Free tier creation")

    # Test 10b: Pro tier with feature gating
    pro_sub = engine.create_subscription("user_2", SubscriptionTier.PRO)
    features = engine.get_available_features(pro_sub)
    assert features["acceptance_graph"] is True
    assert features["income_guarantee"] is True
    assert features["custom_models"] is False  # Only in Elite
    print("  [PASS] Test 10b: Pro tier feature gating")

    # Test 10c: Report credit consumption
    assert engine.use_report(free_sub) is True
    assert free_sub.reports_remaining == 2
    engine.use_report(free_sub)
    engine.use_report(free_sub)
    assert free_sub.reports_remaining == 0
    assert engine.use_report(free_sub) is False  # Exhausted
    print("  [PASS] Test 10c: Report credit consumption and limits")

    # Test 10d: Pricing display with anchoring (Elite first)
    pricing = engine.get_pricing_display()
    assert pricing[0]["tier"] == "Elite"  # First = anchor
    assert any(p["is_popular"] for p in pricing)  # Pro has badge
    print("  [PASS] Test 10d: Pricing display with psychological anchoring")

    # Test 10e: Upgrade value calculator
    upgrade = engine.calculate_upgrade_value("user_1")
    assert "recommended_tier" in upgrade
    assert len(upgrade.get("new_features", [])) > 0
    print("  [PASS] Test 10e: Upgrade value calculator for upsells")

    # Test 10f: v4.0 tier pricing verification
    assert TIER_CONFIGS[SubscriptionTier.GROWTH].price_inr_monthly == 499
    assert TIER_CONFIGS[SubscriptionTier.PRO].price_inr_monthly == 1999
    assert TIER_CONFIGS[SubscriptionTier.ELITE].price_inr_monthly == 4999
    print("  [PASS] Test 10f: v4.0 psychological pricing verified")

    return True


# ============================================================
# Test 11: Revenue Share Calculator
# ============================================================
def test_revenue_share():
    """Verify revenue share calculations across tiers."""
    from src.revenue.subscription_engine import SubscriptionTier
    from src.revenue.revenue_share import RevenueShareCalculator

    calc = RevenueShareCalculator()

    # Test 11a: Pro tier revenue share (10%)
    tx_pro = calc.process_bounty(
        user_id="hunter_1",
        bounty_usd=500.0,
        user_tier=SubscriptionTier.PRO,
        program_id="prog_1",
        platform="hackerone",
    )
    assert tx_pro.platform_cut_usd == 50.0   # 10% of $500
    assert tx_pro.user_payout_usd == 450.0
    print("  [PASS] Test 11a: Pro tier rev share (10%)")

    # Test 11b: Free tier revenue share (20%)
    tx_free = calc.process_bounty(
        user_id="hunter_2",
        bounty_usd=200.0,
        user_tier=SubscriptionTier.FREE,
    )
    assert tx_free.platform_cut_usd == 40.0   # 20% of $200
    assert tx_free.user_payout_usd == 160.0
    print("  [PASS] Test 11b: Free tier rev share (20%)")

    # Test 11c: Platform revenue tracking
    report = calc.get_platform_revenue_report()
    assert report["total_platform_revenue_usd"] == 90.0  # $50 + $40
    assert report["total_transactions"] == 2
    print("  [PASS] Test 11c: Platform revenue tracking")

    # Test 11d: User payout summary
    payout = calc.get_user_payout_summary("hunter_1")
    assert payout.total_bounty_usd == 500.0
    assert payout.total_platform_cut_usd == 50.0
    print("  [PASS] Test 11d: User payout summary")

    # Test 11e: INR conversion
    assert tx_pro.platform_cut_inr > 0
    print("  [PASS] Test 11e: INR conversion")

    return True


# ============================================================
# Test 12: Payment Gateway
# ============================================================
def test_payment_gateway():
    """Verify Razorpay/UPI payment integration in sandbox mode."""
    from src.revenue.payment_gateway import (
        PaymentGateway, PaymentStatus, PayoutStatus,
    )

    # Test 12a: Sandbox mode default
    gw = PaymentGateway()
    assert gw.is_sandbox is True
    print("  [PASS] Test 12a: Sandbox mode by default")

    # Test 12b: Order creation
    order = gw.create_order(
        user_id="hunter_1",
        amount_inr=199900,  # INR 1999 in paise
        description="Pro Plan - Monthly",
    )
    assert order.amount_rupees == 1999.0
    assert order.status == PaymentStatus.CREATED
    assert "sandbox" in order.razorpay_order_id
    print("  [PASS] Test 12b: Order creation")

    # Test 12c: Payment verification (sandbox)
    verified = gw.verify_payment(order.order_id, "pay_test_123", "sig_test_123")
    assert verified is True
    assert order.status == PaymentStatus.CAPTURED
    print("  [PASS] Test 12c: Payment verification (sandbox)")

    # Test 12d: UPI payout
    payout = gw.create_payout(
        user_id="hunter_1",
        amount_inr=45000,  # INR 450
        upi_id="hunter@upi",
    )
    assert payout.mode == "UPI"
    assert payout.status == PayoutStatus.PROCESSED  # Sandbox auto-processes
    print("  [PASS] Test 12d: UPI payout")

    # Test 12e: Financial summary
    summary = gw.get_financial_summary()
    assert summary["total_collected_inr"] == 1999.0
    assert summary["successful_payments"] == 1
    print("  [PASS] Test 12e: Financial summary")

    return True


# ============================================================
# Test 13: Full-Stack Integration (CoPilotApp)
# ============================================================
def test_copilot_app():
    """Verify the full integration of all 12 modules."""
    from src.api.app import CoPilotApp

    app = CoPilotApp(monthly_llm_budget=50.0)

    # Test 13a: Health check -- all 12 modules loaded
    health = app.get_health()
    assert health["status"] == "healthy"
    assert all(health["modules"].values())
    assert len(health["modules"]) == 12
    print("  [PASS] Test 13a: Health check (12/12 modules loaded)")

    # Test 13b: Subscription -> Session -> Workflow flow
    sub_result = app.subscribe("test_user", "pro")
    assert sub_result["tier"] == "Pro"
    assert sub_result["features"]["acceptance_graph"] is True
    print("  [PASS] Test 13b: Subscription creation via app")

    session = app.start_session("test_user", "test_program")
    assert session["status"] == "ACTIVE"
    print("  [PASS] Test 13c: Session start via app")

    # Advance to first HITL gate
    for _ in range(3):
        result = app.advance_workflow(session["workflow_session_id"])
    assert result["requires_approval"] is True
    print("  [PASS] Test 13d: Workflow advances to HITL gate")

    # Approve gate
    approval = app.approve_gate(session["workflow_session_id"], "APPROVE")
    assert approval["approved"] is True
    print("  [PASS] Test 13e: HITL gate approval via app")

    # Test 13f: Report linting via app
    from src.ai.report_linter import ReportContent
    lint_result = app.lint_report(ReportContent(
        title="SQL Injection in /api/login",
        summary="SQLi found in the login endpoint username parameter.",
        severity="Critical",
        impact="Full database read/write access.",
        steps_to_reproduce="1. Go to /api/login\n2. Enter ' OR 1=1-- in username",
        proof_of_concept="Payload ' OR 1=1-- bypasses authentication via /api/login",
        remediation="Use parameterized queries.",
        poc_logs=["HTTP 200: /api/login accepted ' OR 1=1-- payload, returned all user data"],
    ))
    assert "quality_score" in lint_result
    print("  [PASS] Test 13f: Report linting via app")

    # Test 13g: Dashboard
    dashboard = app.get_dashboard("test_user")
    assert dashboard["user_id"] == "test_user"
    assert dashboard["subscription"]["tier"] == "Pro"
    print("  [PASS] Test 13g: Dashboard data retrieval")

    return True


# ============================================================
# FULL REGRESSION AUDIT
# ============================================================
def full_regression():
    """Ensure ALL phases (1, 2, 3) remain intact."""
    # Phase 1 regression
    from src.core.submission_blocker import SubmissionBlocker, GateID, ApprovalToken
    blocker = SubmissionBlocker()
    fake = ApprovalToken("x", "y", GateID.FINAL_REPORT_SUBMISSION, time.time(), "FAKE")
    try:
        blocker.validate_and_permit(fake)
        return False
    except Exception:
        print("  [PASS] Phase 1 Regression: SubmissionBlocker intact")

    # Phase 2 regression
    from src.ai.llm_router import LLMRouter, TaskComplexity, LLMProvider
    router = LLMRouter(monthly_budget_usd=100.0)
    decision = router.route(TaskComplexity.LOW)
    assert decision.selected_provider != LLMProvider.GPT4O  # LOW should not route to GPT4O
    print("  [PASS] Phase 2 Regression: LLM Router intact")

    from src.data.acceptance_graph import AcceptanceGraph
    graph = AcceptanceGraph()
    assert graph.total_records == 0
    print("  [PASS] Phase 2 Regression: Acceptance Graph intact")

    return True


# ============================================================
# MAIN RUNNER
# ============================================================
def main() -> int:
    tests = [
        ("Subscription Engine", test_subscription_engine),
        ("Revenue Share", test_revenue_share),
        ("Payment Gateway", test_payment_gateway),
        ("CoPilotApp Integration", test_copilot_app),
        ("Full Regression (Phases 1-3)", full_regression),
    ]

    print("=" * 60)
    print("verify_phase3.py -- Phase 3 Revenue & Integration TDD Gate")
    print("=" * 60)

    all_passed = True
    for name, test_fn in tests:
        print(f"\n[TEST] Running: {name}")
        try:
            passed = test_fn()
            if not passed:
                print(f"  [FAIL] {name} FAILED")
                all_passed = False
            else:
                print(f"  [PASS] {name} -- ALL TESTS PASSED")
        except Exception as e:
            print(f"  [FAIL] {name} FAILED with exception: {e}")
            traceback.print_exc()
            all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("[PASS] ALL PHASE 3 TESTS PASSED -- Task may be marked COMPLETE")
        return 0
    else:
        print("[FAIL] SOME TESTS FAILED -- Task CANNOT be marked complete")
        return 1


if __name__ == "__main__":
    sys.exit(main())
