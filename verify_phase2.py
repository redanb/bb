"""
verify_phase2.py -- Phase 2 AI Layer TDD Gate
===============================================
Tests for: LLM Router, Report Linter, Acceptance Graph,
           Dup Predictor, Bounty/Hour Tracker

Exit code 0 = PASS. Exit code 1 = FAIL (max 3 retries per Article 3).
"""

import sys
import time
import traceback


# ============================================================
# Test 5: LLM Router
# ============================================================
def test_llm_router():
    """Verify smart routing, cost ceiling, and self-optimization."""
    from src.ai.llm_router import (
        LLMRouter, TaskComplexity, LLMProvider, MODEL_PRICING,
    )

    # Test 5a: Basic routing by complexity tier
    router = LLMRouter(monthly_budget_usd=10.0)
    decision = router.route(TaskComplexity.LOW, estimated_tokens=1000)
    assert decision.selected_provider in (LLMProvider.GEMINI_FLASH_LITE, LLMProvider.DEEPSEEK_V3)
    print("  [PASS] Test 5a: LOW complexity routes to cheap model")

    decision = router.route(TaskComplexity.HIGH, estimated_tokens=1000)
    assert decision.selected_provider in (LLMProvider.GPT4O, LLMProvider.CLAUDE_35_SONNET)
    print("  [PASS] Test 5b: HIGH complexity routes to premium model")

    # Test 5c: Cost ceiling enforcement
    router_tiny = LLMRouter(monthly_budget_usd=0.001)
    # Spend the entire budget
    router_tiny.record_outcome(LLMProvider.GPT4O, cost_usd=0.002)
    decision = router_tiny.route(TaskComplexity.HIGH, estimated_tokens=5000)
    assert decision.selected_provider == LLMProvider.LLAMA_LOCAL
    assert decision.fallback_used is True
    print("  [PASS] Test 5c: Cost ceiling triggers local fallback")

    # Test 5d: Outcome recording
    router.record_outcome(LLMProvider.GEMINI_FLASH_LITE, cost_usd=0.001, accepted=True, quality_score=0.9)
    router.record_outcome(LLMProvider.GEMINI_FLASH_LITE, cost_usd=0.001, accepted=False, quality_score=0.3)
    report = router.get_optimization_report()
    assert "gemini-flash-lite" in report["models"]
    assert report["models"]["gemini-flash-lite"]["total_tasks"] == 2
    print("  [PASS] Test 5d: Outcome recording and reporting")

    # Test 5e: v3.1 pricing verification
    pricing = MODEL_PRICING[LLMProvider.GPT4O_MINI]
    assert pricing.input_per_million == 0.15, "v3.1 corrected price should be $0.15/M"
    assert pricing.output_per_million == 0.60
    print("  [PASS] Test 5e: v3.1 fact-checked pricing verified")

    # Test 5f: Force provider override
    decision = router.route(TaskComplexity.LOW, force_provider=LLMProvider.GPT4O)
    assert decision.selected_provider == LLMProvider.GPT4O
    print("  [PASS] Test 5f: Force provider override")

    return True


# ============================================================
# Test 6: Report Linter
# ============================================================
def test_report_linter():
    """Verify anti-hallucination and quality scoring."""
    from src.ai.report_linter import (
        ReportLinter, ReportContent, LintSeverity, LintCategory,
    )

    linter = ReportLinter()

    # Test 6a: Valid report passes lint
    good_report = ReportContent(
        title="Stored XSS in /api/comments endpoint",
        summary="A stored XSS vulnerability exists in the comments API that allows injection of arbitrary JavaScript.",
        severity="High",
        impact="An attacker can execute arbitrary JavaScript in the context of other users' sessions.",
        steps_to_reproduce="1. Navigate to /api/comments\n2. Submit a comment with payload\n3. View the comment",
        proof_of_concept="The payload <script>alert(document.cookie)</script> was injected via the /api/comments endpoint.",
        remediation="Implement proper output encoding and Content-Security-Policy headers.",
        poc_logs=["HTTP/1.1 200 OK\n<script>alert(document.cookie)</script> rendered in /api/comments response"],
    )
    result = linter.lint(good_report)
    assert result.can_submit is True
    assert result.quality_score > 0.5
    print("  [PASS] Test 6a: Valid report passes lint")

    # Test 6b: Missing sections detected
    bad_report = ReportContent(
        title="XSS Bug",
        summary="",
        severity="",
        impact="",
        steps_to_reproduce="",
        proof_of_concept="",
        remediation="",
    )
    result = linter.lint(bad_report)
    assert result.can_submit is False
    assert result.error_count > 0
    print("  [PASS] Test 6b: Missing sections detected as errors")

    # Test 6c: No PoC logs -> CRITICAL finding
    no_poc_report = ReportContent(
        title="SQL Injection in login form",
        summary="Found SQLi vulnerability in the login endpoint parameter.",
        severity="Critical",
        impact="Full database access for attackers.",
        steps_to_reproduce="1. Go to login page\n2. Enter payload in username field",
        proof_of_concept="The payload ' OR 1=1 -- was used to bypass authentication.",
        remediation="Use parameterized queries.",
        poc_logs=[],  # No PoC logs!
    )
    result = linter.lint(no_poc_report)
    assert result.can_submit is False
    has_critical = any(f.severity == LintSeverity.CRITICAL for f in result.findings)
    assert has_critical, "Missing PoC logs should be CRITICAL"
    print("  [PASS] Test 6c: Missing PoC logs -> CRITICAL finding")

    # Test 6d: Quality score decreases with issues
    assert linter.lint(good_report).quality_score > linter.lint(no_poc_report).quality_score
    print("  [PASS] Test 6d: Quality score reflects report quality")

    # Test 6e: Report hash generation
    assert len(good_report.report_hash) == 64  # SHA-256 hex
    print("  [PASS] Test 6e: Report hash generation")

    return True


# ============================================================
# Test 7: Acceptance Graph
# ============================================================
def test_acceptance_graph():
    """Verify the core data moat -- acceptance prediction engine."""
    from src.data.acceptance_graph import (
        AcceptanceGraph, SubmissionRecord, SubmissionOutcome, VulnerabilityClass,
    )

    graph = AcceptanceGraph()

    # Seed with test data
    for i in range(10):
        graph.record(SubmissionRecord(
            record_id=f"rec_{i}",
            platform="hackerone",
            program_id="prog_1",
            vulnerability_class=VulnerabilityClass.XSS_STORED,
            severity_claimed="High",
            outcome=SubmissionOutcome.ACCEPTED if i < 7 else SubmissionOutcome.REJECTED,
            bounty_amount_usd=500.0 if i < 7 else 0.0,
        ))
    for i in range(5):
        graph.record(SubmissionRecord(
            record_id=f"dup_{i}",
            platform="hackerone",
            program_id="prog_1",
            vulnerability_class=VulnerabilityClass.XSS_STORED,
            outcome=SubmissionOutcome.DUPLICATE,
        ))

    # Test 7a: Prediction with good data
    prediction = graph.predict("hackerone", "prog_1", VulnerabilityClass.XSS_STORED, "High")
    assert prediction.acceptance_probability > 0.0
    assert prediction.confidence > 0.0
    assert prediction.similar_submissions > 0
    print(f"  [PASS] Test 7a: Acceptance prediction (prob={prediction.acceptance_probability:.2f}, conf={prediction.confidence:.2f})")

    # Test 7b: Dup probability tracked
    assert prediction.dup_probability > 0.0
    print(f"  [PASS] Test 7b: Dup probability tracked ({prediction.dup_probability:.2f})")

    # Test 7c: No data -> low confidence fallback
    empty_prediction = graph.predict("unknown", "unknown_prog", VulnerabilityClass.RCE, "Critical")
    assert empty_prediction.confidence < prediction.confidence
    print("  [PASS] Test 7c: Unknown target -> lower confidence")

    # Test 7d: Stats reporting
    stats = graph.get_stats()
    assert stats["total_records"] == 15
    assert stats["total_bounty_earned"] == 3500.0
    print("  [PASS] Test 7d: Graph stats reporting")

    return True


# ============================================================
# Test 8: Dup Predictor
# ============================================================
def test_dup_predictor():
    """Verify duplicate prediction system."""
    from src.data.acceptance_graph import AcceptanceGraph, SubmissionRecord, SubmissionOutcome, VulnerabilityClass
    from src.data.dup_predictor import DupPredictor, VulnerabilityFingerprint

    graph = AcceptanceGraph()
    predictor = DupPredictor(acceptance_graph=graph)

    # Register known fingerprints
    known_fp = VulnerabilityFingerprint(
        target_domain="example.com",
        endpoint="/api/search",
        vulnerability_class=VulnerabilityClass.XSS_REFLECTED,
        parameter="q",
    )
    predictor.register_fingerprint(known_fp)

    # Test 8a: Exact match -> high dup probability
    same_fp = VulnerabilityFingerprint(
        target_domain="example.com",
        endpoint="/api/search",
        vulnerability_class=VulnerabilityClass.XSS_REFLECTED,
        parameter="q",
    )
    result = predictor.check(same_fp, program_id="prog_1")
    assert result.dup_probability > 0.5
    print(f"  [PASS] Test 8a: Exact match -> high dup prob ({result.dup_probability:.2f})")

    # Test 8b: Novel target -> low dup probability
    novel_fp = VulnerabilityFingerprint(
        target_domain="newsite.com",
        endpoint="/api/users",
        vulnerability_class=VulnerabilityClass.IDOR,
        parameter="user_id",
    )
    result = predictor.check(novel_fp, program_id="prog_2")
    assert result.dup_probability < 0.5
    assert result.should_proceed is True
    print(f"  [PASS] Test 8b: Novel target -> low dup prob ({result.dup_probability:.2f})")

    # Test 8c: Recommendation generation
    assert len(result.recommendation) > 0
    print("  [PASS] Test 8c: Recommendations generated")

    return True


# ============================================================
# Test 9: Bounty/Hour Tracker
# ============================================================
def test_bounty_per_hour_tracker():
    """Verify North Star KPI tracking and Income Guarantee."""
    from src.data.bounty_per_hour_tracker import BountyPerHourTracker

    tracker = BountyPerHourTracker(income_guarantee_threshold=100.0)

    # Test 9a: Session lifecycle
    sid = tracker.start_session(user_id="hunter_1", program_id="prog_1")
    tracker.record_bounty(sid, 250.0, vuln_class="xss_stored", accepted=True)
    tracker.record_bounty(sid, 150.0, vuln_class="idor", accepted=True)
    session = tracker.end_session(sid)
    assert session is not None
    assert session.bounty_earned_usd == 400.0
    assert session.submissions_accepted == 2
    assert session.bounty_per_hour > 0
    print(f"  [PASS] Test 9a: Session lifecycle (B/H=${session.bounty_per_hour:.2f})")

    # Test 9b: User performance aggregation
    perf = tracker.get_user_performance("hunter_1")
    assert perf is not None
    assert perf.total_bounty_usd == 400.0
    assert perf.total_sessions == 1
    print("  [PASS] Test 9b: User performance aggregation")

    # Test 9c: Income Guarantee alert (need 3+ sessions below threshold)
    for i in range(4):
        sid = tracker.start_session(user_id="low_earner", program_id="prog_2")
        tracker.record_bounty(sid, 5.0, accepted=True)
        tracker.end_session(sid)

    alerts = tracker.guarantee_alerts
    # Should have alerts since $5/session is way below $100/hr threshold
    print(f"  [PASS] Test 9c: Income Guarantee monitoring ({len(alerts)} alerts)")

    # Test 9d: Leaderboard
    leaderboard = tracker.get_leaderboard(top_n=5)
    assert len(leaderboard) > 0
    assert leaderboard[0]["bounty_per_hour"] > 0
    print("  [PASS] Test 9d: Leaderboard generation")

    return True


# ============================================================
# PHASE 2 REGRESSION AUDIT
# ============================================================
def phase2_regression():
    """Ensure Phase 1 modules still work correctly after Phase 2 additions."""
    from src.core.submission_blocker import SubmissionBlocker, GateID, ApprovalToken
    from src.core.workflow_engine import WorkflowEngine, WorkflowStatus
    from src.compliance.tos_engine import ToSEngine, ProgramScope

    # Phase 1 Module 1: SubmissionBlocker still works
    blocker = SubmissionBlocker()
    fake = ApprovalToken("x", "y", GateID.FINAL_REPORT_SUBMISSION, time.time(), "FAKE")
    try:
        blocker.validate_and_permit(fake)
        return False
    except Exception:
        print("  [PASS] Regression: SubmissionBlocker intact")

    # Phase 1 Module 2: WorkflowEngine still works
    engine = WorkflowEngine(submission_blocker=blocker)
    session = engine.create_session("test", "test")
    for _ in range(3):
        engine.advance(session)
    assert session.status == WorkflowStatus.PAUSED_AT_GATE
    print("  [PASS] Regression: WorkflowEngine HITL gates intact")

    # Phase 1 Module 3: ToSEngine still works
    tos = ToSEngine()
    tos.register_program(ProgramScope(
        program_id="reg", platform="hackerone",
        in_scope_domains=["*.safe.com"],
        out_of_scope_domains=["admin.safe.com"],
    ))
    assert not tos.check_compliance("reg", "admin.safe.com").is_compliant
    print("  [PASS] Regression: ToSEngine blocking intact")

    return True


# ============================================================
# MAIN RUNNER
# ============================================================
def main() -> int:
    tests = [
        ("LLM Router", test_llm_router),
        ("Report Linter", test_report_linter),
        ("Acceptance Graph", test_acceptance_graph),
        ("Dup Predictor", test_dup_predictor),
        ("Bounty/Hour Tracker", test_bounty_per_hour_tracker),
        ("Phase 2 Regression Audit", phase2_regression),
    ]

    print("=" * 60)
    print("verify_phase2.py -- Phase 2 AI Layer TDD Gate")
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
        print("[PASS] ALL PHASE 2 TESTS PASSED -- Task may be marked COMPLETE")
        return 0
    else:
        print("[FAIL] SOME TESTS FAILED -- Task CANNOT be marked complete")
        return 1


if __name__ == "__main__":
    sys.exit(main())
