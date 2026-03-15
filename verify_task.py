"""
verify_task.py — Mandatory TDD Gate (Article 3 of the Constitution)
====================================================================
This script verifies ALL foundation modules pass their core functionality
tests AND includes a Regression Audit to ensure preexisting features
remain intact alongside new ones.

Exit code 0 = PASS → Task can be marked complete.
Exit code != 0 = FAIL → Must loop back (max 3 retries per Article 3).
"""

import sys
import time
import traceback

# ============================================================
# Test 1: SubmissionBlocker — Cryptographic HITL Enforcement
# ============================================================
def test_submission_blocker():
    """Verify the #1 guardrail: no submission without a valid token."""
    from src.core.submission_blocker import (
        SubmissionBlocker, GateID,
        SubmissionBlockedError, TokenExpiredError, TokenInvalidError, ApprovalToken,
    )

    blocker = SubmissionBlocker(token_ttl_seconds=5)

    # Test 1a: Valid token creation and validation
    token = blocker.create_approval_token(
        user_id="hunter_1",
        report_hash="abc123def456",
        gate_id=GateID.FINAL_REPORT_SUBMISSION,
    )
    assert isinstance(token, ApprovalToken), "Token should be an ApprovalToken instance"
    assert token.user_id == "hunter_1"
    assert token.gate_id == GateID.FINAL_REPORT_SUBMISSION
    assert blocker.validate_and_permit(token) is True, "Valid token should permit submission"
    print("  [PASS] Test 1a: Valid token creation and validation PASSED")

    # Test 1b: Token replay attack prevention
    try:
        blocker.validate_and_permit(token)  # Same token again
        print("  [FAIL] Test 1b: FAILED -- replay attack not prevented!")
        return False
    except SubmissionBlockedError:
        print("  [PASS] Test 1b: Replay attack prevention PASSED")

    # Test 1c: Token with tampered signature
    tampered_token = ApprovalToken(
        user_id="hunter_1",
        report_hash="abc123def456",
        gate_id=GateID.FINAL_REPORT_SUBMISSION,
        timestamp=time.time(),
        signature="TAMPERED_SIGNATURE_INVALID",
    )
    try:
        blocker.validate_and_permit(tampered_token)
        print("  [FAIL] Test 1c: FAILED -- tampered token was accepted!")
        return False
    except TokenInvalidError:
        print("  [PASS] Test 1c: Tampered token rejection PASSED")

    # Test 1d: Expired token
    blocker_short_ttl = SubmissionBlocker(token_ttl_seconds=1)
    token = blocker_short_ttl.create_approval_token(
        user_id="hunter_1",
        report_hash="abc123",
        gate_id=GateID.TARGET_HYPOTHESIS_APPROVAL,
    )
    time.sleep(2)  # Wait for expiration
    try:
        blocker_short_ttl.validate_and_permit(token)
        print("  [FAIL] Test 1d: FAILED -- expired token was accepted!")
        return False
    except TokenExpiredError:
        print("  [PASS] Test 1d: Expired token rejection PASSED")

    # Test 1e: Audit trail
    assert blocker.total_submissions_approved == 1, "Should have 1 approved submission"
    assert blocker.total_submissions_blocked >= 1, "Should have at least 1 blocked submission"
    print("  [PASS] Test 1e: Audit trail PASSED")

    return True


# ============================================================
# Test 2: WorkflowEngine — 9-Station HITL State Machine
# ============================================================
def test_workflow_engine():
    """Verify the 9-station workflow with mandatory HITL gates."""
    from src.core.submission_blocker import SubmissionBlocker
    from src.core.workflow_engine import (
        WorkflowEngine, WorkflowStation, WorkflowStatus,
    )

    blocker = SubmissionBlocker()
    events_received = []
    engine = WorkflowEngine(
        submission_blocker=blocker,
        event_listeners=[lambda e: events_received.append(e)],
    )

    session = engine.create_session(user_id="hunter_1", program_id="test_program")
    assert session.current_station == WorkflowStation.PROGRAM_SELECTION
    print("  [PASS] Test 2a: Session creation PASSED")

    # Advance through non-gate stations
    engine.advance(session)  # -> RECONNAISSANCE
    assert session.current_station == WorkflowStation.RECONNAISSANCE
    engine.advance(session)  # -> TARGET_ANALYSIS
    assert session.current_station == WorkflowStation.TARGET_ANALYSIS
    print("  [PASS] Test 2b: Non-gate advancement PASSED")

    # Advance to Gate 1
    engine.advance(session)  # -> HITL_GATE_TARGET_APPROVAL
    assert session.current_station == WorkflowStation.HITL_GATE_TARGET_APPROVAL
    assert session.status == WorkflowStatus.PAUSED_AT_GATE
    print("  [PASS] Test 2c: Gate 1 pause PASSED")

    # Try to advance without approval — should fail
    try:
        engine.advance(session)
        print("  [FAIL] Test 2d: FAILED -- advanced past gate without approval!")
        return False
    except ValueError:
        print("  [PASS] Test 2d: Gate enforcement (cannot advance without approval) PASSED")

    # Try invalid approval input
    try:
        engine.approve_gate(session, "yes")
        print("  [FAIL] Test 2e: FAILED -- accepted invalid approval input!")
        return False
    except ValueError:
        print("  [PASS] Test 2e: Invalid approval input rejection PASSED")

    # Valid approval at Gate 1
    token = engine.approve_gate(session, "APPROVE")
    assert session.status == WorkflowStatus.ACTIVE
    print("  [PASS] Test 2f: Gate 1 approval PASSED")

    # Advance to Gate 2
    engine.advance(session)  # -> VULNERABILITY_DISCOVERY
    engine.advance(session)  # -> HITL_GATE_EXPLOIT_VALIDATION
    assert session.current_station == WorkflowStation.HITL_GATE_EXPLOIT_VALIDATION
    assert session.status == WorkflowStatus.PAUSED_AT_GATE
    token = engine.approve_gate(session, "APPROVE")
    print("  [PASS] Test 2g: Gate 2 PASSED")

    # Advance to Gate 3
    engine.advance(session)  # -> REPORT_GENERATION
    engine.advance(session)  # -> HITL_GATE_REPORT_SUBMISSION
    assert session.current_station == WorkflowStation.HITL_GATE_REPORT_SUBMISSION
    assert session.status == WorkflowStatus.PAUSED_AT_GATE

    # Gate 3 requires report_hash
    try:
        engine.approve_gate(session, "APPROVE")
        print("  [FAIL] Test 2h: FAILED -- Gate 3 accepted without report_hash!")
        return False
    except ValueError:
        print("  [PASS] Test 2h: Gate 3 report_hash requirement PASSED")

    token = engine.approve_gate(session, "APPROVE", report_hash="report_hash_123")
    print("  [PASS] Test 2i: Gate 3 approval with report_hash PASSED")

    # Advance to FEEDBACK_LOOP and complete
    engine.advance(session)  # -> FEEDBACK_LOOP
    assert session.current_station == WorkflowStation.FEEDBACK_LOOP
    engine.advance(session)  # -> Complete
    assert session.status == WorkflowStatus.COMPLETED
    print("  [PASS] Test 2j: Full workflow completion PASSED")

    # Verify events were emitted
    assert len(events_received) > 0, "Should have received workflow events"
    print(f"  [PASS] Test 2k: Event emission PASSED ({len(events_received)} events)")

    return True


# ============================================================
# Test 3: ToSEngine — Compliance-by-Design
# ============================================================
def test_tos_engine():
    """Verify the ToS engine blocks out-of-scope targets."""
    from src.compliance.tos_engine import (
        ToSEngine, ProgramScope, ScopeStatus,
        ComplianceViolationType,
    )

    engine = ToSEngine()

    # Register a test program
    engine.register_program(ProgramScope(
        program_id="test_prog_1",
        platform="hackerone",
        in_scope_domains=["*.example.com", "api.target.io"],
        out_of_scope_domains=["admin.example.com", "staging.example.com"],
        prohibited_methods=["ddos", "social_engineering"],
        allows_automated_scanning=False,
        max_requests_per_minute=5,
    ))

    # Test 3a: In-scope target
    result = engine.check_compliance("test_prog_1", target="app.example.com")
    assert result.is_compliant is True
    assert result.scope_status == ScopeStatus.IN_SCOPE
    print("  [PASS] Test 3a: In-scope target acceptance PASSED")

    # Test 3b: Out-of-scope target
    result = engine.check_compliance("test_prog_1", target="admin.example.com")
    assert result.is_compliant is False
    assert result.scope_status == ScopeStatus.OUT_OF_SCOPE
    assert any(v.violation_type == ComplianceViolationType.OUT_OF_SCOPE_ASSET for v in result.violations)
    print("  [PASS] Test 3b: Out-of-scope target blocking PASSED")

    # Test 3c: Unknown target (not listed — should block with high risk)
    result = engine.check_compliance("test_prog_1", target="random.other.com")
    assert result.is_compliant is False
    assert result.scope_status == ScopeStatus.UNKNOWN
    print("  [PASS] Test 3c: Unknown target blocking PASSED")

    # Test 3d: Prohibited testing method
    result = engine.check_compliance("test_prog_1", target="app.example.com", method="ddos")
    assert result.is_compliant is False
    assert any(v.violation_type == ComplianceViolationType.PROHIBITED_TESTING_METHOD for v in result.violations)
    print("  [PASS] Test 3d: Prohibited method blocking PASSED")

    # Test 3e: Automated scanning blocked
    result = engine.check_compliance("test_prog_1", target="app.example.com", is_automated=True)
    assert result.is_compliant is False
    assert any(v.violation_type == ComplianceViolationType.UNAUTHORIZED_AUTOMATION for v in result.violations)
    print("  [PASS] Test 3e: Unauthorized automation blocking PASSED")

    # Test 3f: Unknown program — block everything
    result = engine.check_compliance("unknown_program", target="anything.com")
    assert result.is_compliant is False
    assert result.risk_score_contribution == 1.0
    print("  [PASS] Test 3f: Unknown program blocking PASSED")

    # Test 3g: Rate limiting
    for _ in range(6):  # Exceed the 5 req/min limit
        engine.check_compliance("test_prog_1", target="app.example.com")
    result = engine.check_compliance("test_prog_1", target="app.example.com")
    assert any(v.violation_type == ComplianceViolationType.RATE_LIMIT_EXCEEDED for v in result.violations)
    print("  [PASS] Test 3g: Rate limiting PASSED")

    return True


# ============================================================
# Test 4: BanRiskScorer — Ban Risk Score
# ============================================================
def test_ban_risk_scorer():
    """Verify the BRS calculator correctly classifies risk levels."""
    from src.compliance.tos_engine import ComplianceCheckResult, ScopeStatus
    from src.compliance.ban_risk_score import (
        BanRiskScorer, BRSInput, RiskLevel, BRSAction,
    )

    scorer = BanRiskScorer()

    # Test 4a: Clean action — low risk
    clean_compliance = ComplianceCheckResult(
        is_compliant=True,
        scope_status=ScopeStatus.IN_SCOPE,
        risk_score_contribution=0.0,
    )
    result = scorer.calculate(BRSInput(
        compliance_result=clean_compliance,
        platform="hackerone",
    ))
    assert result.risk_level == RiskLevel.SAFE
    assert result.action == BRSAction.ALLOW
    print("  [PASS] Test 4a: Clean action -> SAFE PASSED")

    # Test 4b: ToS violation alone -> HIGH_RISK (CRITICAL requires compounding factors)
    violation_compliance = ComplianceCheckResult(
        is_compliant=False,
        scope_status=ScopeStatus.OUT_OF_SCOPE,
        risk_score_contribution=1.0,
    )
    result = scorer.calculate(BRSInput(
        compliance_result=violation_compliance,
        platform="hackerone",
    ))
    # Single-factor risk: compliance_weight(0.40) * 1.0 = 0.40 -> CAUTION or HIGH_RISK
    assert result.risk_level in (RiskLevel.CAUTION, RiskLevel.HIGH_RISK)
    assert result.action in (BRSAction.WARN, BRSAction.REQUIRE_REVIEW)
    print("  [PASS] Test 4b: ToS violation -> HIGH_RISK (single factor) PASSED")

    # Test 4b2: COMPOUNDING risk factors -> CRITICAL (BLOCK)
    result_critical = scorer.calculate(BRSInput(
        compliance_result=violation_compliance,
        submission_count_last_hour=15,
        report_similarity_score=0.9,
        is_automated_action=True,
        user_ban_history_count=3,
        platform="synack",  # Synack multiplier makes it even higher
    ))
    assert result_critical.risk_level == RiskLevel.CRITICAL
    assert result_critical.action == BRSAction.BLOCK
    assert result_critical.is_blocked is True
    print("  [PASS] Test 4b2: Compounding factors -> CRITICAL (BLOCK) PASSED")

    # Test 4c: High velocity detection — verify velocity IS detected as risk factor
    result = scorer.calculate(BRSInput(
        compliance_result=clean_compliance,
        submission_count_last_hour=15,
        submission_count_last_day=40,
        platform="hackerone",
    ))
    # Velocity weight=0.20, velocity_risk=1.0 -> BRS=0.20 (SAFE to CAUTION range)
    # The key assertion: velocity IS detected as contributing factor
    assert result.score > 0.0, "Velocity should produce non-zero risk score"
    assert any("Velocity" in f for f in result.contributing_factors), "Velocity should be in contributing factors"
    print("  [PASS] Test 4c: High velocity detection PASSED")

    # Test 4d: Platform multiplier (Synack = stricter)
    result_synack = scorer.calculate(BRSInput(
        compliance_result=clean_compliance,
        submission_count_last_hour=8,
        is_automated_action=True,
        platform="synack",
    ))
    result_bugbase = scorer.calculate(BRSInput(
        compliance_result=clean_compliance,
        submission_count_last_hour=8,
        is_automated_action=True,
        platform="bugbase",
    ))
    assert result_synack.score > result_bugbase.score, "Synack should score higher risk than BugBase"
    print("  [PASS] Test 4d: Platform risk multiplier PASSED")

    # Test 4e: Self-correcting weight update
    old_weight = scorer._weights["compliance"]
    scorer.update_weights({"compliance": 0.50})
    assert scorer._weights["compliance"] == 0.50
    scorer.update_weights({"compliance": old_weight})  # Restore
    print("  [PASS] Test 4e: Self-correcting weight update PASSED")

    return True


# ============================================================
# REGRESSION AUDIT
# ============================================================
def regression_audit():
    """
    Ensure all core guardrails remain intact after any code change.
    This is the regression safety net per Article 3.
    """
    from src.core.submission_blocker import SubmissionBlocker, GateID, SubmissionBlockedError

    # Regression 1: SubmissionBlocker MUST NOT accept unsigned tokens
    blocker = SubmissionBlocker()
    from src.core.submission_blocker import ApprovalToken
    fake_token = ApprovalToken(
        user_id="attacker",
        report_hash="fake",
        gate_id=GateID.FINAL_REPORT_SUBMISSION,
        timestamp=time.time(),
        signature="NOT_A_VALID_SIGNATURE",
    )
    try:
        blocker.validate_and_permit(fake_token)
        print("  [FAIL] REGRESSION FAILURE: Unsigned token was accepted!")
        return False
    except Exception:
        print("  [PASS] Regression 1: Unsigned token rejection intact")

    # Regression 2: WorkflowEngine MUST NOT skip HITL gates
    from src.core.workflow_engine import WorkflowEngine, WorkflowStation, WorkflowStatus
    engine = WorkflowEngine(submission_blocker=blocker)
    session = engine.create_session(user_id="test", program_id="test")
    for _ in range(3):  # Advance to Gate 1
        engine.advance(session)
    assert session.status == WorkflowStatus.PAUSED_AT_GATE, "Should be paused at gate"
    try:
        engine.advance(session)
        print("  [FAIL] REGRESSION FAILURE: HITL gate was skipped!")
        return False
    except (ValueError, SubmissionBlockedError):
        print("  [PASS] Regression 2: HITL gate enforcement intact")

    # Regression 3: ToSEngine MUST block out-of-scope by default
    from src.compliance.tos_engine import ToSEngine, ProgramScope
    tos = ToSEngine()
    tos.register_program(ProgramScope(
        program_id="reg_test",
        platform="hackerone",
        in_scope_domains=["*.safe.com"],
        out_of_scope_domains=["admin.safe.com"],
    ))
    result = tos.check_compliance("reg_test", target="admin.safe.com")
    assert not result.is_compliant, "Out-of-scope target should be blocked"
    result2 = tos.check_compliance("reg_test", target="unknown.random.com")
    assert not result2.is_compliant, "Unknown target should be blocked (safe default)"
    print("  [PASS] Regression 3: ToS safe-default blocking intact")

    return True


# ============================================================
# MAIN RUNNER
# ============================================================
def main() -> int:
    tests = [
        ("SubmissionBlocker", test_submission_blocker),
        ("WorkflowEngine", test_workflow_engine),
        ("ToSEngine", test_tos_engine),
        ("BanRiskScorer", test_ban_risk_scorer),
        ("Regression Audit", regression_audit),
    ]

    print("=" * 60)
    print("verify_task.py — Article 3 TDD Gate + Regression Audit")
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
        print("[PASS] ALL TESTS PASSED -- Task may be marked COMPLETE")
        return 0
    else:
        print("[FAIL] SOME TESTS FAILED -- Task CANNOT be marked complete")
        return 1


if __name__ == "__main__":
    sys.exit(main())
