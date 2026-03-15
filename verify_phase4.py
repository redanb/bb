"""
verify_phase4.py -- Phase 4 Deployment TDD Gate
=================================================
Tests for: FastAPI REST Endpoints (using TestClient)

Exit code 0 = PASS.
"""

import sys
import time
import traceback
from fastapi.testclient import TestClient

from src.api.main import app, lifespan


# ============================================================
# Test 14: FastAPI Endpoints
# ============================================================
def test_fastapi_endpoints():
    """Verify REST API functionality using TestClient."""
    # TestClient must be used inside the lifespan context
    # but Starlette 0.30+ TestClient handles lifespan automatically
    with TestClient(app) as client:
        # Test 14a: Health check
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "healthy"
        print("  [PASS] Test 14a: GET /health")

        # Test 14b: Start session via API
        payload_start = {
            "user_id": "api_user_1",
            "program_id": "api_prog_1"
        }
        res = client.post("/api/v1/workflow/start", json=payload_start)
        assert res.status_code == 200
        data = res.json()
        assert "workflow_session_id" in data
        assert data["status"] == "ACTIVE"
        session_id = data["workflow_session_id"]
        print("  [PASS] Test 14b: POST /api/v1/workflow/start")

        # Test 14c: Advance workflow
        payload_adv = {"session_id": session_id}
        res = client.post("/api/v1/workflow/advance", json=payload_adv)
        assert res.status_code == 200
        assert "current_station" in res.json()
        print("  [PASS] Test 14c: POST /api/v1/workflow/advance")

        # Test 14d: Subscription and payments
        payload_sub = {
            "user_id": "api_user_1",
            "tier": "growth",
            "is_annual": False
        }
        res = client.post("/api/v1/payments/subscribe", json=payload_sub)
        assert res.status_code == 200
        assert res.json()["tier"] == "Growth"
        assert "payment_order" in res.json()
        print("  [PASS] Test 14d: POST /api/v1/payments/subscribe")

        # Test 14e: Predict acceptance
        payload_pred = {
            "platform": "hackerone",
            "program_id": "prog_1",
            "vuln_class": "sqli",
            "severity": "Critical"
        }
        res = client.post("/api/v1/predict/acceptance", json=payload_pred)
        assert res.status_code == 200
        assert "acceptance_probability" in res.json()
        print("  [PASS] Test 14e: POST /api/v1/predict/acceptance")

        # Test 14f: Dashboard
        res = client.get("/api/v1/dashboard/api_user_1")
        assert res.status_code == 200
        assert res.json()["user_id"] == "api_user_1"
        assert "bounty_per_hour" in res.json()["performance"]
        print("  [PASS] Test 14f: GET /api/v1/dashboard/{user_id}")

    return True


# ============================================================
# FULL REGRESSION AUDIT (Phases 1-3)
# ============================================================
def full_regression():
    """Ensure ALL previous modules remain intact."""
    # Phase 1 + 2 + 3 coverage test via CoPilotApp instance directly
    from src.api.app import CoPilotApp
    copilot = CoPilotApp()
    
    # Verify Phase 1: ToS Engine blocking
    from src.compliance.tos_engine import ProgramScope
    copilot.tos_engine.register_program(ProgramScope("prog1", "platform", out_of_scope_domains=["admin.com"]))
    assert copilot.tos_engine.check_compliance("prog1", "admin.com", "scanner").is_compliant is False
    print("  [PASS] Regression: ToS Engine intact")

    # Verify Phase 2: LLM Routing
    from src.ai.llm_router import TaskComplexity
    assert copilot.llm_router.route(TaskComplexity.LOW).selected_provider.value == "gemini-flash-lite"
    print("  [PASS] Regression: LLM Router intact")

    # Verify Phase 3: Subscription Tiers
    from src.revenue.subscription_engine import SubscriptionTier
    sub = copilot.subscriptions.create_subscription("u1", SubscriptionTier.ELITE)
    assert sub.config.price_inr_monthly == 4999
    print("  [PASS] Regression: Subscription Engine intact")
    
    return True


# ============================================================
# MAIN RUNNER
# ============================================================
def main() -> int:
    try:
        import httpx  # Required by TestClient
    except ImportError:
        import subprocess
        print("Installing httpx for TestClient...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "httpx"])

    tests = [
        ("FastAPI Web Server", test_fastapi_endpoints),
        ("Full Regression (Phases 1-3)", full_regression),
    ]

    print("=" * 60)
    print("verify_phase4.py -- Phase 4 Deployment TDD Gate")
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
        print("[PASS] ALL PHASE 4 TESTS PASSED -- Task may be marked COMPLETE")
        return 0
    else:
        print("[FAIL] SOME TESTS FAILED -- Task CANNOT be marked complete")
        return 1


if __name__ == "__main__":
    sys.exit(main())
