"""
Bug Bounty Co-Pilot -- CLI Wrapper
====================================
Command-line interface for the CoPilot App.
Allows testing the full pipeline directly from the terminal.
"""

import sys
import time
from typing import Any

from src.api.app import CoPilotApp
from src.ai.report_linter import ReportContent


def print_header(title: str):
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)


def main():
    print_header("BUG BOUNTY CO-PILOT v4.0 -- CLI MODE")
    print("Initializing AI components and loading data moat...")
    app = CoPilotApp(monthly_llm_budget=100.0)
    time.sleep(1)  # Simulate load time for effect
    print("System Online.\n")

    user_id = input("Enter Hunter ID (e.g., hunter_99): ").strip() or "hunter_99"
    
    print_header("1. SUBSCRIPTION & REVENUE TIER")
    print("Select your subscription tier:")
    print("  1. Starter (0/mo, 20% rev share)")
    print("  2. Growth (499/mo, 15% rev share, Smart Routing)")
    print("  3. Pro    (1999/mo, 10% rev share, +Acceptance Graph)")
    print("  4. Elite  (4999/mo, VIP features)")
    
    tier_choice = input("\nChoice [1-4]: ").strip()
    tier_map = {"1": "free", "2": "growth", "3": "pro", "4": "elite"}
    selected_tier = tier_map.get(tier_choice, "free")
    
    sub = app.subscribe(user_id, selected_tier)
    print(f"\n[+] Subscribed to {sub['tier']} Tier.")
    print(f"[+] Reports remaining: {sub['reports_remaining']}")
    
    # Show payment if not free
    if sub.get("payment_order"):
        print(f"[*] Payment Order generated: {sub['payment_order']['order_id']}")
        print(f"[*] Amount Due: INR {sub['payment_order']['amount_inr']}")
        print("[*] (Sandbox mode: Payment auto-verified)")

    print_header("2. ACCEPTANCE PREDICTION (DATA MOAT)")
    print("Checking Acceptance Intelligence Graph for vulnerability probability...")
    platform = input("Platform (e.g., hackerone): ").strip() or "hackerone"
    vuln_class = input("Vuln Class (e.g., sqli, xss, idor): ").strip() or "sqli"
    
    pred = app.predict_acceptance(platform, "prog_1", vuln_class, "High")
    print(f"\n[AI] Prediction Results:")
    print(f"  Acceptance Prob: {pred['acceptance_probability'] * 100:.1f}%")
    print(f"  Dup Probability: {pred['dup_probability'] * 100:.1f}%")
    print(f"  Est. Bounty:     ${pred['estimated_bounty_usd']:.2f}")
    print(f"  Confidence:      {pred['confidence'] * 100:.1f}%")
    print(f"\n[AI] Recommendation: {pred['recommendation']}")

    if pred['acceptance_probability'] < 0.4:
        print("\n[!] Warning: Low probability. Consider hunting elsewhere.")
        continue_hunt = input("Continue anyway? (y/n): ").strip().lower()
        if continue_hunt != 'y':
            print("Hunt aborted. Smart decision.")
            sys.exit(0)

    print_header("3. HUNTING WORKFLOW")
    print("Starting secure hunting session...")
    session = app.start_session(user_id, "prog_1")
    session_id = session["workflow_session_id"]
    
    print(f"[*] Session ID: {session_id}")
    print(f"[*] Status: {session['status']}")
    print(f"[*] Current Station: {session['current_station']}")
    
    # Advance to HITL
    print("\nAdvancing through automated stations (Recon -> Exploitation -> Report)...")
    for _ in range(3):
        time.sleep(0.5)
        res = app.advance_workflow(session_id)
        print(f"  -> Reached: {res['current_station']}")
        if res.get("requires_approval"):
            print("  [!] HITL Gate Triggered. Halting automation.")
            break

    print_header("4. AI REPORT LINTER (ANTI-HALLUCINATION)")
    print("Linting the generated report before submission...")
    
    report = ReportContent(
        title="SQL Injection in Login parameters",
        summary="Found SQLi in username param.",
        severity="High",
        impact="Can read user database",
        steps_to_reproduce="1. Go to login. 2. Input ' OR 1=1--",
        proof_of_concept="Payload works.",
        remediation="Fix it.",
        poc_logs=["[ERROR] syntax error in SQL query near ' OR 1=1--"]
    )
    
    lint_res = app.lint_report(report)
    print(f"\n[Linter] Quality Score: {lint_res['quality_score']}/100")
    print(f"[Linter] Can Submit: {lint_res['can_submit']}")
    if lint_res['findings']:
        print("\nFindings:")
        for f in lint_res['findings']:
            print(f"  - [{f['severity']}] {f['message']}")

    if lint_res['can_submit']:
        print("\nAction: APPROVING report submission gate.")
        approval = app.approve_gate(session_id, "APPROVE", lint_res["report_hash"])
        print(f"[+] Gate Result: {'Approved' if approval['approved'] else 'Denied'}")
        
        # Advance to end
        print("\nAdvancing to completion...")
        while True:
            res = app.advance_workflow(session_id)
            print(f"  -> Reached: {res['current_station']}")
            if res['current_station'] == "COMPLETED" or "error" in res:
                break
                
        print("\n[+] Hunt Complete! Report submitted securely.")
    else:
        print("\n[-] Hunt blocked by Report Linter. Fix issues and try again.")

    print_header("5. PERFORMANCE DASHBOARD")
    dash = app.get_dashboard(user_id)
    print(f"User: {dash['user_id']} | Tier: {dash['subscription']['tier']}")
    print(f"\nMetrics:")
    print(f"  Sessions:      {dash['performance']['sessions']}")
    print(f"  Total Bounty:  ${dash['performance']['total_bounty_usd']:.2f}")
    print(f"  Bounty/Hour:   ${dash['performance']['bounty_per_hour']:.2f}/hr")
    
    print("\nThank you for using Bug Bounty Co-Pilot!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
