"""
Bug Bounty Co-Pilot -- FastAPI Web Server
===========================================
Exposes the CoPilotApp via REST endpoints.
Includes OpenAPI/Swagger UI.
"""

import os
import sys
import logging
from typing import Any

# God-Mode Path Injection: Ensures 'src' is always resolvable in cloud environments
root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
if root_path not in sys.path:
    sys.path.insert(0, root_path)

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

from src.api.app import CoPilotApp
from src.ai.report_linter import ReportContent

logger = logging.getLogger(__name__)


# Global app instance initialized on startup
copilot: CoPilotApp = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global copilot
    logger.info("Starting CoPilotApp REST API...")
    copilot = CoPilotApp()
    
    # Initialize a test user with a "Growth" tier subscription
    # This simulates a logged-in user for beta testing
    copilot.subscribe("beta_user_1", "growth")
    logger.info("Created test user 'beta_user_1' on Growth tier.")
    
    yield
    
    logger.info("Shutting down CoPilotApp REST API...")


app = FastAPI(
    title="Bug Bounty SaaS Co-Pilot",
    description="AI-driven bug bounty hunting automation tier",
    version="4.0.0",
    lifespan=lifespan,
)

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# API Models
# ============================================================

class SessionStartRequest(BaseModel):
    user_id: str
    program_id: str


class SessionAdvanceRequest(BaseModel):
    session_id: str


class GateApprovalRequest(BaseModel):
    session_id: str
    approval: str  # "APPROVE" or "REJECT"
    report_hash: str = ""


class LintReportRequest(BaseModel):
    title: str
    summary: str
    severity: str
    impact: str
    steps_to_reproduce: str
    proof_of_concept: str
    remediation: str
    poc_logs: list[str]


class PredictAcceptanceRequest(BaseModel):
    platform: str
    program_id: str
    vuln_class: str
    severity: str


class SubscribeRequest(BaseModel):
    user_id: str
    tier: str
    is_annual: bool = False


# ============================================================
# Endpoints
# ============================================================

from fastapi.responses import RedirectResponse

@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="/docs")

@app.get("/health")
def read_health() -> dict[str, Any]:
    return copilot.get_health()

@app.get("/api/v1/dashboard/{user_id}")
def get_dashboard(user_id: str) -> dict[str, Any]:
    return copilot.get_dashboard(user_id)


@app.post("/api/v1/workflow/start")
def start_session(req: SessionStartRequest) -> dict[str, Any]:
    try:
        return copilot.start_session(req.user_id, req.program_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/workflow/advance")
def advance_workflow(req: SessionAdvanceRequest) -> dict[str, Any]:
    res = copilot.advance_workflow(req.session_id)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])
    return res


@app.post("/api/v1/workflow/approve")
def approve_gate(req: GateApprovalRequest) -> dict[str, Any]:
    res = copilot.approve_gate(req.session_id, req.approval, req.report_hash)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])
    return res


@app.post("/api/v1/reports/lint")
def lint_report(req: LintReportRequest) -> dict[str, Any]:
    content = ReportContent(
        title=req.title,
        summary=req.summary,
        severity=req.severity,
        impact=req.impact,
        steps_to_reproduce=req.steps_to_reproduce,
        proof_of_concept=req.proof_of_concept,
        remediation=req.remediation,
        poc_logs=req.poc_logs,
    )
    return copilot.lint_report(content)


@app.post("/api/v1/predict/acceptance")
def predict_acceptance(req: PredictAcceptanceRequest) -> dict[str, Any]:
    return copilot.predict_acceptance(
        platform=req.platform,
        program_id=req.program_id,
        vuln_class=req.vuln_class,
        severity=req.severity,
    )


@app.post("/api/v1/payments/subscribe")
def subscribe(req: SubscribeRequest) -> dict[str, Any]:
    res = copilot.subscribe(req.user_id, req.tier, req.is_annual)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])
    return res


if __name__ == "__main__":
    import uvicorn
    import os
    # Use environment-provided port or default to 8000
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=port, reload=False)

