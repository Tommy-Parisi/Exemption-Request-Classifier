import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from engine.decision_engine import make_exception_decision
from engine.rag_integration import RAGIntegrator
from engine.risk_scorer import calculate_risk_score

load_dotenv()

logger = logging.getLogger(__name__)

DATA_LEVEL_MAP = {"Level I": 1, "Level II": 2, "Level III": 3}
DATA_LEVEL_ROMAN = {1: "I", 2: "II", 3: "III"}

PATCH_FREQ_MAP = {
    "Monthly": "monthly",
    "Quarterly": "quarterly",
    "Every 3-6 months": "every 3-6 months",
    "Every 6-12 months": "every 6-12 months",
    "Yearly": "yearly+",
    "Unavailable": "patches unavailable",
}

FIREWALL_MAP = {
    "High Coverage": "adequate",
    "Moderate Coverage": "adequate",
    "Minimal Coverage": "minimal",
    "No Coverage": "no",
}

IMPACT_MAP = {
    "Low": "low",
    "Moderate": "moderate",
    "Extensive": "excessive",
    "Widespread": "excessive",
}

UNIVERSITY_MAP = {
    "Non-Critical": "low",
    "Critical": "moderate",
    "Mission Critical": "excessive",
}

RISK_LEVEL_MAP = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (40, "MEDIUM"),
    (16, "LOW-MEDIUM"),
    (0, "LOW"),
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initialising RAGIntegrator...")
    try:
        app.state.rag = RAGIntegrator()
        logger.info("RAGIntegrator ready")
    except Exception as exc:
        logger.error("RAGIntegrator failed to initialise: %s", exc)
        app.state.rag = None
    yield
    if app.state.rag is not None:
        try:
            app.state.rag.close()
            logger.info("RAGIntegrator closed")
        except Exception as exc:
            logger.warning("RAGIntegrator close error: %s", exc)


app = FastAPI(lifespan=lifespan)
app.state.rag = None

_raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
_allowed_origins = (
    [o.strip() for o in _raw_origins.split(",") if o.strip()]
    if _raw_origins != "*"
    else ["*"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class ExceptionForm(BaseModel):
    requestor: Optional[str] = None
    department: Optional[str] = None
    exceptionType: Optional[str] = None
    reason: Optional[str] = None
    startDate: Optional[str] = None
    hostnames: Optional[str] = None
    unitHead: Optional[str] = None
    riskAssessment: Optional[str] = None
    impactedSystems: Optional[str] = None
    dataLevelStored: Optional[str] = None
    dataAccessLevel: Optional[str] = None
    vulnScanner: Optional[str] = None
    edrAllowed: Optional[str] = None
    managementAccess: Optional[str] = None
    publicIP: Optional[str] = None
    osUpToDate: Optional[str] = None
    osPatchFrequency: Optional[str] = None
    appPatchFrequency: Optional[str] = None
    localFirewall: Optional[str] = None
    networkFirewall: Optional[str] = None
    dependencyLevel: Optional[str] = None
    userImpact: Optional[str] = None
    universityImpact: Optional[str] = None
    mitigation: Optional[str] = None


class ChatMessageRequest(BaseModel):
    message: str
    sessionId: Optional[str] = None
    history: Optional[list] = None
    formData: Optional[ExceptionForm] = None


def map_form_to_scorer(form: ExceptionForm) -> dict:
    return {
        "data_stored_level": DATA_LEVEL_MAP.get(form.dataLevelStored or "", 2),
        "data_access_level": DATA_LEVEL_MAP.get(form.dataAccessLevel or "", 2),
        "allow_vulnerability_scanning": (form.vulnScanner or "").strip().lower() == "yes",
        "allow_edr_crowdstrike": (form.edrAllowed or "").strip().lower() == "yes",
        "local_firewall": FIREWALL_MAP.get(form.localFirewall or "", "minimal"),
        "network_firewall": FIREWALL_MAP.get(form.networkFirewall or "", "minimal"),
        "os_up_to_date": (form.osUpToDate or "").strip().lower() == "yes",
        "has_public_ip": (form.publicIP or "").strip().lower() == "yes",
        "management_network_access": (form.managementAccess or "").strip().lower() == "yes",
        "os_patch_frequency": PATCH_FREQ_MAP.get(form.osPatchFrequency or "", "quarterly"),
        "app_patch_frequency": PATCH_FREQ_MAP.get(form.appPatchFrequency or "", "quarterly"),
        "server_dependencies": IMPACT_MAP.get(form.dependencyLevel or "", "low"),
        "user_dependencies": IMPACT_MAP.get(form.userImpact or "", "low"),
        "university_importance": UNIVERSITY_MAP.get(form.universityImpact or "", "low"),
    }


def build_rag_request(form: ExceptionForm, scorer_data: dict, request_id: str) -> dict:
    controls = []
    if scorer_data["allow_vulnerability_scanning"]:
        controls.append("vulnerability scanning")
    if scorer_data["allow_edr_crowdstrike"]:
        controls.append("edr crowdstrike endpoint detection")
    if scorer_data["local_firewall"] == "adequate":
        controls.append("local firewall")
    if scorer_data["network_firewall"] == "adequate":
        controls.append("network firewall")
    if scorer_data["os_up_to_date"]:
        controls.append("os up to date")
    if form.mitigation:
        controls.append(form.mitigation[:200])

    return {
        "id": request_id,
        "exception_type": (form.exceptionType or "other").lower(),
        "data_level": DATA_LEVEL_ROMAN.get(scorer_data["data_stored_level"], "II"),
        "security_controls": controls,
    }


def _risk_level(score: int) -> str:
    for threshold, label in RISK_LEVEL_MAP:
        if score > threshold:
            return label
    return "LOW"


def format_reply(
    score_result: dict,
    decision: dict,
    compliance: Optional[dict],
    narrative: Optional[str],
    rag_ok: bool,
) -> str:
    total = score_result["total"]
    bd = score_result["breakdown"]
    level = _risk_level(total)

    duration = (
        f"{decision['max_duration']} days" if decision.get("max_duration") else "Not approved"
    )

    lines = [
        "SECURITY EXCEPTION REQUEST EVALUATION",
        "======================================",
        "",
        "RISK ASSESSMENT",
        f"  Score: {total}/100  |  Level: {level}",
        f"  Recommendation: {decision['recommendation']}",
        "",
        "SCORE BREAKDOWN",
        f"  Data Classification:   {bd['data_classification']}/30",
        f"  Security Controls Gap: {bd['security_controls_gap']}/35",
        f"  Network Exposure:      {bd['network_exposure']}/15",
        f"  Patch Management:      {bd['patch_management']}/10",
        f"  Impact Assessment:     {bd['impact_assessment']}/10",
        "",
        f"  Maximum Duration: {duration}",
    ]

    if decision.get("conditions"):
        lines += ["", "CONDITIONS"]
        for i, cond in enumerate(decision["conditions"], 1):
            lines.append(f"  {i}. {cond}")

    lines += ["", "POLICY COMPLIANCE"]
    if not rag_ok or compliance is None:
        lines.append("  Policy analysis unavailable (RAG service error).")
    else:
        lines.append(f"  Status: {compliance['compliance_status']}")
        if compliance.get("policy_refs"):
            lines.append(f"  Referenced Policies: {', '.join(compliance['policy_refs'])}")
        if compliance.get("violations"):
            lines.append("  Violations:")
            for v in compliance["violations"]:
                if isinstance(v, dict):
                    lines.append(f"    - {v.get('policy', '')}: {v.get('reason', '')}")
                else:
                    lines.append(f"    - {v}")
        if compliance.get("required_controls"):
            lines.append("  Required Controls:")
            for ctrl in compliance["required_controls"]:
                lines.append(f"    - {ctrl}")

    if narrative:
        lines += ["", "EXECUTIVE RISK NARRATIVE", f"  {narrative}"]

    return "\n".join(lines)


async def _chat_with_agent(message: str, form_data: Optional[dict], session_id: str) -> str:
    from services.agent_service import chat_with_form_data as agent_chat_with_form_data

    return await agent_chat_with_form_data(
        message=message,
        form_data=form_data,
        session_id=session_id,
    )


@app.post("/chat")
async def chat(form: ExceptionForm, request: Request):
    rag: Optional[RAGIntegrator] = request.app.state.rag

    scorer_data = map_form_to_scorer(form)
    score_result = calculate_risk_score(scorer_data)
    decision = make_exception_decision(score_result["total"], scorer_data)

    compliance = None
    narrative = None
    rag_ok = False

    if rag is not None:
        try:
            request_id = str(uuid.uuid4())
            rag_request = build_rag_request(form, scorer_data, request_id)
            compliance = rag.policy_compliance_checker(rag_request, top_k=6)
            narrative = rag.generate_risk_narrative(
                risk_score=score_result["total"],
                factors=score_result["breakdown"],
                policy_refs=compliance.get("policy_refs", []),
            )
            rag_ok = True
        except Exception as exc:
            logger.error("RAG pipeline error: %s", exc)

    reply = format_reply(score_result, decision, compliance, narrative, rag_ok)
    return {"reply": reply}


@app.post("/chat/message")
async def chat_message(body: ChatMessageRequest):
    form_dict = body.formData.model_dump(exclude_none=True) if body.formData else None
    session_id = body.sessionId or str(uuid.uuid4())
    try:
        reply = await _chat_with_agent(
            message=body.message,
            form_data=form_dict,
            session_id=session_id,
        )
        return {"reply": reply, "sessionId": session_id}
    except Exception as exc:
        return {"reply": f"Error processing request: {str(exc)}", "sessionId": session_id}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
