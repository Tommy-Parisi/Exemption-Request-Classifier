from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from agents import (
    Agent,
    GuardrailFunctionOutput,
    ModelSettings,
    RunConfig,
    RunContextWrapper,
    Runner,
    SQLiteSession,
    SessionSettings,
    function_tool,
    input_guardrail,
)
from agents.exceptions import InputGuardrailTripwireTriggered
from agents.models.openai_provider import OpenAIProvider
from dotenv import load_dotenv
from openai.types.shared import Reasoning
from pydantic import BaseModel, Field
from pypdf import PdfReader

from engine.rag_integration import PolicyMatch, RAGIntegrator

load_dotenv(override=True)

logger = logging.getLogger(__name__)

DEFAULT_GOOGLE_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
DEFAULT_MAIN_MODEL = "gpt-4.1-mini"
DEFAULT_REVIEW_MODEL = "gpt-4.1-mini"
DEFAULT_GOOGLE_MODEL = "gemini-2.5-flash"

CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent
SECURITY_DATA_DIR = CURRENT_DIR / "security_data"
PDF_PATH = SECURITY_DATA_DIR / "UD.pdf"
SUMMARY_PATH = SECURITY_DATA_DIR / "summary.txt"
LOCAL_POLICY_PATH = REPO_ROOT / "data" / "data.json"
SESSION_DB_PATH = REPO_ROOT / "data" / "agent_sessions.sqlite3"

FIELD_LABELS = {
    "requestor": "Requestor",
    "department": "Department",
    "exceptionType": "Type of Exception",
    "reason": "Reason for Request",
    "startDate": "Exception Start Date",
    "hostnames": "Hostnames",
    "unitHead": "Unit Head",
    "riskAssessment": "Risk Assessment Justification",
    "impactedSystems": "Impacted Systems, Services and Data",
    "dataLevelStored": "Level of Data Stored on System",
    "dataAccessLevel": "Level of Data the Device has Access to",
    "vulnScanner": "Allow Vulnerability Scanning Agent on Client",
    "edrAllowed": "Allow EDR (Crowdstrike on Client)",
    "managementAccess": "Does system have access to management network",
    "publicIP": "Does this machine have a public IP address",
    "osUpToDate": "Is the OS up to date with the latest patch",
    "osPatchFrequency": "How often are OS patches installed",
    "appPatchFrequency": "How often are application patches installed",
    "localFirewall": "Local Firewall Rules",
    "networkFirewall": "Network Firewall Rules",
    "dependencyLevel": "How many assets or servers depend on this asset",
    "userImpact": "How many users are impacted by this asset",
    "universityImpact": "How important is this asset to the University as a whole",
    "mitigation": "Additional mitigation tools or techniques",
}

STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "has",
    "have",
    "how",
    "i",
    "if",
    "in",
    "is",
    "it",
    "me",
    "my",
    "of",
    "on",
    "or",
    "our",
    "please",
    "should",
    "that",
    "the",
    "their",
    "this",
    "to",
    "us",
    "we",
    "what",
    "when",
    "with",
    "you",
    "your",
}


def _read_pdf_text(path: Path) -> str:
    if not path.exists():
        logger.warning("Security PDF missing at %s", path)
        return ""

    reader = PdfReader(str(path))
    parts: list[str] = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            parts.append(text)
    return "\n".join(parts)


def _read_text_file(path: Path) -> str:
    if not path.exists():
        logger.warning("Text file missing at %s", path)
        return ""
    return path.read_text(encoding="utf-8").strip()


SECURITY_FORM_TEXT = _read_pdf_text(PDF_PATH)
SUMMARY_TEXT = _read_text_file(SUMMARY_PATH)


def format_form_data(form_data: Optional[dict[str, Any]]) -> str:
    if not form_data:
        return "No form fields have been provided yet."

    lines = []
    for key, value in form_data.items():
        if value and str(value).strip():
            lines.append(f"- {FIELD_LABELS.get(key, key)}: {value}")

    return "\n".join(lines) if lines else "No form fields have been provided yet."


def _extract_input_text(agent_input: str | list[Any]) -> str:
    if isinstance(agent_input, str):
        return agent_input

    parts: list[str] = []
    for item in agent_input:
        if isinstance(item, dict):
            content = item.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        parts.append(str(part.get("text") or ""))
        else:
            parts.append(str(item))
    return "\n".join(parts)


class ConfidentialityCheck(BaseModel):
    is_confidential: bool
    confidential_data: list[str] = Field(default_factory=list)
    safe_response: str


class ReviewDecision(BaseModel):
    approved: bool
    feedback: str
    missing_points: list[str] = Field(default_factory=list)


class PolicyDatabase:
    def __init__(self) -> None:
        self.records = self._load_local_records()
        self.rag: Optional[RAGIntegrator] = None
        try:
            self.rag = RAGIntegrator()
        except Exception as exc:
            logger.warning(
                "Unable to initialize Firestore RAG policy database; using local fallback: %s",
                exc,
            )

    def _load_local_records(self) -> list[dict[str, Any]]:
        if not LOCAL_POLICY_PATH.exists():
            logger.warning("Local policy dataset missing at %s", LOCAL_POLICY_PATH)
            return []

        try:
            data = json.loads(LOCAL_POLICY_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.warning("Unable to parse local policy data: %s", exc)
            return []

        if not isinstance(data, list):
            logger.warning("Local policy data is not a list.")
            return []
        return data

    def search(self, query: str, top_k: int = 4) -> list[dict[str, Any]]:
        cleaned_query = (query or "").strip()
        if not cleaned_query:
            return []

        if self.rag is not None:
            try:
                results = self._search_firestore(cleaned_query, top_k)
                if results:
                    return results
            except Exception as exc:
                logger.warning("Firestore RAG search failed, falling back to local search: %s", exc)

        return self._search_local(cleaned_query, top_k)

    def _search_firestore(self, query: str, top_k: int) -> list[dict[str, Any]]:
        if self.rag is None:
            return []

        keywords = [
            token
            for token in re.findall(r"[a-zA-Z0-9]+", query.lower())
            if len(token) > 2 and token not in STOP_WORDS
        ][:8]
        matches = self.rag.hybrid_search(query=query, top_k=top_k, keywords=keywords)
        return [self._normalize_firestore_match(match) for match in matches]

    def _normalize_firestore_match(self, match: PolicyMatch) -> dict[str, Any]:
        metadata = match.metadata or {}
        requirements = metadata.get("requirements") or metadata.get("required_controls") or []
        if isinstance(requirements, str):
            requirements = [requirements]

        classification_levels = metadata.get("classification_levels") or []
        if isinstance(classification_levels, str):
            classification_levels = [classification_levels]

        return {
            "control_id": metadata.get("control_id") or metadata.get("_id") or match.id,
            "risk_area": metadata.get("risk_area") or metadata.get("category"),
            "requirements": requirements,
            "note": metadata.get("note") or metadata.get("summary"),
            "references": metadata.get("references") or metadata.get("nist_reference"),
            "page_number": metadata.get("page_number"),
            "requires_approval": metadata.get("requires_approval"),
            "approver_role": metadata.get("approver_role"),
            "classification_levels": classification_levels,
            "is_exception_related": metadata.get("is_exception_related"),
            "chunk_text": match.text or metadata.get("chunk_text"),
            "score": round(match.score, 3),
            "source": "firestore",
        }

    def _search_local(self, query: str, top_k: int) -> list[dict[str, Any]]:
        query_tokens = [
            token
            for token in re.findall(r"[a-zA-Z0-9]+", query.lower())
            if len(token) > 2 and token not in STOP_WORDS
        ]
        if not query_tokens:
            return []

        scored_records: list[tuple[float, dict[str, Any]]] = []
        for record in self.records:
            searchable_text = " ".join(
                [
                    str(record.get("_id", "")),
                    str(record.get("control_id", "")),
                    str(record.get("risk_area", "")),
                    str(record.get("nist_reference", "")),
                    str(record.get("note", "")),
                    str(record.get("references", "")),
                    " ".join(record.get("requirements", []) or []),
                    " ".join(record.get("classification_levels", []) or []),
                ]
            ).lower()

            matched_tokens = 0
            score = 0.0
            for token in query_tokens:
                if token in searchable_text:
                    matched_tokens += 1
                    score += 2.0
                    if token in str(record.get("control_id", "")).lower():
                        score += 3.0

            if matched_tokens == 0:
                continue

            if record.get("is_exception_related"):
                score += 1.0
            if "exception" in query.lower() and record.get("is_exception_related"):
                score += 2.0
            if "approval" in query.lower() and record.get("requires_approval"):
                score += 1.0

            score += matched_tokens / max(len(query_tokens), 1)
            scored_records.append((score, record))

        scored_records.sort(key=lambda item: item[0], reverse=True)
        return [
            {
                **record,
                "score": round(score, 3),
                "source": "local_json",
            }
            for score, record in scored_records[:top_k]
        ]

    def format_results(self, results: list[dict[str, Any]]) -> str:
        if not results:
            return "No policy matches were found in the available database."

        sections: list[str] = []
        for idx, result in enumerate(results, start=1):
            requirements = result.get("requirements") or []
            requirement_lines = [f"  - {requirement}" for requirement in requirements[:3] if requirement]
            if not requirement_lines and result.get("chunk_text"):
                requirement_lines.append(f"  - {result['chunk_text']}")

            approval_summary = "No explicit approval listed"
            if result.get("requires_approval"):
                approval_summary = f"Approval required: {result.get('approver_role') or 'approval required'}"

            sections.append(
                "\n".join(
                    [
                        f"{idx}. Control {result.get('control_id') or result.get('_id')}",
                        f"   Source: {result.get('source', 'unknown')}",
                        f"   Risk area: {result.get('risk_area') or 'Not specified'}",
                        f"   Page: {result.get('page_number') or 'Unknown'}",
                        f"   Exception related: {bool(result.get('is_exception_related'))}",
                        f"   {approval_summary}",
                        f"   Classification levels: {', '.join(result.get('classification_levels') or []) or 'Not specified'}",
                        "   Key requirements:",
                        *(requirement_lines or ["  - No requirement text available"]),
                        f"   Note: {result.get('note') or 'None provided'}",
                        f"   References: {result.get('references') or 'None provided'}",
                    ]
                )
            )
        return "\n\n".join(sections)


@dataclass
class AgentContext:
    service: "AgentService"
    form_data: dict[str, Any] = field(default_factory=dict)
    session_id: str = ""


def _assistant_instructions(ctx: RunContextWrapper[AgentContext], agent: Agent[AgentContext]) -> str:
    del agent
    return (
        "You are a professional senior IT security analyst at the University of Delaware. "
        "Help the user complete, review, and improve a security exception request. "
        "The Agents SDK session already contains the conversation history, so use that memory instead of asking the user to repeat prior context. "
        "Rely on the current form data and policy database tools for specifics. "
        "Use `search_policy_database` whenever you need policy requirements, approvals, controls, or exemption guidance. "
        "Before you send any final answer, always call `review_exception_response` on your planned draft and revise if it finds issues. "
        "Do not invent policy details. Cite relevant control IDs in plain text when policy data is available. "
        "If important fields are missing, say which ones matter most and why.\n\n"
        "Current form data:\n"
        f"{format_form_data(ctx.context.form_data)}\n\n"
        "Security form summary:\n"
        f"{SUMMARY_TEXT or 'No summary available.'}\n\n"
        "Security form reference text:\n"
        f"{SECURITY_FORM_TEXT or 'No PDF text available.'}"
    )


def _guardrail_instructions(ctx: RunContextWrapper[AgentContext], agent: Agent[AgentContext]) -> str:
    del agent
    return (
        "You review user input for clearly sensitive material that should not be processed in this assistant. "
        "Only flag passwords, API keys, private keys, tokens, secrets, SSNs, financial account numbers, or similarly regulated identifiers. "
        "Do not flag ordinary exception-request fields like hostnames, departments, system descriptions, unit heads, or mitigations unless they include a real secret. "
        "Return a safe_response that asks the user to redact the sensitive content without repeating it.\n\n"
        "Current form data:\n"
        f"{format_form_data(ctx.context.form_data)}"
    )


def _reviewer_instructions(ctx: RunContextWrapper[AgentContext], agent: Agent[AgentContext]) -> str:
    del agent
    return (
        "You are the quality reviewer for a University of Delaware security exception assistant. "
        "Review the proposed answer for accuracy, policy grounding, completeness, and safety. "
        "Reject answers that invent policy, skip obvious missing fields, or fail to answer the user's request. "
        "If the answer is acceptable, approve it briefly. If not, give concrete feedback and list missing points.\n\n"
        "Current form data:\n"
        f"{format_form_data(ctx.context.form_data)}"
    )


@function_tool
async def search_policy_database(
    ctx: RunContextWrapper[AgentContext],
    query: str,
    top_k: int = 4,
) -> str:
    results = ctx.context.service.database.search(query, top_k=top_k)
    return ctx.context.service.database.format_results(results)


@function_tool
async def review_exception_response(
    ctx: RunContextWrapper[AgentContext],
    user_request: str,
    draft_answer: str,
) -> str:
    service = ctx.context.service
    service._ensure_initialized()
    assert service.reviewer_agent is not None
    assert service.run_config is not None
    review_prompt = (
        "User request:\n"
        f"{user_request}\n\n"
        "Draft answer to review:\n"
        f"{draft_answer}"
    )
    result = await Runner.run(
        service.reviewer_agent,
        review_prompt,
        context=ctx.context,
        run_config=service.run_config,
        max_turns=3,
    )
    review = result.final_output_as(ReviewDecision, raise_if_incorrect_type=True)
    status = "APPROVED" if review.approved else "REVISE"
    missing_points = ", ".join(review.missing_points) if review.missing_points else "None"
    return f"{status}\nFeedback: {review.feedback}\nMissing points: {missing_points}"


@input_guardrail(run_in_parallel=False)
async def confidentiality_guardrail(
    ctx: RunContextWrapper[AgentContext],
    agent: Agent[Any],
    agent_input: str | list[Any],
) -> GuardrailFunctionOutput:
    del agent
    service = ctx.context.service
    service._ensure_initialized()
    assert service.guardrail_agent is not None
    assert service.run_config is not None
    input_text = _extract_input_text(agent_input)
    result = await Runner.run(
        service.guardrail_agent,
        input_text,
        context=ctx.context,
        run_config=service.run_config,
        max_turns=2,
    )
    review = result.final_output_as(ConfidentialityCheck, raise_if_incorrect_type=True)
    return GuardrailFunctionOutput(
        output_info={
            "confidential_data": review.confidential_data,
            "safe_response": review.safe_response,
        },
        tripwire_triggered=review.is_confidential,
    )


class AgentService:
    def __init__(self) -> None:
        self.database = PolicyDatabase()
        self.main_model: Optional[str] = None
        self.review_model: Optional[str] = None
        self.model_provider: Optional[OpenAIProvider] = None
        self.run_config: Optional[RunConfig] = None
        self.guardrail_agent: Optional[Agent[AgentContext]] = None
        self.reviewer_agent: Optional[Agent[AgentContext]] = None
        self.assistant_agent: Optional[Agent[AgentContext]] = None

    def _ensure_initialized(self) -> None:
        if self.assistant_agent is not None:
            return

        self.main_model, self.review_model, self.model_provider = self._build_model_provider()
        self.run_config = RunConfig(
            model_provider=self.model_provider,
            session_settings=SessionSettings(limit=40),
        )
        self.guardrail_agent = Agent[AgentContext](
            name="Confidentiality Guardrail",
            instructions=_guardrail_instructions,
            model=self.review_model,
            model_settings=ModelSettings(temperature=0),
            output_type=ConfidentialityCheck,
        )
        self.reviewer_agent = Agent[AgentContext](
            name="Security Exception Reviewer",
            instructions=_reviewer_instructions,
            model=self.review_model,
            model_settings=ModelSettings(temperature=0),
            output_type=ReviewDecision,
        )
        self.assistant_agent = Agent[AgentContext](
            name="IT Security Analyst Assistant",
            instructions=_assistant_instructions,
            model=self.main_model,
            tools=[search_policy_database, review_exception_response],
            input_guardrails=[confidentiality_guardrail],
            model_settings=ModelSettings(reasoning=Reasoning(effort="low"), temperature=0.2),
        )

    def _build_model_provider(self) -> tuple[str, str, OpenAIProvider]:
        openai_key = os.getenv("OPENAI_API_KEY")
        openai_base_url = os.getenv("OPENAI_BASE_URL")
        google_key = os.getenv("GOOGLE_API_KEY")

        if openai_key:
            return (
                os.getenv("AGENT_MAIN_MODEL", DEFAULT_MAIN_MODEL),
                os.getenv("AGENT_REVIEW_MODEL", DEFAULT_REVIEW_MODEL),
                OpenAIProvider(api_key=openai_key, base_url=openai_base_url or None),
            )

        if google_key:
            google_model = os.getenv("GEMINI_CHAT_MODEL", DEFAULT_GOOGLE_MODEL)
            return (
                os.getenv("AGENT_MAIN_MODEL", google_model),
                os.getenv("AGENT_REVIEW_MODEL", google_model),
                OpenAIProvider(
                    api_key=google_key,
                    base_url=os.getenv("GOOGLE_OPENAI_BASE_URL", DEFAULT_GOOGLE_BASE_URL),
                    use_responses=False,
                ),
            )

        raise ValueError(
            "No LLM credentials found. Set OPENAI_API_KEY or GOOGLE_API_KEY."
        )

    def _get_session(self, session_id: str) -> SQLiteSession:
        SESSION_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        return SQLiteSession(session_id=session_id, db_path=SESSION_DB_PATH)

    async def chat_with_form_data(
        self,
        *,
        message: str,
        form_data: Optional[dict[str, Any]] = None,
        session_id: str,
    ) -> str:
        self._ensure_initialized()
        assert self.assistant_agent is not None
        assert self.run_config is not None
        context = AgentContext(
            service=self,
            form_data=form_data or {},
            session_id=session_id,
        )
        session = self._get_session(session_id)

        try:
            result = await Runner.run(
                self.assistant_agent,
                message,
                context=context,
                session=session,
                run_config=self.run_config,
                max_turns=8,
            )
            return str(result.final_output).strip()
        except InputGuardrailTripwireTriggered as exc:
            output_info = exc.guardrail_result.output.output_info or {}
            safe_response = str(output_info.get("safe_response") or "").strip()
            if safe_response:
                return safe_response
            return (
                "I found potentially sensitive information in your request. "
                "Please redact secrets or regulated data and resend a sanitized version."
            )

    async def chat(self, *, message: str, session_id: str) -> str:
        return await self.chat_with_form_data(
            message=message,
            form_data=None,
            session_id=session_id,
        )


agent_service = AgentService()


async def chat_with_form_data(
    *,
    message: str,
    form_data: Optional[dict[str, Any]] = None,
    session_id: str,
) -> str:
    return await agent_service.chat_with_form_data(
        message=message,
        form_data=form_data,
        session_id=session_id,
    )


async def chat(*, message: str, session_id: str) -> str:
    return await agent_service.chat(message=message, session_id=session_id)
