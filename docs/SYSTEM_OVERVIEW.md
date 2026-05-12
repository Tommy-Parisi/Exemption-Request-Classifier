# Security Exception Request Classifier — System Overview

## What It Does

A university IT security team receives requests from departments asking to be exempt from certain security policies (e.g., "we can't install CrowdStrike on this device" or "this server needs a public IP"). Manually reviewing every request is slow. This system automates the initial evaluation via two intake paths:

1. **Web form** — a staff member fills out a React form and submits it; the result is a structured evaluation report written to `reports/`.
2. **TDX polling** — a background process polls the TDX ticketing system for new open tickets, runs the same pipeline, and writes a report for each new ticket.

Both paths run the identical four-stage pipeline and produce the same structured text report format.

---

## Architecture

```
Browser (React form)
    │  POST /chat  (JSON)
    ▼
FastAPI server  (api/routes.py, port 8000)
    │
    ├─ 1. Risk Scorer        (engine/risk_scorer.py)      — deterministic, instant
    ├─ 2. Decision Engine    (engine/decision_engine.py)  — deterministic, instant
    ├─ 3. RAG Compliance     (engine/rag_integration.py)  — calls Gemini API + Firestore
    └─ 4. Risk Narrative     (engine/rag_integration.py)  — calls Gemini API
    │
    └─ writes report to reports/  (api/tdx.write_report)


TDX polling loop  (api/tdx.main_loop, runs as separate process)
    │  polls TDX REST API every 3600 s
    ▼
    same four-stage pipeline → writes report to reports/


Browser (React chat)
    │  POST /chat/message  (JSON)
    ▼
FastAPI server  (api/routes.py)
    │
    └─ AgentService  (services/agent_service.py)
           │
           ├─ Confidentiality Guardrail agent  (Gemini, structured output)
           ├─ IT Security Analyst Assistant    (Gemini, tool-calling)
           │       └─ search_policy_database   (Firestore RAG → local JSON fallback)
           │       └─ review_exception_response
           └─ Security Exception Reviewer      (Gemini, structured output)
```

---

## The Evaluation Pipeline

When a form is submitted (POST /chat) or a TDX ticket is processed, four steps run in sequence:

### 1. Risk Scoring (`engine/risk_scorer.py`)

A deterministic algorithm produces an **approval score** from roughly −20 to 114 across five categories. A higher score means a stronger security posture and makes the exception more likely to be approved.

| Category | Max Points | What it measures |
|---|---|---|
| Data Classification | 20 | Sensitivity of data stored and accessed (Level I/II/III) |
| Security Controls | 40 | Vulnerability scanning, EDR, local/network firewall coverage, OS up to date |
| Network Posture | 10 | Absence of public IP (+5) and management network access (+5) |
| Patch Management | 20 | OS and application patch frequency (monthly = +10 each; unavailable = −10 each) |
| Impact Assessment | 24 | Server/user dependencies and university importance |

**Decision thresholds:**
- Score > 90 → Auto-Approve
- Score 16–90 → Requires Review
- Score < 16 → Auto-Deny

### 2. Decision Engine (`engine/decision_engine.py`)

Takes the approval score and form data and outputs:
- **Recommendation**: APPROVE / REVIEW / DENY
- **Routing**: IAM, SecOps, or GRC team based on exception type
- **Conditions**: remediation requirements for review cases (e.g., "Must allow vulnerability scanning within 30 days")
- **Max duration**: 365 days for approvals, 180 days for reviews

### 3. RAG Policy Compliance Check (`engine/rag_integration.py`)

The system searches a Firestore vector database of 79+ university IT security policies using hybrid search (semantic similarity + keyword matching). The top-k matching policies are retrieved and sent to **Gemini** along with the exception request. The LLM returns:
- **Compliance status**: NON_COMPLIANT / POTENTIAL_ISSUE / COMPLIANT
- **Violations**: specific policy conflicts and reasons
- **Required controls**: compensating controls that should be in place
- **Policy refs**: IDs of the policies consulted

If Firestore or the Gemini API is unavailable, this step is skipped gracefully; the rule-based result alone is sufficient for routing.

### 4. Risk Narrative Generation (`engine/rag_integration.py`)

A second LLM call generates a concise executive narrative summarising the risk, written for a security manager audience. It incorporates the numeric score, the score breakdown, and the specific policies that were flagged.

---

## Chat Assistant (`services/agent_service.py`)

A separate endpoint (`POST /chat/message`) exposes a multi-agent chat assistant that helps users fill out the form. It is built on the OpenAI Agents SDK (pointed at Gemini via the OpenAI-compatible endpoint).

**Agents:**
- **Confidentiality Guardrail** — input guardrail; blocks passwords, keys, SSNs, and regulated identifiers before they reach the assistant.
- **IT Security Analyst Assistant** — main agent; answers questions about the form using two tools:
  - `search_policy_database` — queries Firestore RAG (falls back to local `data/data.json`).
  - `review_exception_response` — sub-call to the reviewer agent before finalizing any answer.
- **Security Exception Reviewer** — quality gate; checks drafts for accuracy, policy grounding, plain-text formatting, and brevity.

Sessions are persisted in `data/agent_sessions.sqlite3` via `GeminiSafeSession` (a sanitizing wrapper around `SQLiteSession`).

---

## TDX Integration (`api/tdx.py`)

The TDX path runs as a standalone process (`python api/tdx.py`). It:
1. Polls `GET_TICKETS` every hour for new open tickets.
2. Fetches each new ticket's fields and attachments (CSV, Excel, PDF, Word, plain text parsed and summarised).
3. Maps TDX field names to the same internal representation used by the web form.
4. Runs the identical four-stage pipeline.
5. Writes a structured `.txt` report to `reports/ticket_<id>.txt`.

A local JSON cache (`api/ticket_cache.json`) tracks which ticket IDs have already been processed to avoid duplicate evaluations.

---

## Field Mapping

The form uses plain English labels; `config.py` holds all translation maps used by both `api/routes.py` (web path) and `api/tdx.py` (TDX path).

| Form / TDX value | Internal value |
|---|---|
| "High Coverage" | `"high"` (+10 firewall score) |
| "Moderate Coverage" | `"moderate"` (+7 firewall score) |
| "Minimal Coverage" | `"minimal"` (+3 firewall score) |
| "No Coverage" | `"no"` (+0 firewall score) |
| "Monthly" | `"monthly"` (+10 patch score) |
| "Quarterly" | `"quarterly"` (+8 patch score) |
| "Yearly" | `"yearly+"` (−1 patch score) |
| "Unavailable" | `"patches unavailable"` (−10 patch score) |
| "Extensive" / "Widespread" | `"excessive"` (min impact score) |
| "Mission Critical" | `"excessive"` (max university importance score) |
| "Level I" / "Level II" / "Level III" | `1` / `2` / `3` (integer) |

---

## Key Files

| File | Role |
|---|---|
| `frontend/src/App.tsx` | React form and chat UI |
| `api/routes.py` | FastAPI app — field mapping, pipeline orchestration, response formatting |
| `api/tdx.py` | TDX polling loop, ticket processing, shared `write_report` function |
| `main.py` | Server entry point (`python main.py` → port 8000) |
| `config.py` | All env vars, mapping tables, and thresholds in one place |
| `engine/risk_scorer.py` | Deterministic approval scoring algorithm |
| `engine/decision_engine.py` | Routing and approval logic |
| `engine/rag_integration.py` | Firestore vector search + Gemini LLM calls (compliance + narrative) |
| `services/agent_service.py` | Multi-agent chat assistant (Agents SDK + Gemini) |
| `database/vector_db.py` | Seeds Firestore with policy embeddings (run once) |
| `data/data.json` | 79+ IT security policies as structured JSON (local fallback) |
| `data/agent_sessions.sqlite3` | Persisted chat session history |
| `reports/` | Output directory — one `.txt` report per form submission or TDX ticket |

---

## Running Locally

```bash
# Backend (from project root, with myvenv active)
python main.py

# TDX polling loop (separate terminal, optional)
python api/tdx.py

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

The form will be at `http://localhost:5173`. The API runs at `http://localhost:8000`.

---

## Error Handling

If the RAG system is unavailable (API key missing, Firestore unreachable, network error), the response still includes the full rule-based risk score and decision. Only the policy compliance section and narrative will be marked as unavailable. The rule-based result alone is sufficient for routing decisions.

If the Agents SDK chat assistant cannot initialize (missing `GOOGLE_API_KEY`), the `/chat/message` endpoint returns an error string; the evaluation endpoint (`/chat`) is unaffected.
