# Security Exception Request Classifier — System Overview

## What It Does

A university IT security team receives requests from departments asking to be exempt from certain security policies (e.g., "we can't install CrowdStrike on this device" or "this server needs a public IP"). Manually reviewing every request is slow. This system automates the initial evaluation: a staff member fills out a web form, submits it, and within seconds receives an AI-generated risk assessment with a routing recommendation.

---

## Architecture

```
Browser (React form)
    │  POST /chat  (JSON)
    ▼
FastAPI server  (api/routes.py, port 8000)
    │
    ├─ 1. Risk Scorer        (engine/risk_scorer.py)      — pure Python, instant
    ├─ 2. Decision Engine    (engine/decision_engine.py)  — pure Python, instant
    ├─ 3. RAG Compliance     (engine/rag_integration.py)  — calls Gemini API + Firestore
    └─ 4. Risk Narrative     (engine/rag_integration.py)  — calls Gemini API
```

---

## The Pipeline

When the form is submitted, four things happen in sequence:

### 1. Risk Scoring (`engine/risk_scorer.py`)
A deterministic algorithm scores the request from 0–100 across five categories:

| Category | Max Points | What it measures |
|---|---|---|
| Data Classification | 30 | How sensitive is the data on this system (Level I/II/III) |
| Security Controls Gap | 35 | Which security tools are missing (vuln scanning, EDR, firewall) |
| Network Exposure | 15 | Does the system have a public IP or management network access |
| Patch Management | 10 | How frequently are patches applied |
| Impact Assessment | 10 | How many systems and users depend on this asset |

**Thresholds:**
- Score < 16 → Auto-Approve
- Score 16–90 → Requires Review
- Score > 90 → Auto-Deny

### 2. Decision Engine (`engine/decision_engine.py`)
Takes the risk score and exception type, then outputs:
- **Recommendation**: APPROVE / REVIEW / DENY
- **Routing**: which team should handle the review (IAM, SecOps, or GRC)
- **Approvers required**: Unit Head + the relevant team
- **Conditions**: any remediation requirements (e.g., "must implement quarterly patching")
- **Max duration**: how long the exception can last (up to 365 days for approvals, 180 for reviews)

Routing logic:
- Identity/Access exceptions → IAM Team
- Firewall/Vulnerability exceptions → SecOps Team
- Everything else → GRC Team

### 3. RAG Policy Compliance Check (`engine/rag_integration.py`)
This is where the AI comes in. The system searches a Firestore vector database of 79+ university IT security policies using hybrid search (semantic similarity + keyword matching). The top matching policies are retrieved and sent to **Gemini 2.0 Flash** along with the exception request details. The LLM returns:
- **Compliance status**: whether the request appears compliant, non-compliant, or uncertain
- **Violations**: specific policies that may be violated and why
- **Required controls**: compensating controls that should be put in place

### 4. Risk Narrative Generation (`engine/rag_integration.py`)
A second LLM call generates a 2–3 paragraph executive summary of the risk, written for a security manager audience. It incorporates the numeric risk score, the score breakdown, and the specific policies that were flagged.

---

## Field Mapping

The form uses plain English labels ("High Coverage", "Extensive", "Level III"). The backend engines expect specific internal values. The API layer (`api/routes.py`) handles all translation:

| Form value | Internal value |
|---|---|
| "High Coverage" / "Moderate Coverage" | `"adequate"` (no firewall penalty) |
| "Minimal Coverage" | `"minimal"` (+7 risk points) |
| "No Coverage" | `"no"` (+7 risk points) |
| "Yearly" | `"yearly+"` (+8 patch risk points) |
| "Unavailable" | `"patches unavailable"` (+10 patch risk points) |
| "Extensive" / "Widespread" | `"excessive"` (max impact score) |
| "Mission Critical" | `"excessive"` (max university importance) |
| "Level III" | `3` (integer, triggers max data classification score) |

---

## Key Files

| File | Role |
|---|---|
| `frontend/src/App.tsx` | React form UI |
| `api/routes.py` | FastAPI app — field mapping, pipeline orchestration, response formatting |
| `main.py` | Server entry point (`python main.py` → runs on port 8000) |
| `engine/risk_scorer.py` | Deterministic 0–100 risk scoring algorithm |
| `engine/decision_engine.py` | Routing and approval logic |
| `engine/rag_integration.py` | Firestore vector search + Gemini LLM calls |
| `database/vector_db.py` | Loads policies into Firestore (run once to seed the DB) |
| `data/data.json` | 79+ IT security policies as structured JSON |

---

## Running Locally

```bash
# Backend (from project root, with myvenv active)
python main.py

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

The form will be at `http://localhost:5173`. The API runs at `http://localhost:8000`.

---

## Error Handling

If the RAG system is unavailable (API key missing, Firestore unreachable, network error), the response will still include the full rule-based risk score and decision. Only the policy compliance section and narrative will be marked as unavailable. The rule-based result alone is sufficient for routing decisions.
