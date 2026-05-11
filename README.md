# Exemption Request Classifier

A university IT security tool that evaluates security policy exception requests automatically. When a department submits an exception request (e.g., "we cannot install CrowdStrike on this device"), the system calculates a weighted risk score, routes the request to the correct approval team, checks it against 79+ indexed security policies via RAG (Retrieval-Augmented Generation), and returns a structured evaluation report in seconds.

The system has two intake paths:
- **Web form** — a React frontend where staff fill out and submit the form directly
- **TDX pipeline** — a background polling loop that picks up new tickets from TeamDynamix and processes them automatically

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Quick Setup](#quick-setup)
- [Environment Variables](#environment-variables)
- [Running Locally](#running-locally)
- [Running the TDX Pipeline](#running-the-tdx-pipeline)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Known Limitations](#known-limitations)
- [Future Work](#future-work)

---

## Architecture Overview

```
Browser (React/Vite form)
        │
        │  POST /chat          ← form submission → evaluation report
        │  POST /chat/message  ← conversational chat assistant
        ▼
api/routes.py            ← FastAPI app, CORS, request routing
        │
        ├── engine/risk_scorer.py      ← weighted risk score (0–114, can go negative)
        ├── engine/decision_engine.py  ← approval routing (IAM / SecOps / GRC)
        └── engine/rag_integration.py  ← policy compliance via Firestore + Gemini
                │
                ├── database/vector_db.py      ← one-time Firestore seeding utility
                └── services/agent_service.py  ← Agents SDK chatbot (Gemini-backed)

api/tdx.py               ← independent TDX polling loop (run separately)
```

### Risk Score Thresholds

The scoring model is an *approval* model: a higher score means a stronger security posture, which increases the likelihood of approval.

| Score | Decision |
|-------|----------|
| > 90 | Auto-Approve |
| 16 – 90 | Requires Review |
| < 16 | Auto-Deny |

### Score Breakdown (max points per category)

| Category | Max Points | What it measures |
|---|---|---|
| Data Classification | 20 | Sensitivity of data stored and accessed (Level I/II/III) |
| Security Controls | 40 | Vuln scanning, EDR, local/network firewall, OS patch status |
| Network Posture | 10 | Absence of public IP and management network access |
| Patch Management | 20 | OS and app patch frequency (can be negative for missing patches) |
| Impact Assessment | 24 | Server/user dependencies and university criticality |

---

## Quick Setup

### 1. Clone and create a virtual environment

```bash
git clone <repo-url>
cd Exemption-Request-Classifier
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in your values. See [Environment Variables](#environment-variables) for the full reference. **Never commit `.env` or any service account JSON key to version control.**

### 3. Set up Google Cloud Firestore (one-time)

Firestore stores the vectorized security policy documents that power the RAG compliance check.

**a. Enable billing on your GCP project**

Firestore requires a billing-enabled GCP project (or use the Firebase Spark free tier):

```
https://console.cloud.google.com/billing/enable?project=YOUR_PROJECT_ID
```

**b. Create a Firestore database**

Visit the GCP Console and create a Firestore database in **Native mode**:

```
https://console.cloud.google.com/datastore/setup?project=YOUR_PROJECT_ID
```

Leave the database ID as **`policies`** (matches the default in `.env.example`) and pick a nearby region.

**c. Create a service account and download credentials**

1. Go to **IAM & Admin → Service Accounts** in the GCP Console
2. Create a service account with the **Cloud Datastore User** role
3. Under **Keys**, click **Add Key → JSON** and save the downloaded file somewhere outside the repo
4. Add the path to `.env`:
   ```
   GOOGLE_APPLICATION_CREDENTIALS=/path/to/your-service-account.json
   ```

**d. Seed the Firestore collection (one-time)**

```bash
python database/vector_db.py
```

This reads `data/data.json` (79 university security policies), generates 768-dimensional embeddings via Google's `gemini-embedding-001` model, and writes them into the Firestore `policies` collection. Re-run only if the policy data changes.

### 4. Install frontend dependencies

```bash
cd frontend
npm install
cd ..
```

---

## Environment Variables

All configuration is driven by environment variables. Copy `.env.example` to `.env` and fill in real values.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GOOGLE_API_KEY` | Yes | — | Google Gemini API key (chat assistant + RAG) |
| `LLM_API_KEY` | No | falls back to `GOOGLE_API_KEY` | Optional separate key for RAG embeddings/LLM calls |
| `LLM_API_URL` | No | Gemini 2.0 Flash endpoint | Override LLM endpoint |
| `GEMINI_CHAT_MODEL` | No | `gemini-2.5-flash` | Model for the chat assistant |
| `GEMINI_REVIEW_MODEL` | No | same as `GEMINI_CHAT_MODEL` | Model for internal response quality review |
| `GOOGLE_CLOUD_PROJECT` | Yes | — | GCP project ID hosting the Firestore database |
| `FIRESTORE_DATABASE` | No | `policies` | Firestore database ID |
| `FIRESTORE_COLLECTION` | No | `policies` | Firestore collection name for policy documents |
| `GOOGLE_APPLICATION_CREDENTIALS` | Yes | — | Path to GCP service account JSON key file |
| `TDX_API_URL` | Yes (TDX only) | — | Full TeamDynamix flow API URL |
| `TDX_API_KEY` | Yes (TDX only) | — | TeamDynamix API key |
| `SERVER_HOST` | No | `0.0.0.0` | Host to bind when using `python main.py` |
| `SERVER_PORT` | No | `8000` | Port to bind when using `python main.py` |
| `ENV` | No | `production` | Set to `development` to enable hot reload |
| `ALLOWED_ORIGINS` | No | `http://localhost:5173,http://localhost:4173` | Comma-separated allowed CORS origins |
| `VITE_API_URL` | No | `http://localhost:8000` | Frontend env variable — set in `frontend/.env` |

---

## Running Locally

### Backend

```bash
# Development mode (hot reload)
make dev
# or: ENV=development python main.py

# Production mode
make run
# or: uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

The API will be available at `http://localhost:8000`. Visit `/health` to confirm it is running.

### Frontend

```bash
cd frontend
npm run dev
```

The form will be available at `http://localhost:5173`.

### Verify services before starting

```bash
python test_environment.py
```

This checks that all required API keys and services are reachable before you start the server.

### End-to-end pipeline demo (no frontend required)

```bash
python end_to_end_demo.py
```

Submits a synthetic exception request through the full pipeline and prints the evaluation report.

---

## Running the TDX Pipeline

The TDX polling loop runs as a **separate process** independent of the web server. It polls TeamDynamix every hour for new open tickets, extracts the form fields, runs the full evaluation pipeline, and writes per-ticket reports to the `reports/` directory.

```bash
make tdx
# or: python api/tdx.py
```

**Requirements:** `TDX_API_URL` and `TDX_API_KEY` must be set in `.env`.

**How it works:**
1. Fetches all open TDX tickets via the configured flow API
2. Compares against `api/ticket_cache.json` to find new ticket IDs
3. For each new ticket: retrieves full ticket data, extracts attachments (PDF, Word, CSV, Excel, text), runs risk scoring + decision engine + RAG, writes a report to `reports/ticket_<id>.txt`
4. Sleeps for one hour, then repeats

Processed ticket IDs are cached so they are not reprocessed on subsequent runs. The cache is stored in `api/ticket_cache.json` (gitignored). Attachment files are saved to `attachments/<ticket_id>/` (also gitignored).

---

## API Reference

### `POST /chat` — Evaluate Exception Request Form

Accepts a completed exception form and returns a full evaluation report.

**Request body** (`application/json`): all fields are optional strings.

| Field | Description |
|-------|-------------|
| `requestor` | Name of the person submitting the request |
| `department` | Requestor's department |
| `exceptionType` | `firewall`, `identity`, `vulnerability`, or `other` |
| `reason` | Description / justification for the exception |
| `startDate` | Exception start date |
| `hostnames` | Hostnames of affected systems |
| `unitHead` | Name of the unit head approving the request |
| `riskAssessment` | Requestor's own risk assessment justification |
| `impactedSystems` | Impacted systems, services, and data |
| `dataLevelStored` | `Level I`, `Level II`, or `Level III` |
| `dataAccessLevel` | `Level I`, `Level II`, or `Level III` |
| `vulnScanner` | `yes` / `no` |
| `edrAllowed` | `yes` / `no` |
| `localFirewall` | `High Coverage`, `Moderate Coverage`, `Minimal Coverage`, or `No Coverage` |
| `networkFirewall` | Same options as `localFirewall` |
| `osUpToDate` | `yes` / `no` |
| `osPatchFrequency` | `Monthly`, `Quarterly`, `Every 3-6 months`, `Every 6-12 months`, `Yearly`, or `Unavailable` |
| `appPatchFrequency` | Same options as `osPatchFrequency` |
| `publicIP` | `yes` / `no` |
| `managementAccess` | `yes` / `no` |
| `dependencyLevel` | `Low`, `Moderate`, `Extensive`, or `Widespread` |
| `userImpact` | Same options as `dependencyLevel` |
| `universityImpact` | `Non-Critical`, `Critical`, or `Mission Critical` |
| `mitigation` | Free-text description of compensating controls |

**Response** (`application/json`):

```json
{
  "reply": "<formatted plain-text evaluation report>"
}
```

---

### `POST /chat/message` — Chat Assistant

Sends a conversational message to the AI assistant. The assistant has access to the current form state and the full policy database, and maintains session history via SQLite.

**Request body** (`application/json`):

| Field | Type | Description |
|-------|------|-------------|
| `message` | string (required) | The user's message |
| `sessionId` | string (optional) | Session ID for conversation continuity; generated if not provided |
| `formData` | object (optional) | Current form values (same fields as `/chat`); injected into assistant context |

**Response** (`application/json`):

```json
{
  "reply": "<assistant response as plain text>",
  "sessionId": "<session id>"
}
```

The assistant is built on the OpenAI Agents SDK with a Gemini backend. It uses three internal agents:
- **Guardrail agent** — blocks requests containing real secrets (API keys, SSNs, passwords)
- **Reviewer agent** — quality-checks the assistant's draft response before it is sent
- **Assistant agent** — answers questions, searches the policy database, and helps the user fill out the form

---

### `GET /health`

Returns `{"status": "healthy"}`. Use this to confirm the server is running.

---

## Project Structure

```
.
├── api/
│   ├── routes.py          # FastAPI app, all HTTP endpoints, field mapping helpers
│   └── tdx.py             # TeamDynamix ticket polling loop (run separately)
├── database/
│   └── vector_db.py       # One-time Firestore seeding utility
├── docs/
│   ├── SYSTEM_OVERVIEW.md         # Plain-language architecture explanation
│   └── RAG_SYSTEM_ARCHITECTURE.md # Deep-dive on the RAG pipeline
├── engine/
│   ├── risk_scorer.py     # Deterministic 0–114 approval scoring algorithm
│   ├── decision_engine.py # Approval routing and condition logic
│   └── rag_integration.py # Firestore hybrid search + Gemini LLM calls
├── frontend/
│   └── src/App.tsx        # React/Vite form UI and chat panel
├── services/
│   └── agent_service.py   # Agents SDK chatbot with guardrail and reviewer agents
├── tests/
│   ├── conftest.py        # Shared test fixtures (min/max/review-band forms)
│   ├── test_risk_scorer.py       # Unit tests for the scoring algorithm
│   ├── test_decision_engine.py   # Unit tests for approval routing
│   ├── test_config.py            # Unit tests for field mapping tables
│   └── test_edge_cases.py        # Edge case coverage
├── data/
│   └── data.json          # 79 university IT security policies (source for vector index)
├── config.py              # Centralised configuration (reads from env)
├── main.py                # Application entry point
├── Makefile               # Common dev commands (make dev, make test, make tdx, etc.)
├── requirements.txt       # Python dependencies
├── .env.example           # Environment variable template (copy to .env)
└── test_environment.py    # Pre-flight connectivity check
```

---

## Testing

Run the full unit test suite (no external services required):

```bash
make test
# or: python -m pytest tests/ -v
```

Run tests with coverage report:

```bash
make test-cov
# or: python -m pytest tests/ -v --cov=engine --cov=config --cov-report=term-missing
```

The test suite covers the risk scorer, decision engine, and config mapping tables with parametrized boundary tests and ground-truth cases derived from real TDX tickets. All tests run offline — no API keys or Firestore connection needed.

---

## Known Limitations

**RAG degradation:** If Firestore is unreachable or the Google API key is missing, the evaluation report will still include the full rule-based risk score and routing decision. Only the Policy Compliance and Executive Narrative sections will be marked unavailable. The rule-based result alone is sufficient for routing.

**No write-back to TDX:** The TDX polling loop reads tickets and writes local report files, but does not post results back to TDX or update ticket status. A human must review the report and act on it in TDX manually.

**Single-tenant:** There is no authentication or multi-tenant support. The API and frontend are designed for internal network use. Exposing the API publicly without adding authentication would allow anyone to submit requests and access the chat assistant.

**Agent session storage is local:** Chat session history is stored in `data/agent_sessions.sqlite3`. If the server is restarted or deployed to a new machine, existing session history is lost unless the file is migrated.

**Attachment storage is local:** TDX attachments are decoded and saved to `attachments/<ticket_id>/` on the server's local filesystem. There is no cloud storage backend; disk space should be monitored in long-running deployments.

**Gemini model names may change:** The model IDs configured in `.env` (e.g., `gemini-2.5-flash`, `gemini-embedding-001`) are subject to deprecation by Google. Check the Google AI Studio documentation if API calls begin failing with model-not-found errors.

**No file attachment processing in the web form:** The frontend accepts a file attachment field, but the `/chat` endpoint does not process attached files. Attachment processing is only implemented in the TDX pipeline (`api/tdx.py`).

---

## Future Work

**TDX write-back:** Post evaluation results directly back to TDX as ticket comments or status updates, eliminating the need for manual review of local report files.

**Authentication:** Add API key or SSO authentication (e.g., UD CAS) to both the frontend and the API so that only authorized staff can submit requests.

**Admin dashboard:** A simple read-only admin view showing all processed requests, scores, decisions, and policy references — searchable by requestor, department, or date range.

**Re-indexing workflow:** Currently, updating the policy corpus requires manually re-running `database/vector_db.py`. A scheduled or webhook-triggered re-index would keep the policy database current as UD security policies evolve.

**Cloud session storage:** Replace the SQLite session database with a cloud-backed store (e.g., Firestore or Redis) so chat history survives server restarts and scales across multiple API instances.

**Expanded file type support:** The TDX pipeline handles PDF, Word, CSV, Excel, and plain text attachments. Images are saved but not analyzed. Adding OCR or vision model support for image-based attachments would improve coverage.

**Structured output to TDX:** Map the evaluation report fields back into TDX ticket attributes so the risk score and routing decision appear directly in the TDX ticket view without requiring staff to open a separate report file.

**Rate limiting:** Add rate limiting to the `/chat` and `/chat/message` endpoints to prevent runaway Gemini API costs from automated or accidental bulk submissions.
