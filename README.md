# Exemption Request Classifier

A FastAPI backend that evaluates security policy exception requests. Given a completed exception request form, the system calculates a risk score, routes the request to the correct approval team, checks the request against indexed security policies via RAG (Retrieval-Augmented Generation), and returns a structured evaluation report.

---

## Architecture Overview

```
Frontend (React/Vite)
        │  POST /chat  (ExceptionForm JSON)
        ▼
api/routes.py          ← FastAPI application, CORS, lifespan
        │
        ├── engine/risk_scorer.py      ← Weighted risk score (0–100)
        ├── engine/decision_engine.py  ← Approval routing (IAM / SecOps / GRC)
        └── engine/rag_integration.py  ← Policy compliance via Firestore + Gemini
                │
                ├── database/vector_db.py   ← Firestore upsert utility (run once)
                └── services/llm_service.py ← Gemini chat assistant (form helper)
```

### Risk Score Thresholds

| Score | Decision |
|-------|----------|
| < 16 | Auto-Approve |
| 16 – 90 | Requires Review |
| > 90 | Auto-Deny |

---

## Quick Setup

### 1. Create a virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in your real API keys. See the [Environment Variables](#environment-variables) section below for a full reference. **Never commit `.env` to version control.**

### 3. Set up Google Cloud Firestore (one-time setup)

Firestore is used as the vector database for policy retrieval.

**a. Enable billing on your GCP project**

Firestore requires a billing-enabled GCP project. Contact your Google Workspace administrator to link a billing account, or visit:
```
https://console.cloud.google.com/billing/enable?project=YOUR_PROJECT_ID
```

**b. Create a Firestore database**

Visit the GCP Console and create a Firestore database:
```
https://console.cloud.google.com/datastore/setup?project=YOUR_PROJECT_ID
```
Select **Native mode**, choose a region, and leave the database ID as **`(default)`**.

Alternatively, use the Firebase Console (free Spark plan) at **console.firebase.google.com**.

**c. Create a service account and download credentials**

1. Go to **IAM & Admin → Service Accounts** in the GCP Console
2. Create a service account with the **Cloud Datastore User** role
3. Under **Keys**, click **Add Key → JSON** and download the file
4. Add to your `.env`:
   ```
   GOOGLE_APPLICATION_CREDENTIALS = /path/to/service_account.json
   ```

**d. Populate the Firestore collection (one-time)**

```bash
python database/vector_db.py
```

This reads `data/data.json`, generates embeddings via Google's `text-embedding-004` model, and writes the policy documents (with vector embeddings) into your Firestore `policies` collection. Only needs to be re-run if the policy data changes.

### 4. Start the API server

```bash
# Development (hot reload enabled when ENV=development)
ENV=development python main.py

# Production
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

The API will be available at `http://localhost:8000`.

---

## Environment Variables

All configuration is driven by environment variables. See `.env.example` for a complete template.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GOOGLE_API_KEY` | Yes | — | Google API key (general use) |
| `GOOGLE_API_KEY_2` | Yes | — | Google API key used by the chat assistant (`llm_service.py`) |
| `LLM_API_KEY` | Yes | — | Google API key for RAG embeddings |
| `LLM_API_URL` | No | Gemini 2.0 Flash endpoint | Override LLM endpoint |
| `GEMINI_CHAT_MODEL` | No | `gemini-2.5-flash` | Model used for chat responses |
| `GEMINI_EVAL_MODEL` | No | same as `GEMINI_CHAT_MODEL` | Model used for response evaluation |
| `GOOGLE_CLOUD_PROJECT` | Yes | — | GCP project ID hosting the Firestore database |
| `FIRESTORE_COLLECTION` | No | `policies` | Firestore collection name for policy documents |
| `GOOGLE_APPLICATION_CREDENTIALS` | Yes | — | Path to GCP service account JSON key file |
| `TDX_API_URL` | Yes | — | Full TeamDynamix flow API URL |
| `TDX_API_KEY` | Yes | — | TeamDynamix API key |
| `SERVER_HOST` | No | `0.0.0.0` | Host to bind when using `python main.py` |
| `SERVER_PORT` | No | `8000` | Port to bind when using `python main.py` |
| `ENV` | No | `production` | Set to `development` to enable hot reload |
| `ALLOWED_ORIGINS` | No | `http://localhost:5173,...` | Comma-separated list of allowed CORS origins |

---

## API Reference

### `POST /chat`

Evaluates a security exception request form submission.

**Request body** (`application/json`): all fields are optional strings unless noted.

| Field | Description |
|-------|-------------|
| `requestor` | Name of the person submitting the request |
| `department` | Requestor's department |
| `exceptionType` | `firewall`, `identity`, `vulnerability`, or `other` |
| `reason` | Description / justification for the exception |
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
  "reply": "<formatted evaluation report as plain text>"
}
```

---

## Project Structure

```
.
├── api/
│   ├── routes.py          # FastAPI app, endpoints, field mapping helpers
│   └── tdx.py             # TeamDynamix ticket polling and processing loop
├── database/
│   └── vector_db.py       # Firestore collection setup and data upsert utility
├── engine/
│   ├── decision_engine.py # Approval routing logic
│   ├── rag_integration.py # RAG pipeline (Firestore retrieval + Gemini generation)
│   └── risk_scorer.py     # Weighted risk score calculation
├── services/
│   └── llm_service.py     # Gemini-powered chat assistant for form guidance
├── tests/
│   └── test_rag_integration_real.py
├── data/
│   └── data.json          # Security policy documents (source for vector index)
├── config.py              # Centralised configuration (reads from env)
├── main.py                # Application entry point
├── requirements.txt
├── .env.example           # Environment variable template
└── README.md
```

---

## Testing

Run the RAG integration test suite (requires a populated Firestore collection and valid API keys):

```bash
source venv/bin/activate
python tests/test_rag_integration_real.py
```

Run the basic connectivity check:

```bash
python test_environment.py
```
