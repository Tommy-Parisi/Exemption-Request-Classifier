# RAG System Architecture: Security Exception Request Processing

## Overview

The Retrieval-Augmented Generation (RAG) system provides policy compliance checking and executive risk narrative generation for the Security Exception Request Classifier. It combines semantic vector search across university IT security policies (stored in Firestore) with LLM analysis (Google Gemini) to produce structured compliance assessments and plain-English risk summaries.

The RAG system is used in two contexts:
- **Evaluation pipeline** — `engine/rag_integration.py` (`RAGIntegrator`) is called by both `api/routes.py` and `api/tdx.py` during request evaluation.
- **Chat assistant** — `services/agent_service.py` (`PolicyDatabase`) wraps `RAGIntegrator` for policy lookups during form-filling assistance.

---

## System Components

### Core Infrastructure
- **Vector Database**: Google Cloud Firestore (native vector search via `find_nearest`)
- **Embedding Model**: Google `gemini-embedding-001` (768-dimensional vectors, `RETRIEVAL_QUERY` task type)
- **LLM**: Google Gemini (model configured via `LLM_API_URL` env var; defaults to `gemini-2.0-flash`)
- **Policy Corpus**: 79+ university IT security policies stored as chunked documents with NIST references
- **Embedding Cache**: `shelve`-backed disk cache (`.rag_cache`) with 6-hour TTL — avoids redundant embedding API calls
- **Policy Memory Cache**: in-process dict cache of `PolicyMatch` objects with 6-hour TTL

### Key Classes

| Class / Module | Location | Purpose |
|---|---|---|
| `RAGIntegrator` | `engine/rag_integration.py` | Firestore connection, embedding generation, hybrid search, LLM calls |
| `PolicyMatch` | `engine/rag_integration.py` | Dataclass: `id`, `score`, `metadata`, `text` |
| `PolicyDatabase` | `services/agent_service.py` | Wraps `RAGIntegrator` for chat tool use; falls back to local JSON |

---

## Complete RAG Pipeline

### Phase 1: Data Ingestion & Indexing (one-time setup)

```
Policy JSON → Text Chunking → Embedding Generation → Firestore Storage
```

Run `database/vector_db.py` once to seed Firestore. Each policy chunk is stored as a Firestore document with:
- `chunk_text` — the policy text
- `embedding` — 768-dimensional float vector
- Metadata fields: `control_id`, `risk_area`, `nist_reference`, `category`, `classification_levels`, `is_exception_related`, `requires_approval`, `approver_role`, etc.

The local copy of all policies is also maintained as `data/data.json` and serves as a fallback.

---

### Phase 2: Exception Request Evaluation (runtime)

#### Step 2.1 — Embedding Generation

**Function**: `RAGIntegrator._get_embedding(text: str) → List[float]`

1. Check shelve cache; return cached vector if fresh (< 6 h old).
2. POST to `https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-001:embedContent` with `RETRIEVAL_QUERY` task type.
3. Validate that the returned vector has exactly 768 dimensions.
4. Save to shelve cache and return.
5. If the API call fails and no cached vector exists, raise `RuntimeError` — no pseudo-random fallback is used (garbage results are worse than a hard failure).

---

#### Step 2.2 — Hybrid Search

**Function**: `RAGIntegrator.hybrid_search(query, top_k, metadata_filter, keywords) → List[PolicyMatch]`

```
Query text → Embedding → Firestore vector search (semantic)
                       ↘ keyword scan of in-process policy cache
                         → merge + rank → top_k PolicyMatch objects
```

1. **Semantic search**: `collection.find_nearest(vector_field="embedding", query_vector=Vector(embedding), distance_measure=COSINE, limit=top_k*2)`. Distance converted to score: `score = max(0.0, 1.0 − distance/2.0)`.
2. **Keyword search**: scans the in-process `_policy_cache` (populated from prior searches) for any match whose text contains all supplied keywords.
3. Merges both result sets (higher score wins on collision), sorts by score descending, truncates to `top_k`.
4. Caches each result in `_policy_cache`.

Optional `metadata_filter` supports exact-match and `$in`-list filtering on any metadata field.

---

#### Step 2.3 — Policy Compliance Check

**Function**: `RAGIntegrator.policy_compliance_checker(request_data, top_k) → Dict`

**Input** (built by `api/routes.py` / `api/tdx.py`):
```json
{
  "id": "<uuid>",
  "exception_type": "crowdstrike",
  "data_level": "III",
  "security_controls": ["vulnerability scanning", "os up to date"]
}
```

**Steps**:
1. Builds a query string from `exception_type` + `data_level` + `security_controls`.
2. Calls `hybrid_search` with those keywords and `top_k=6` (default).
3. Assembles a prompt containing the request JSON and up to 6 policy excerpts with their IDs, scores, and metadata.
4. Calls `_call_llm_json` → Gemini with `responseMimeType: application/json`.
5. If the LLM omits `policy_refs`, falls back to the IDs of the retrieved matches.

**Output**:
```json
{
  "compliance_status": "NON_COMPLIANT | POTENTIAL_ISSUE | COMPLIANT",
  "violations": [{"policy": "...", "reason": "..."}],
  "required_controls": ["..."],
  "policy_refs": ["policy-id-1", "policy-id-2"]
}
```

---

#### Step 2.4 — Risk Narrative Generation

**Function**: `RAGIntegrator.generate_risk_narrative(risk_score, factors, policy_refs) → str`

**Input**:
- `risk_score`: integer approval score (0–114 range)
- `factors`: score breakdown dict (data_classification, security_controls, network_posture, patch_management, impact_assessment)
- `policy_refs`: list of policy IDs from the compliance check

**Steps**:
1. Builds a prompt asking for a concise executive risk narrative.
2. Calls `_call_llm_json` → Gemini.
3. Extracts the narrative string from the response, checking keys `narrative`, `summary`, `executive_risk_narrative`, or the first value in the dict.

**Output**: Plain-text executive narrative (2–4 paragraphs).

---

#### Step 2.5 — LLM Wrapper

**Function**: `RAGIntegrator._call_llm_json(prompt: str) → Dict`

- Posts to the configured `LLM_API_URL` with `temperature=0.25` and `responseMimeType: application/json`.
- Retries up to `max_retries` times (default 4) with exponential backoff (capped at 8 s).
- Raises `RuntimeError` after all retries exhausted.

---

### Phase 3: Chat Assistant Policy Lookup

**Class**: `PolicyDatabase` in `services/agent_service.py`

Used by the `search_policy_database` tool in the chat agent. The lookup strategy:

1. **Firestore first**: calls `RAGIntegrator.hybrid_search` with keyword extraction (stop-word filtered, max 8 tokens).
2. **Local JSON fallback**: token-based TF-IDF-style scoring across `data/data.json` if Firestore is unavailable or returns no results.
3. Normalises Firestore results to a standard dict shape (`control_id`, `risk_area`, `requirements`, `classification_levels`, `chunk_text`, `score`, `source`).

---

## Data Flow Diagram

```
Form / TDX ticket
       │
       ▼
  map_form_to_scorer / map_ticket_to_scorer
       │
       ├──▶ calculate_risk_score  ──────────────────────────────────────┐
       │         (engine/risk_scorer.py)                                │
       │                                                                │
       ├──▶ make_exception_decision ─────────────────────────────────── │
       │         (engine/decision_engine.py)                            │
       │                                                                │
       └──▶ RAGIntegrator (engine/rag_integration.py)                   │
                 │                                                       │
                 ├─▶ _get_embedding  ──▶ gemini-embedding-001            │
                 │       ↓ 768-d vector                                  │
                 ├─▶ hybrid_search  ──▶ Firestore find_nearest           │
                 │       ↓ List[PolicyMatch]                             │
                 ├─▶ policy_compliance_checker  ──▶ Gemini LLM ──▶ JSON  │
                 └─▶ generate_risk_narrative    ──▶ Gemini LLM ──▶ str   │
                                                                         │
                 ┌───────────────────────────────────────────────────────┘
                 ▼
          write_report  (api/tdx.write_report)
          reports/<id>.txt
```

---

## API Contracts

### `hybrid_search` output — `PolicyMatch`
```python
@dataclass
class PolicyMatch:
    id: str          # Firestore document ID
    score: float     # 0.0–1.0 cosine similarity score
    metadata: dict   # all non-embedding Firestore fields
    text: str        # chunk_text value
```

### `policy_compliance_checker` output
```python
{
    "compliance_status": str,      # NON_COMPLIANT | POTENTIAL_ISSUE | COMPLIANT
    "violations":        list,     # list of str or {"policy": str, "reason": str}
    "required_controls": list,     # list of str
    "policy_refs":       list[str] # list of Firestore document IDs
}
```

### `generate_risk_narrative` output
Plain string — 2–4 paragraph executive summary.

---

## Configuration

All values read from environment (`.env` via `python-dotenv`):

```bash
# Firestore
GOOGLE_CLOUD_PROJECT=capstone-489617
FIRESTORE_DATABASE=policies
FIRESTORE_COLLECTION=policies
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json

# Gemini LLM
GOOGLE_API_KEY=<key>
LLM_API_KEY=<key>                  # alias; GOOGLE_API_KEY takes precedence
LLM_API_URL=https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent
GEMINI_CHAT_MODEL=gemini-2.5-flash  # used by the chat agent
```

`RAGIntegrator` is initialised once at server startup via FastAPI's `lifespan` hook and stored on `app.state.rag`. If initialisation fails, `app.state.rag` is set to `None` and all RAG steps are skipped gracefully.

### Dependencies
```
google-cloud-firestore>=2.16.0
requests>=2.28.0
python-dotenv>=1.0.0
openai-agents            # for chat assistant
```

---

## Caching

| Cache | Backing store | TTL | Key |
|---|---|---|---|
| Embedding cache | `shelve` (`.rag_cache`) | 6 hours | Raw query/policy text |
| Policy match cache | In-process dict | 6 hours | Firestore document ID |

---

## Error Handling & Degradation

| Failure | Behaviour |
|---|---|
| Embedding API unavailable | `RuntimeError` propagated; compliance check skipped; report notes RAG unavailable |
| Firestore unavailable | `hybrid_search` returns empty list; compliance check skipped |
| LLM call fails after retries | `RuntimeError` propagated; narrative omitted from report |
| `google-cloud-firestore` not installed | Warns at import; `RAGIntegrator.is_ready` returns `False` |
| Chat: Firestore unavailable | `PolicyDatabase` falls back to local JSON token search |

---

## Performance Notes

- Embedding calls are cached aggressively (6 h TTL) — repeated queries for the same exception type incur no API cost.
- `find_nearest` requests `top_k * 2` candidates from Firestore then re-ranks, reducing the chance of missing relevant results due to distance-only ordering.
- LLM prompts are built inline and kept short — policy excerpts are capped to what Firestore returns for the top `k` matches; no chunking or token-counting logic is needed at current corpus sizes.
- The chat assistant uses `session_settings=SessionSettings(limit=40)` to bound context window growth.
