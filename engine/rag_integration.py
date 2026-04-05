"""RAG integration utilities for policy compliance and risk narrative generation.

This module provides a RAGIntegrator class to query a Firestore vector
collection of policies and to call an LLM (Gemini) for policy compliance checks
and for producing executive risk narratives.

Design notes:
- Uses hybrid search (keyword + semantic) against Firestore vector collection.
- Caches embeddings (shelve) and frequently accessed policy text in memory.
- Provides LLM wrapper with retries + exponential backoff and token chunking.
- Config via environment vars (with reasonable defaults) or a local config module.
"""
from __future__ import annotations

import json
import logging
import os
import shelve
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

try:
    from google.cloud import firestore
    from google.cloud.firestore_v1.vector import Vector
    from google.cloud.firestore_v1.base_vector_query import DistanceMeasure
except ImportError:  # pragma: no cover
    firestore = None
    Vector = None
    DistanceMeasure = None

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Embedding dimension for Google text-embedding-004
_EMBEDDING_DIM = 768


@dataclass
class PolicyMatch:
    id: str
    score: float
    metadata: Dict[str, Any]
    text: str


class RAGIntegrator:
    """Integrates with Firestore (vector DB) and Gemini LLM for policy checks.

    Configuration (via env vars):
    - GOOGLE_CLOUD_PROJECT, FIRESTORE_COLLECTION
    - LLM_API_KEY, LLM_API_URL
    """

    def __init__(self, *,
                 firestore_project: Optional[str] = None,
                 firestore_database: Optional[str] = None,
                 firestore_collection: Optional[str] = None,
                 llm_api_key: Optional[str] = None,
                 llm_api_url: Optional[str] = None,
                 cache_path: str = ".rag_cache",
                 cache_ttl_seconds: int = 24 * 3600,
                 llm_temperature: float = 0.25,
                 max_retries: int = 4) -> None:
        """Initialize connector, set up caches and external clients."""

        self._project = firestore_project or os.getenv("GOOGLE_CLOUD_PROJECT")
        self._database = firestore_database or os.getenv("FIRESTORE_DATABASE", "policies")
        self._collection_name = firestore_collection or os.getenv("FIRESTORE_COLLECTION", "policies")
        self.llm_api_key = llm_api_key or os.getenv("LLM_API_KEY")
        self.llm_api_url = llm_api_url or os.getenv("LLM_API_URL") or "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
        self.llm_temperature = llm_temperature
        self.max_retries = max_retries

        # Fixed at 768 for Google text-embedding-004
        self._index_dimension = _EMBEDDING_DIM

        # Caches persisted for embeddings and historical cases
        self._shelf_path = cache_path
        os.makedirs(os.path.dirname(self._shelf_path) or ".", exist_ok=True)
        self._shelf = shelve.open(self._shelf_path, writeback=True)

        # in-memory cache for policy texts (frequently accessed)
        self._policy_cache: Dict[str, Tuple[float, PolicyMatch]] = {}
        self._policy_cache_ttl = 6 * 3600  # 6 hours
        self._historical_case_ttl = cache_ttl_seconds

        # Initialize Firestore client
        self._firestore_client = None
        self._firestore_collection = None
        if firestore is not None:
            try:
                if self._project:
                    self._firestore_client = firestore.Client(project=self._project, database=self._database)
                else:
                    self._firestore_client = firestore.Client(database=self._database)
                self._firestore_collection = self._firestore_client.collection(self._collection_name)
                logger.info("Firestore initialized: project=%s database=%s collection=%s", self._project, self._database, self._collection_name)
            except Exception as e:
                logger.warning("Firestore initialization failed: %s", e)
                self._firestore_client = None
                self._firestore_collection = None
        else:
            logger.warning("google-cloud-firestore not installed")

        # Expose a stable namespace string for compatibility with demo/display code
        self._default_namespace = self._collection_name

        logger.info("RAGIntegrator initialized (collection=%s)", self._collection_name)

    # ---- Cache helpers ----
    def _get_embedding_cache(self) -> Dict[str, Any]:
        if "embeddings" not in self._shelf:
            self._shelf["embeddings"] = {}
        return self._shelf["embeddings"]

    def _save_embedding(self, text: str, vector: List[float]) -> None:
        cache = self._get_embedding_cache()
        cache[text] = {"vector": vector, "ts": time.time()}
        self._shelf["embeddings"] = cache
        self._shelf.sync()

    def _load_embedding(self, text: str) -> Optional[List[float]]:
        cache = self._get_embedding_cache()
        entry = cache.get(text)
        if not entry:
            return None
        ts = entry.get("ts", 0.0)
        if time.time() - ts > self._policy_cache_ttl:
            del cache[text]
            self._shelf["embeddings"] = cache
            self._shelf.sync()
            logger.debug("Evicted expired embedding from shelf cache (key len=%d)", len(text))
            return None
        return entry.get("vector")

    def _cache_policy_match(self, match: PolicyMatch) -> None:
        self._policy_cache[match.id] = (time.time(), match)

    def _get_cached_policy(self, policy_id: str) -> Optional[PolicyMatch]:
        tup = self._policy_cache.get(policy_id)
        if not tup:
            return None
        ts, match = tup
        if time.time() - ts > self._policy_cache_ttl:
            del self._policy_cache[policy_id]
            return None
        return match

    # ---- Embedding helpers ----
    def _get_embedding(self, text: str) -> List[float]:
        """Get or compute an embedding for text; caches results."""
        existing = self._load_embedding(text)
        if existing is not None and len(existing) == self._index_dimension:
            return existing

        if self.llm_api_key:
            try:
                url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-001:embedContent"
                headers = {"Content-Type": "application/json"}
                params = {"key": self.llm_api_key}
                data = {
                    "model": "models/gemini-embedding-001",
                    "content": {"parts": [{"text": text}]},
                    "task_type": "RETRIEVAL_QUERY",
                    "outputDimensionality": 768
                }
                response = requests.post(url, headers=headers, params=params, json=data, timeout=30)
                if response.status_code == 200:
                    result = response.json()
                    embedding = result.get("embedding", {}).get("values", [])
                    if len(embedding) == self._index_dimension:
                        self._save_embedding(text, embedding)
                        return embedding
                    else:
                        logger.warning("Embedding dimension mismatch: got %d, expected %d", len(embedding), self._index_dimension)
                else:
                    logger.warning("Embedding API failed with status %d: %s", response.status_code, response.text)
            except Exception as e:
                logger.warning("Failed to generate embedding via Google API: %s", e)

        # Bug 11 fix: do NOT silently fall back to a pseudo-random vector.
        logger.error(
            "Embedding generation failed (API unavailable or key missing). "
            "Refusing to use a pseudo-random fallback vector that would produce "
            "semantically garbage results. Raising so callers can degrade explicitly."
        )
        return self._generate_fallback_embedding(text)  # always raises

    def _generate_fallback_embedding(self, text: str) -> List[float]:  # noqa: ARG002
        raise RuntimeError(
            "Embedding generation failed and no safe fallback is available. "
            "Verify that LLM_API_KEY is set and that the Google embedding "
            "endpoint is reachable before retrying."
        )

    # ---- Search ----
    def hybrid_search(self,
                      query: str,
                      top_k: int = 5,
                      metadata_filter: Optional[Dict[str, Any]] = None,
                      keywords: Optional[List[str]] = None) -> List[PolicyMatch]:
        """Perform hybrid (keyword + semantic) search and return policy matches.

        Args:
            query: Free-text query.
            top_k: Number of top results.
            metadata_filter: Optional dict used for post-filtering results
                (e.g. {'classification_levels': {'$in': ['III']}}).
            keywords: Optional list of keywords to boost recall from cache.

        Returns:
            List of PolicyMatch instances sorted by relevance score (desc).
        """
        logger.debug("Running hybrid search; query=%s, keywords=%s, filter=%s", query, keywords, metadata_filter)

        embedding = self._get_embedding(query)
        sem_matches: List[PolicyMatch] = []

        if self._firestore_collection is not None and Vector is not None:
            try:
                vector_query = self._firestore_collection.find_nearest(
                    vector_field="embedding",
                    query_vector=Vector(embedding),
                    distance_measure=DistanceMeasure.COSINE,
                    limit=top_k * 2,
                    distance_result_field="vector_distance",
                )
                docs = vector_query.get()
                for doc in docs:
                    data = doc.to_dict() or {}
                    # Cosine distance: 0 = identical, 2 = opposite → convert to similarity
                    distance = data.pop("vector_distance", 0.0) or 0.0
                    score = max(0.0, 1.0 - (distance / 2.0))
                    text = data.get("chunk_text", "")
                    metadata = {k: v for k, v in data.items() if k != "embedding"}
                    sem_matches.append(PolicyMatch(id=doc.id, score=score, metadata=metadata, text=text))
            except Exception as e:
                logger.warning("Firestore vector search failed: %s", e)

        # Apply metadata post-filter if requested
        if metadata_filter and sem_matches:
            sem_matches = self._apply_metadata_filter(sem_matches, metadata_filter)

        # Keyword boost from in-memory cache
        kw_matches: List[PolicyMatch] = []
        for pid, (ts, match) in list(self._policy_cache.items()):
            if any(kw.lower() in match.text.lower() for kw in (keywords or [])):
                kw_matches.append(match)

        # Merge: prefer higher score for duplicates
        combined: Dict[str, PolicyMatch] = {}
        for m in sem_matches + kw_matches:
            if m.id not in combined or m.score > combined[m.id].score:
                combined[m.id] = m

        matches = sorted(combined.values(), key=lambda m: m.score, reverse=True)[:top_k]

        for m in matches:
            self._cache_policy_match(m)

        logger.info("Hybrid search returned %d matches", len(matches))
        return matches

    def _apply_metadata_filter(self, matches: List[PolicyMatch], metadata_filter: Dict[str, Any]) -> List[PolicyMatch]:
        """Post-filter PolicyMatch results based on a Pinecone-style filter dict."""
        filtered = []
        for match in matches:
            if self._matches_filter(match.metadata, metadata_filter):
                filtered.append(match)
        return filtered

    def _matches_filter(self, metadata: Dict[str, Any], filt: Dict[str, Any]) -> bool:
        for field, condition in filt.items():
            value = metadata.get(field)
            if isinstance(condition, dict):
                if "$in" in condition:
                    allowed = condition["$in"]
                    if isinstance(value, list):
                        if not any(v in allowed for v in value):
                            return False
                    elif value not in allowed:
                        return False
                elif "$eq" in condition:
                    if value != condition["$eq"]:
                        return False
            else:
                if value != condition:
                    return False
        return True

    # ---- LLM helpers ----
    def _chunk_text(self, text: str, max_tokens: int = 2000) -> List[str]:
        """Naive chunking by characters to approximate token limits."""
        approx_tokens = max(1, len(text) // 4)
        if approx_tokens <= max_tokens:
            return [text]
        chunk_chars = max_tokens * 4
        chunks = [text[i:i + chunk_chars] for i in range(0, len(text), chunk_chars)]
        logger.debug("Chunked text into %d parts (approx tokens=%d)", len(chunks), approx_tokens)
        return chunks

    def _call_llm(self, prompt: str, *, max_tokens: int = 2048, temperature: Optional[float] = None) -> str:
        """Call the LLM endpoint with retries and exponential backoff."""
        temp = temperature if temperature is not None else self.llm_temperature
        headers = {"Content-Type": "application/json"}
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": temp,
                "maxOutputTokens": max_tokens,
                "candidateCount": 1
            }
        }
        url_with_key = f"{self.llm_api_url}?key={self.llm_api_key}"

        backoff = 1.0
        for attempt in range(1, self.max_retries + 1):
            try:
                if not self.llm_api_url or not self.llm_api_key:
                    raise RuntimeError("LLM API URL or key not configured")

                resp = requests.post(url_with_key, headers=headers, data=json.dumps(body), timeout=30)
                resp.raise_for_status()
                data = resp.json()

                if isinstance(data, dict):
                    candidates = data.get("candidates", [])
                    if candidates:
                        content = candidates[0].get("content", {})
                        parts = content.get("parts", [])
                        if parts and "text" in parts[0]:
                            return parts[0]["text"]
                    logger.debug("Gemini response structure: %s", json.dumps(data, indent=2)[:500])

                logger.warning("Unexpected Gemini response, returning raw JSON")
                return json.dumps(data)

            except Exception as e:
                logger.warning("LLM call attempt %d failed: %s", attempt, e)
                if attempt == self.max_retries:
                    logger.exception("LLM call failed after %d attempts", attempt)
                    raise
                time.sleep(backoff)
                backoff *= 2.0

    # ---- Business-facing methods ----
    def policy_compliance_checker(self,
                                  exception_request: Dict[str, Any],
                                  top_k: int = 6) -> Dict[str, Any]:
        """Check an exception request against policy corpus and return findings."""
        logger.info("Running policy compliance checker for request id=%s", exception_request.get("id"))

        exception_type = exception_request.get("exception_type", "")
        data_level = exception_request.get("data_level")
        controls = exception_request.get("security_controls", [])

        metadata_filter = {}
        if data_level is not None:
            metadata_filter["classification_levels"] = {"$in": [data_level]}

        keywords = [exception_type] + (controls or [])
        hits = self.hybrid_search(
            query=exception_type or json.dumps(exception_request),
            top_k=top_k,
            metadata_filter=metadata_filter,
            keywords=keywords
        )

        policy_summary = ". ".join([f"{h.id}: {h.text[:400]}" for h in hits[:3]])
        prompt = (
            f"Check if '{exception_type}' for '{data_level}' data violates these policies: {policy_summary}. "
            f"Return only JSON: {{\"verdict\":\"COMPLIANT|NON_COMPLIANT|POTENTIAL_ISSUE\",\"violations\":[],\"required_controls\":[]}}"
        )

        chunks = self._chunk_text(prompt, max_tokens=400)
        llm_responses: List[str] = []
        for chunk in chunks:
            resp = self._call_llm(chunk, max_tokens=800, temperature=self.llm_temperature)
            llm_responses.append(resp)

        llm_combined = "\n".join(llm_responses)

        compliance = {
            "compliance_status": "UNKNOWN",
            "violations": [],
            "required_controls": [],
            "policy_refs": [h.id for h in hits],
            "raw_llm": llm_combined,
        }

        try:
            llm_text = llm_combined.strip()
            if llm_text.startswith("```"):
                lines = llm_text.split('\n')
                start_idx = 1 if lines[0].startswith("```") else 0
                end_idx = len(lines)
                for i, line in enumerate(lines[1:], 1):
                    if line.strip() == "```":
                        end_idx = i
                        break
                llm_text = '\n'.join(lines[start_idx:end_idx])

            json_start = llm_text.find("{")
            json_end = llm_text.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                parsed = json.loads(llm_text[json_start:json_end])
                verdict = parsed.get("verdict") or parsed.get("compliance") or parsed.get("status")
                if verdict:
                    compliance["compliance_status"] = verdict.upper()
                compliance["violations"] = parsed.get("violations", [])
                compliance["required_controls"] = parsed.get("required_controls", [])
                compliance["policy_refs"] = parsed.get("policy_references", compliance["policy_refs"]) or compliance["policy_refs"]
                logger.info("Successfully parsed compliance result: %s", verdict)
            else:
                logger.warning("No JSON found in LLM response")
        except Exception as e:
            logger.warning("Failed parsing LLM JSON output: %s", e)

        return compliance

    def generate_risk_narrative(self, risk_score: float, factors: Dict[str, Any], policy_refs: Optional[List[str]] = None) -> str:
        """Generate an executive 2-3 paragraph risk assessment using the LLM."""
        policy_refs = policy_refs or []
        prompt = (
            "You are a concise executive security writer. Given a risk score (0-100) and contributing factors, "
            "produce a 2-3 paragraph executive risk assessment suitable for senior leadership. Start with a one-sentence summary, "
            "describe the key contributing factors, and finish with recommended next steps and policy references (short list). Be precise and avoid jargon."
            f"\n\nRisk Score: {risk_score}\nFactors: {json.dumps(factors, indent=2)}\nPolicy References: {policy_refs}\n\nLimit to ~200-300 words."
        )
        resp = self._call_llm(prompt, max_tokens=800, temperature=self.llm_temperature)
        return resp.strip()

    def close(self) -> None:
        """Close and persist caches; call on shutdown."""
        try:
            if hasattr(self._shelf, "close"):
                self._shelf.close()
        except Exception:
            logger.exception("Failed closing shelf cache")


__all__ = ["RAGIntegrator", "PolicyMatch"]
