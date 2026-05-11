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

load_dotenv()

try:
    from google.cloud import firestore
    from google.cloud.firestore_v1.base_vector_query import DistanceMeasure
    from google.cloud.firestore_v1.vector import Vector
except ImportError:  # pragma: no cover
    firestore = None
    Vector = None
    DistanceMeasure = None

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

_EMBEDDING_DIM = 768


@dataclass
class PolicyMatch:
    id: str
    score: float
    metadata: Dict[str, Any]
    text: str


class RAGIntegrator:
    def __init__(
        self,
        *,
        firestore_project: Optional[str] = None,
        firestore_database: Optional[str] = None,
        firestore_collection: Optional[str] = None,
        llm_api_key: Optional[str] = None,
        llm_api_url: Optional[str] = None,
        cache_path: str = ".rag_cache",
        cache_ttl_seconds: int = 24 * 3600,
        llm_temperature: float = 0.25,
        max_retries: int = 4,
    ) -> None:
        self._project = firestore_project or os.getenv("GOOGLE_CLOUD_PROJECT")
        self._database = firestore_database or os.getenv("FIRESTORE_DATABASE", "policies")
        self._collection_name = firestore_collection or os.getenv(
            "FIRESTORE_COLLECTION", "policies"
        )
        self.llm_api_key = llm_api_key or os.getenv("LLM_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.llm_api_url = (
            llm_api_url
            or os.getenv("LLM_API_URL")
            or "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent"
        )
        self.llm_temperature = llm_temperature
        self.max_retries = max_retries
        self._index_dimension = _EMBEDDING_DIM

        self._shelf_path = cache_path
        os.makedirs(os.path.dirname(self._shelf_path) or ".", exist_ok=True)
        self._shelf = shelve.open(self._shelf_path, writeback=True)

        self._policy_cache: Dict[str, Tuple[float, PolicyMatch]] = {}
        self._policy_cache_ttl = 6 * 3600
        self._historical_case_ttl = cache_ttl_seconds

        self._firestore_client = None
        self._firestore_collection = None
        if firestore is not None:
            try:
                if self._project:
                    self._firestore_client = firestore.Client(
                        project=self._project,
                        database=self._database,
                    )
                else:
                    self._firestore_client = firestore.Client(database=self._database)
                self._firestore_collection = self._firestore_client.collection(
                    self._collection_name
                )
                logger.info(
                    "Firestore initialized: project=%s database=%s collection=%s",
                    self._project,
                    self._database,
                    self._collection_name,
                )
            except Exception as exc:
                logger.warning("Firestore initialization failed: %s", exc)
                self._firestore_client = None
                self._firestore_collection = None
        else:
            logger.warning("google-cloud-firestore not installed")

        self._default_namespace = self._collection_name
        logger.info("RAGIntegrator initialized (collection=%s)", self._collection_name)

    @property
    def is_ready(self) -> bool:
        return self._firestore_collection is not None

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

    def _get_embedding(self, text: str) -> List[float]:
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
                    "outputDimensionality": 768,
                }
                response = requests.post(url, headers=headers, params=params, json=data, timeout=30)
                if response.status_code == 200:
                    result = response.json()
                    embedding = result.get("embedding", {}).get("values", [])
                    if len(embedding) == self._index_dimension:
                        self._save_embedding(text, embedding)
                        return embedding
                    logger.warning(
                        "Embedding dimension mismatch: got %d, expected %d",
                        len(embedding),
                        self._index_dimension,
                    )
                else:
                    logger.warning(
                        "Embedding API failed with status %d: %s",
                        response.status_code,
                        response.text,
                    )
            except Exception as exc:
                logger.warning("Failed to generate embedding via Google API: %s", exc)

        logger.error(
            "Embedding generation failed (API unavailable or key missing). "
            "Refusing to use a pseudo-random fallback vector that would produce "
            "semantically garbage results. Raising so callers can degrade explicitly."
        )
        return self._generate_fallback_embedding(text)

    def _generate_fallback_embedding(self, text: str) -> List[float]:  # noqa: ARG002
        raise RuntimeError(
            "Embedding generation failed and no safe fallback is available. "
            "Verify that LLM_API_KEY or GOOGLE_API_KEY is set and that the Google embedding "
            "endpoint is reachable before retrying."
        )

    def hybrid_search(
        self,
        query: str,
        top_k: int = 5,
        metadata_filter: Optional[Dict[str, Any]] = None,
        keywords: Optional[List[str]] = None,
    ) -> List[PolicyMatch]:
        logger.debug(
            "Running hybrid search; query=%s, keywords=%s, filter=%s",
            query,
            keywords,
            metadata_filter,
        )

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
                    distance = data.pop("vector_distance", 0.0) or 0.0
                    score = max(0.0, 1.0 - (distance / 2.0))
                    text = data.get("chunk_text", "")
                    metadata = {key: value for key, value in data.items() if key != "embedding"}
                    sem_matches.append(
                        PolicyMatch(id=doc.id, score=score, metadata=metadata, text=text)
                    )
            except Exception as exc:
                logger.warning("Firestore vector search failed: %s", exc)

        if metadata_filter and sem_matches:
            sem_matches = self._apply_metadata_filter(sem_matches, metadata_filter)

        kw_matches: List[PolicyMatch] = []
        for _, match in list(self._policy_cache.values()):
            if any(keyword.lower() in match.text.lower() for keyword in (keywords or [])):
                kw_matches.append(match)

        combined: Dict[str, PolicyMatch] = {}
        for match in sem_matches + kw_matches:
            if match.id not in combined or match.score > combined[match.id].score:
                combined[match.id] = match

        results = sorted(combined.values(), key=lambda item: item.score, reverse=True)[:top_k]
        for match in results:
            self._cache_policy_match(match)
        return results

    def _apply_metadata_filter(
        self, matches: List[PolicyMatch], metadata_filter: Dict[str, Any]
    ) -> List[PolicyMatch]:
        def match_filter(policy_match: PolicyMatch) -> bool:
            metadata = policy_match.metadata or {}
            for key, expected in metadata_filter.items():
                value = metadata.get(key)
                if isinstance(expected, dict) and "$in" in expected:
                    candidates = expected["$in"]
                    if isinstance(value, list):
                        if not any(item in value for item in candidates):
                            return False
                    elif value not in candidates:
                        return False
                elif value != expected:
                    return False
            return True

        return [match for match in matches if match_filter(match)]

    def _call_llm_json(self, prompt: str) -> Dict[str, Any]:
        if not self.llm_api_key:
            raise RuntimeError("LLM_API_KEY or GOOGLE_API_KEY is required for Gemini LLM calls")

        headers = {"Content-Type": "application/json"}
        params = {"key": self.llm_api_key}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.llm_temperature,
                "responseMimeType": "application/json",
            },
        }

        last_error = None
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    self.llm_api_url,
                    headers=headers,
                    params=params,
                    json=payload,
                    timeout=45,
                )
                response.raise_for_status()
                data = response.json()
                text = (
                    data.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [{}])[0]
                    .get("text", "{}")
                )
                return json.loads(text)
            except Exception as exc:
                last_error = exc
                time.sleep(min(2**attempt, 8))

        raise RuntimeError(f"LLM call failed after retries: {last_error}")

    def policy_compliance_checker(self, request_data: Dict[str, Any], top_k: int = 5) -> Dict[str, Any]:
        query = " ".join(
            [
                str(request_data.get("exception_type", "")),
                str(request_data.get("data_level", "")),
                " ".join(request_data.get("security_controls", []) or []),
            ]
        ).strip()
        keywords = [request_data.get("exception_type", ""), str(request_data.get("data_level", ""))]
        matches = self.hybrid_search(query=query, top_k=top_k, keywords=keywords)

        prompt = (
            "You are a security compliance analyst. Using the request and policy excerpts below, "
            "return JSON with keys compliance_status, policy_refs, violations, and required_controls.\n\n"
            f"Request:\n{json.dumps(request_data, indent=2)}\n\n"
            "Policies:\n"
        )
        for match in matches:
            prompt += (
                f"- Policy {match.id} (score={match.score:.3f})\n"
                f"  Metadata: {json.dumps(match.metadata)}\n"
                f"  Text: {match.text}\n"
            )

        result = self._call_llm_json(prompt)
        if "policy_refs" not in result:
            result["policy_refs"] = [match.id for match in matches]
        return result

    def generate_risk_narrative(
        self,
        risk_score: int,
        factors: Dict[str, Any],
        policy_refs: Optional[List[str]] = None,
    ) -> str:
        prompt = (
            "Write a concise executive risk narrative for a university IT security exception request.\n\n"
            f"Risk score: {risk_score}\n"
            f"Factors: {json.dumps(factors, indent=2)}\n"
            f"Policy references: {policy_refs or []}\n"
        )
        result = self._call_llm_json(prompt)
        if isinstance(result, dict):
            text = (
                result.get("narrative")
                or result.get("summary")
                or result.get("executive_risk_narrative")
                or next(iter(result.values()), None)
            )
            return str(text) if text else json.dumps(result)
        return str(result)

    def close(self) -> None:
        try:
            self._shelf.close()
        except Exception:
            pass


__all__ = ["PolicyMatch", "RAGIntegrator"]
