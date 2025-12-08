"""RAG integration utilities for policy compliance and risk narrative generation.

This module provides a RAGIntegrator class to query a Pinecone vector
index of policies and to call an LLM (Gemini) for policy compliance checks
and for producing executive risk narratives.

Design notes:
- Uses hybrid search (keyword + semantic) against Pinecone index.
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
    from pinecone import Pinecone
except ImportError:  # pragma: no cover - pinecone may not be installed in test env
    Pinecone = None

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


@dataclass
class PolicyMatch:
    id: str
    score: float
    metadata: Dict[str, Any]
    text: str


class RAGIntegrator:
    """Integrates with Pinecone (vector DB) and Gemini LLM for policy checks.

    Configuration (via env vars):
    - PINECONE_API_KEY, PINECONE_ENV, PINECONE_INDEX
    - LLM_API_KEY, LLM_API_URL
    """

    def __init__(self, *,
                 pinecone_api_key: Optional[str] = None,
                 pinecone_env: Optional[str] = None,
                 pinecone_index: Optional[str] = None,
                 llm_api_key: Optional[str] = None,
                 llm_api_url: Optional[str] = None,
                 cache_path: str = ".rag_cache",
                 cache_ttl_seconds: int = 24 * 3600,
                 llm_temperature: float = 0.25,
                 max_retries: int = 4) -> None:
        """Initialize connector, set up caches and external clients."""

        self.pinecone_api_key = pinecone_api_key or os.getenv("PINECONE_API_KEY")
        self.pinecone_env = pinecone_env or os.getenv("PINECONE_ENV")
        self.pinecone_index_name = pinecone_index or os.getenv("PINECONE_INDEX", "policies")
        self.llm_api_key = llm_api_key or os.getenv("LLM_API_KEY")
        self.llm_api_url = llm_api_url or os.getenv("LLM_API_URL") or "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
        self.llm_temperature = llm_temperature
        self.max_retries = max_retries

        # Caches persisted for embeddings and historical cases
        self._shelf_path = cache_path
        os.makedirs(os.path.dirname(self._shelf_path) or ".", exist_ok=True)
        self._shelf = shelve.open(self._shelf_path, writeback=True)

        # in-memory cache for policy texts (frequently accessed)
        self._policy_cache: Dict[str, Tuple[float, PolicyMatch]] = {}
        self._policy_cache_ttl = 6 * 3600  # 6 hours for policy cache
        self._historical_case_ttl = cache_ttl_seconds

        if Pinecone and self.pinecone_api_key:
            try:
                self._pinecone_client = Pinecone(api_key=self.pinecone_api_key)
                self._pinecone_index = self._pinecone_client.Index(self.pinecone_index_name)
                
                # Get index stats to understand structure
                stats = self._pinecone_index.describe_index_stats()
                self._index_dimension = stats.dimension
                self._namespaces = list(stats.namespaces.keys()) if stats.namespaces else ['']
                self._default_namespace = self._namespaces[0] if self._namespaces else ''
                
                logger.info(f"Pinecone initialized: {self.pinecone_index_name}")
                logger.info(f"Index dimension: {self._index_dimension}")
                logger.info(f"Available namespaces: {self._namespaces}")
                logger.info(f"Using namespace: {self._default_namespace}")
            except Exception as e:
                logger.warning(f"Pinecone initialization failed: {e}")
                self._pinecone_index = None
                self._index_dimension = 128  # fallback
                self._namespaces = ['']
                self._default_namespace = ''
        else:
            self._pinecone_index = None
            self._index_dimension = 128  # fallback
            self._namespaces = ['']
            self._default_namespace = ''

        logger.info("RAGIntegrator initialized (index=%s)", self.pinecone_index_name)

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

    # ---- Pinecone / search helpers ----
    def _get_embedding(self, text: str) -> List[float]:
        """Get or compute an embedding for text; caches results."""
        existing = self._load_embedding(text)
        if existing is not None and len(existing) == self._index_dimension:
            return existing

        # Try to generate embedding using Google Gemini's embedding API
        if self.llm_api_key:
            try:
                import requests
                
                url = "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent"
                headers = {"Content-Type": "application/json"}
                params = {"key": self.llm_api_key}
                
                data = {
                    "model": "models/text-embedding-004",
                    "content": {"parts": [{"text": text}]},
                    "task_type": "RETRIEVAL_QUERY"
                }
                
                response = requests.post(url, headers=headers, params=params, json=data, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    embedding = result.get("embedding", {}).get("values", [])
                    if len(embedding) == self._index_dimension:
                        self._save_embedding(text, embedding)
                        return embedding
                    else:
                        logger.warning(f"Embedding dimension mismatch: got {len(embedding)}, expected {self._index_dimension}")
                else:
                    logger.warning(f"Embedding API failed with status {response.status_code}: {response.text}")
                    
            except Exception as e:
                logger.warning(f"Failed to generate embedding via Google API: {e}")

        # Fallback: create a deterministic pseudo-embedding matching index dimensions
        logger.warning(f"Using fallback embedding generation for dimension {self._index_dimension}")
        return self._generate_fallback_embedding(text)

    def _generate_fallback_embedding(self, text: str) -> List[float]:
        """Generate a fallback embedding of the correct dimension."""
        # Create a deterministic pseudo-embedding based on text content
        vec = []
        text_bytes = text.encode('utf-8')
        
        # Use text hash and content to create vector
        for i in range(self._index_dimension):
            # Combine position, hash, and character data
            if i < len(text_bytes):
                val = float(text_bytes[i]) / 255.0
            else:
                val = float(hash(text + str(i)) % 1000) / 1000.0
            
            # Center around 0 and add some variation
            val = (val - 0.5) * 2.0 * (1.0 + (i % 7) / 10.0)
            vec.append(val)
        
        # Normalize to unit vector
        magnitude = sum(x * x for x in vec) ** 0.5
        if magnitude > 0:
            vec = [x / magnitude for x in vec]
        
        self._save_embedding(text, vec)
        return vec

    def hybrid_search(self,
                      query: str,
                      top_k: int = 5,
                      metadata_filter: Optional[Dict[str, Any]] = None,
                      keywords: Optional[List[str]] = None) -> List[PolicyMatch]:
        """Perform hybrid (keyword + semantic) search and return policy matches.

        Args:
            query: Free-text query.
            top_k: Number of top results.
            metadata_filter: Dict used for Pinecone metadata filter (risk_area, classification_levels).
            keywords: Optional list of keywords to boost recall.

        Returns:
            List of PolicyMatch instances sorted by relevance.
        """
        logger.debug("Running hybrid search; query=%s, keywords=%s, filter=%s", query, keywords, metadata_filter)

        # Semantic part: get embedding and query vector index
        embedding = self._get_embedding(query)
        sem_matches: List[PolicyMatch] = []
        if self._pinecone_index is not None:
            try:
                # Pinecone query using vector. This code expects the pinecone index
                # to be configured to accept embeddings from the same provider.
                result = self._pinecone_index.query(
                    vector=embedding,
                    top_k=top_k * 2,
                    include_metadata=True,
                    include_values=False,
                    filter=metadata_filter or {},
                    namespace=self._default_namespace
                )
                for item in (result.matches or []):
                    # Extract text from metadata chunk_text field
                    text = (item.metadata or {}).get("chunk_text", "") or (item.metadata or {}).get("text", "")
                    pm = PolicyMatch(id=item.id, score=item.score, metadata=item.metadata or {}, text=text)
                    sem_matches.append(pm)
            except Exception as e:
                logger.warning("Pinecone semantic query failed: %s", e)

        # Keyword part: simple lexical search over cached policy metadata/text if available
        kw_matches: List[PolicyMatch] = []
        # Search cache first
        for pid, (ts, match) in list(self._policy_cache.items()):
            if any((kw.lower() in match.text.lower()) for kw in (keywords or [])):
                kw_matches.append(match)

        # Combine and deduplicate by id, prefer higher score
        combined: Dict[str, PolicyMatch] = {}
        for m in sem_matches + kw_matches:
            if m.id not in combined or m.score > combined[m.id].score:
                combined[m.id] = m

        # If nothing found in sem + cache, attempt a metadata-filtered fetch from index
        if not combined and self._pinecone_index is not None:
            try:
                # Use a fallback pinecone query by using the query text as "query" param
                result = self._pinecone_index.query(
                    top_k=top_k,
                    include_metadata=True,
                    filter=metadata_filter or {},
                    namespace=self._default_namespace
                    # vendor-specific text search fields may be available; this
                    # is a no-op here and will be mocked in tests.
                )
                for item in (result.matches or []):
                    # Extract text from metadata chunk_text field
                    text = (item.metadata or {}).get("chunk_text", "") or (item.metadata or {}).get("text", "")
                    pm = PolicyMatch(id=item.id, score=item.score, metadata=item.metadata or {}, text=text)
                    combined[item.id] = pm
            except Exception as e:
                logger.debug("Fallback text query against Pinecone failed or not supported: %s", e)

        matches = sorted(combined.values(), key=lambda m: getattr(m, "score", 0.0), reverse=True)[:top_k]

        for m in matches:
            self._cache_policy_match(m)

        logger.info("Hybrid search returned %d matches", len(matches))
        return matches

    # ---- LLM helpers ----
    def _chunk_text(self, text: str, max_tokens: int = 2000) -> List[str]:
        """Naive chunking by characters to approximate token limits.

        This uses a heuristic of 4 chars per token for English; replace with an
        accurate tokenizer in production (tiktoken, sentencepiece).
        """
        approx_tokens = max(1, len(text) // 4)
        if approx_tokens <= max_tokens:
            return [text]

        # chunk size in characters
        chunk_chars = max_tokens * 4
        chunks = [text[i:i + chunk_chars] for i in range(0, len(text), chunk_chars)]
        logger.debug("Chunked text into %d parts (approx tokens=%d)", len(chunks), approx_tokens)
        return chunks

    def _call_llm(self, prompt: str, *, max_tokens: int = 2048, temperature: Optional[float] = None) -> str:
        """Call the LLM endpoint with retries and exponential backoff.

        This method posts JSON to Google's Gemini API endpoint. The payload is formatted
        according to Gemini's expected structure.
        """
        temp = temperature if temperature is not None else self.llm_temperature
        headers = {"Content-Type": "application/json"}
        
        # Format request for Google Gemini API
        body = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }],
            "generationConfig": {
                "temperature": temp,
                "maxOutputTokens": max_tokens,
                "candidateCount": 1
            }
        }
        
        # Add API key to URL
        url_with_key = f"{self.llm_api_url}?key={self.llm_api_key}"

        backoff = 1.0
        for attempt in range(1, self.max_retries + 1):
            try:
                if not self.llm_api_url or not self.llm_api_key:
                    raise RuntimeError("LLM API URL or key not configured")

                resp = requests.post(url_with_key, headers=headers, data=json.dumps(body), timeout=30)
                resp.raise_for_status()
                data = resp.json()
                
                # Parse Google Gemini response format
                if isinstance(data, dict):
                    candidates = data.get("candidates", [])
                    if candidates:
                        content = candidates[0].get("content", {})
                        parts = content.get("parts", [])
                        if parts and "text" in parts[0]:
                            return parts[0]["text"]
                    
                    # Log the structure for debugging
                    logger.debug("Gemini response structure: %s", json.dumps(data, indent=2)[:500])

                # fallback: return raw text if structure is unexpected
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
        """Check an exception request against policy corpus and return findings.

        The method performs hybrid search to retrieve relevant policies and
        calls the LLM to assess violations and required controls.

        Args:
            exception_request: Dict including keys: 'exception_type', 'data_level', 'security_controls'.
            top_k: Number of policies to retrieve for LLM analysis.

        Returns:
            Dict with keys: compliance_status ('COMPLIANT'|'NON_COMPLIANT'|'POTENTIAL_ISSUE'),
            'violations' list, 'required_controls' list and 'policy_refs' list.
        """
        logger.info("Running policy compliance checker for request id=%s", exception_request.get("id"))

        # Build semantic query
        exception_type = exception_request.get("exception_type", "")
        data_level = exception_request.get("data_level")
        controls = exception_request.get("security_controls", [])

        metadata_filter = {}
        if data_level is not None:
            metadata_filter["classification_level"] = {"$in": [data_level]}

        keywords = [exception_type] + (controls or [])
        hits = self.hybrid_search(query=exception_type or json.dumps(exception_request), top_k=top_k, metadata_filter=metadata_filter, keywords=keywords)

        # Build prompt for LLM (concise but with enough policy detail)
        policy_summary = ". ".join([f"{h.id}: {h.text[:400]}" for h in hits[:3]])  # Longer policy text, top 3
        prompt = (
            f"Check if '{exception_type}' for '{data_level}' data violates these policies: {policy_summary}. "
            f"Return only JSON: {{\"verdict\":\"COMPLIANT|NON_COMPLIANT|POTENTIAL_ISSUE\",\"violations\":[],\"required_controls\":[]}}"
        )

        # Handle long prompts by chunking if necessary
        chunks = self._chunk_text(prompt, max_tokens=400)
        llm_responses: List[str] = []
        for chunk in chunks:
            resp = self._call_llm(chunk, max_tokens=800, temperature=self.llm_temperature)
            llm_responses.append(resp)

        llm_combined = "\n".join(llm_responses)

        # Try to parse JSON from LLM reply
        compliance = {
            "compliance_status": "UNKNOWN",
            "violations": [],
            "required_controls": [],
            "policy_refs": [h.id for h in hits],
            "raw_llm": llm_combined,
        }

        try:
            # LLM may include explanatory text or markdown; attempt to locate the JSON substring
            llm_text = llm_combined.strip()
            
            # Remove markdown code blocks if present
            if llm_text.startswith("```"):
                lines = llm_text.split('\n')
                start_idx = 1 if lines[0].startswith("```") else 0
                end_idx = len(lines)
                for i, line in enumerate(lines[1:], 1):
                    if line.strip() == "```":
                        end_idx = i
                        break
                llm_text = '\n'.join(lines[start_idx:end_idx])
            
            # Find JSON content
            json_start = llm_text.find("{")
            json_end = llm_text.rfind("}") + 1
            
            if json_start >= 0 and json_end > json_start:
                json_text = llm_text[json_start:json_end]
                parsed = json.loads(json_text)
                
                verdict = parsed.get("verdict") or parsed.get("compliance") or parsed.get("status")
                if verdict:
                    compliance["compliance_status"] = verdict.upper()
                compliance["violations"] = parsed.get("violations", [])
                compliance["required_controls"] = parsed.get("required_controls", [])
                compliance["policy_refs"] = parsed.get("policy_references", compliance["policy_refs"]) or compliance["policy_refs"]
                
                logger.info(f"Successfully parsed compliance result: {verdict}")
            else:
                logger.warning("No JSON found in LLM response")
                
        except Exception as e:
            logger.warning("Failed parsing LLM JSON output: %s", e)
            logger.debug(f"Raw LLM text: {llm_combined}")
            # Leave raw LLM content for debugging

        return compliance

    def generate_risk_narrative(self, risk_score: float, factors: Dict[str, Any], policy_refs: Optional[List[str]] = None) -> str:
        """Generate an executive 2-3 paragraph risk assessment using the LLM.

        Args:
            risk_score: Numeric 0-100 risk score.
            factors: Dictionary of contributing factors.
            policy_refs: Optional list of policy ids to reference in narrative.

        Returns:
            Narrative string (2-3 paragraphs) suitable for executive summary.
        """
        policy_refs = policy_refs or []
        prompt = (
            "You are a concise executive security writer. Given a risk score (0-100) and contributing factors, "
            "produce a 2-3 paragraph executive risk assessment suitable for senior leadership. Start with a one-sentence summary, "
            "describe the key contributing factors, and finish with recommended next steps and policy references (short list). Be precise and avoid jargon." 
            f"\n\nRisk Score: {risk_score}\nFactors: {json.dumps(factors, indent=2)}\nPolicy References: {policy_refs}\n\nLimit to ~200-300 words."
        )

        # Try a single LLM call; chunking not usually required for a short prompt
        resp = self._call_llm(prompt, max_tokens=800, temperature=self.llm_temperature)
        # Ensure response is reasonably short and human readable
        return resp.strip()

    def close(self) -> None:
        """Close and persist caches; call on shutdown."""
        try:
            if hasattr(self._shelf, "close"):
                self._shelf.close()
        except Exception:
            logger.exception("Failed closing shelf cache")


__all__ = ["RAGIntegrator", "PolicyMatch"]
