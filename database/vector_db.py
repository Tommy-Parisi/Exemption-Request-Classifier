import logging
from pinecone import Pinecone, ServerlessSpec
from dotenv import load_dotenv
import os
import time
import json
import requests

load_dotenv()

logger = logging.getLogger(__name__)

pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))

index_name = os.getenv("PINECONE_INDEX", "exemption-policy")

def get_google_embedding(text, api_key):
    """Generate embedding using Google's text-embedding-004 model (768 dimensions)."""
    url = "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent"
    headers = {"Content-Type": "application/json"}
    params = {"key": api_key}

    data = {
        "model": "models/text-embedding-004",
        "content": {"parts": [{"text": text}]},
        "task_type": "RETRIEVAL_DOCUMENT"  # Use RETRIEVAL_DOCUMENT for indexing
    }

    response = requests.post(url, headers=headers, params=params, json=data, timeout=30)
    response.raise_for_status()

    result = response.json()
    embedding = result.get("embedding", {}).get("values", [])
    return embedding

def initialize_index():
    if not pc.has_index(index_name):
        pc.create_index(
            name=index_name,
            dimension=768,  # Google text-embedding-004 dimension
            metric="cosine",
            spec=ServerlessSpec(
                cloud="aws",
                region="us-east-1"
            )
        )

def build_chunk_text(item):
    """Build searchable text from policy document fields."""
    parts = []

    if item.get('control_id'):
        parts.append(f"Control {item['control_id']}")

    if item.get('risk_area'):
        parts.append(f"Risk Area: {item['risk_area']}")

    if item.get('classification_levels'):
        levels = ', '.join(item['classification_levels'])
        parts.append(f"Data Classification: {levels}")

    if item.get('requirements'):
        reqs = ' '.join(item['requirements']) if isinstance(item['requirements'], list) else item['requirements']
        parts.append(reqs)

    if item.get('note'):
        parts.append(item['note'])

    if item.get('references'):
        parts.append(f"References: {item['references']}")

    return ' '.join(parts)

def upsert_data():
    # Load policy data from JSON
    json_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'data.json')

    with open(json_path, encoding='utf-8') as f:
        policies = json.load(f)

    if not isinstance(policies, list):
        policies = [policies]  # Handle single object

    logger.info("Loaded %d policies from JSON", len(policies))

    # Get Google API key for embeddings
    google_api_key = os.getenv("LLM_API_KEY")
    if not google_api_key:
        raise ValueError("LLM_API_KEY environment variable not set")

    # Generate embeddings and prepare vectors
    logger.info("Generating embeddings using Google text-embedding-004...")
    vectors_to_upsert = []

    for idx, policy in enumerate(policies):
        # Build searchable text
        text = build_chunk_text(policy)
        if not text:
            logger.warning("Policy %s has no text, skipping", policy.get('_id', idx))
            continue

        try:
            embedding = get_google_embedding(text, google_api_key)
            if len(embedding) != 768:
                logger.warning("Embedding dimension mismatch for policy %s, skipping", policy.get('_id'))
                continue

            # Prepare metadata (no None/null values allowed in Pinecone)
            # Bug 12 fix: store classification_levels as a list so that Pinecone
            # $in filters work correctly (e.g. {"classification_levels": {"$in": ["III"]}}).
            # Previously this was collapsed to a single comma-joined string which
            # made metadata filtering impossible.
            classification_levels = policy.get("classification_levels", []) or []

            vectors_to_upsert.append({
                "id": policy.get("_id", f"policy-{idx}"),
                "values": embedding,
                "metadata": {
                    "chunk_text": text,
                    "control_id": policy.get("control_id") or "",
                    "risk_area": policy.get("risk_area") or "",
                    "classification_levels": classification_levels,  # list, not string
                    "is_exception_related": bool(policy.get("is_exception_related")),
                    "requires_approval": bool(policy.get("requires_approval")),
                    "approver_role": policy.get("approver_role") or ""
                }
            })

            if (idx + 1) % 10 == 0:
                logger.info("Processed %d/%d policies...", idx + 1, len(policies))

        except Exception as e:
            logger.error("Error processing policy %s: %s", policy.get('_id'), e)
            continue

    dense_index = pc.Index(index_name)
    logger.info("Upserting %d vectors to index '%s'...", len(vectors_to_upsert), index_name)

    # Upsert in batches of 100
    batch_size = 100
    for i in range(0, len(vectors_to_upsert), batch_size):
        batch = vectors_to_upsert[i:i + batch_size]
        dense_index.upsert(
            vectors=batch,
            namespace="policy-and-exemption-criterion"
        )
        logger.info("Upserted batch %d (%d vectors)", i // batch_size + 1, len(batch))

    logger.info("Successfully upserted %d vectors", len(vectors_to_upsert))

    # Verify indexing
    logger.info("Verifying index...")
    time.sleep(2)  # Brief wait for indexing
    stats = dense_index.describe_index_stats()
    logger.info("Index stats: %s", stats)

def delete_index():
    if pc.has_index(index_name):
        pc.delete_index(index_name)

def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logger.info("Initializing index...")
    initialize_index()
    logger.info("Upserting data...")
    upsert_data()
    logger.info("Done!")

if __name__ == "__main__":
    main()