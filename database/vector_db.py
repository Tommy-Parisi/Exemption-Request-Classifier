import logging
from google.cloud import firestore
from google.cloud.firestore_v1.vector import Vector
from dotenv import load_dotenv
import os
import json
import requests

load_dotenv()

logger = logging.getLogger(__name__)

project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
collection_name = os.getenv("FIRESTORE_COLLECTION", "policies")


database_id = os.getenv("FIRESTORE_DATABASE", "policies")


def get_firestore_client():
    """Return a Firestore client, using project and database from env if set."""
    if project_id:
        return firestore.Client(project=project_id, database=database_id)
    return firestore.Client(database=database_id)


def get_google_embedding(text, api_key):
    """Generate embedding using Google's gemini-embedding-001 model (768 dimensions)."""
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-001:embedContent"
    headers = {"Content-Type": "application/json"}
    params = {"key": api_key}

    data = {
        "model": "models/gemini-embedding-001",
        "content": {"parts": [{"text": text}]},
        "task_type": "RETRIEVAL_DOCUMENT",
        "outputDimensionality": 768
    }

    response = requests.post(url, headers=headers, params=params, json=data, timeout=30)
    response.raise_for_status()

    result = response.json()
    embedding = result.get("embedding", {}).get("values", [])
    return embedding


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
    """Load policies from data.json, generate embeddings, and write to Firestore."""
    json_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'data.json')

    with open(json_path, encoding='utf-8') as f:
        policies = json.load(f)

    if not isinstance(policies, list):
        policies = [policies]

    logger.info("Loaded %d policies from JSON", len(policies))

    google_api_key = os.getenv("LLM_API_KEY")
    if not google_api_key:
        raise ValueError("LLM_API_KEY environment variable not set")

    db = get_firestore_client()
    col = db.collection(collection_name)

    logger.info("Generating embeddings and writing to Firestore collection '%s'...", collection_name)
    success_count = 0

    for idx, policy in enumerate(policies):
        text = build_chunk_text(policy)
        if not text:
            logger.warning("Policy %s has no text, skipping", policy.get('_id', idx))
            continue

        try:
            embedding = get_google_embedding(text, google_api_key)
            if len(embedding) != 768:
                logger.warning("Embedding dimension mismatch for policy %s, skipping", policy.get('_id'))
                continue

            doc_id = policy.get("_id", f"policy-{idx}")
            doc_data = {
                "embedding": Vector(embedding),
                "chunk_text": text,
                "control_id": policy.get("control_id") or "",
                "risk_area": policy.get("risk_area") or "",
                "classification_levels": policy.get("classification_levels") or [],
                "is_exception_related": bool(policy.get("is_exception_related")),
                "requires_approval": bool(policy.get("requires_approval")),
                "approver_role": policy.get("approver_role") or "",
            }

            col.document(doc_id).set(doc_data)
            success_count += 1

            if (idx + 1) % 10 == 0:
                logger.info("Processed %d/%d policies...", idx + 1, len(policies))

        except Exception as e:
            logger.error("Error processing policy %s: %s", policy.get('_id'), e)
            continue

    logger.info("Successfully wrote %d/%d policies to Firestore", success_count, len(policies))


def delete_collection():
    """Delete all documents in the policies collection."""
    db = get_firestore_client()
    col = db.collection(collection_name)
    docs = col.stream()
    deleted = 0
    for doc in docs:
        doc.reference.delete()
        deleted += 1
    logger.info("Deleted %d documents from collection '%s'", deleted, collection_name)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logger.info("Upserting policy data to Firestore...")
    upsert_data()
    logger.info("Done!")


if __name__ == "__main__":
    main()
