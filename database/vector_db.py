from pinecone import Pinecone, ServerlessSpec
from dotenv import load_dotenv
import os
import time
import json
import requests

load_dotenv()

pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))

index_name = "exemption-policy"

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

    print(f"Loaded {len(policies)} policies from JSON")

    # Get Google API key for embeddings
    google_api_key = os.getenv("LLM_API_KEY")
    if not google_api_key:
        raise ValueError("LLM_API_KEY environment variable not set")

    # Generate embeddings and prepare vectors
    print(f"Generating embeddings using Google text-embedding-004...")
    vectors_to_upsert = []

    for idx, policy in enumerate(policies):
        # Build searchable text
        text = build_chunk_text(policy)
        if not text:
            print(f"Warning: Policy {policy.get('_id', idx)} has no text, skipping")
            continue

        try:
            embedding = get_google_embedding(text, google_api_key)
            if len(embedding) != 768:
                print(f"Warning: Embedding dimension mismatch for {policy.get('_id')}, skipping")
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
                print(f"  Processed {idx + 1}/{len(policies)} policies...")

        except Exception as e:
            print(f"Error processing policy {policy.get('_id')}: {e}")
            continue

    dense_index = pc.Index(index_name)
    print(f"Upserting {len(vectors_to_upsert)} vectors to index '{index_name}'...")

    # Upsert in batches of 100
    batch_size = 100
    for i in range(0, len(vectors_to_upsert), batch_size):
        batch = vectors_to_upsert[i:i + batch_size]
        dense_index.upsert(
            vectors=batch,
            namespace="policy-and-exemption-criterion"
        )
        print(f"Upserted batch {i // batch_size + 1} ({len(batch)} vectors)")

    print(f"\nSuccessfully upserted {len(vectors_to_upsert)} vectors!")

    # Verify indexing
    print("Verifying index...")
    time.sleep(2)  # Brief wait for indexing
    stats = dense_index.describe_index_stats()
    print(f"Index stats: {stats}")

def delete_index():
    if pc.has_index(index_name):
        pc.delete_index(index_name)

def main():
    print("Initializing index...")
    initialize_index()
    print("Upserting data...")
    upsert_data()
    print("Done!")
    # delete_index()

if __name__ == "__main__":
    main()