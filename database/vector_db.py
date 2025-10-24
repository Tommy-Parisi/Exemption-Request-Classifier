from pinecone import Pinecone, ServerlessSpec as pc
from dotenv import load_dotenv
import os
import time
import csv
import json
import re

load_dotenv()

pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))

index_name = "exemption-policy"

def initialize_index():
    if not pc.has_index(index_name):
        pc.create_index_for_model(
            name=index_name,
            cloud="aws",
            region="us-east-1",
            embed={
                "model":"llama-text-embed-v2",
                "field_map":{"text": "chunk_text"}
            }
        )

def upsert_data():
    # Load records from data/data.csv
    records = []
    csv_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'data.csv')
    csv_path = os.path.normpath(csv_path)
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    with open(csv_path, encoding='utf-8') as fh:
        raw = fh.read().strip()

    # Strip code fences if present
    if raw.startswith('```'):
        raw = raw.lstrip('`').rstrip('`').strip()
    
    # Find all JSON objects: { ... }
    pattern = r'\{[^{}]*\}'
    matches = re.findall(pattern, raw, re.DOTALL)
    
    for match in matches:
        try:
            item = json.loads(match)
            rec_id = item.get('_id') or item.get('id')
            text = item.get('chunk_text') or item.get('text')
            category = item.get('category')
            if not rec_id:
                rec_id = f"rec-{len(records)+1}"
            records.append({"_id": rec_id, "chunk_text": text or "", "category": category or ""})
        except Exception as e:
            print(f"Warning: Failed to parse JSON object: {e}")
            continue
    
    print(f"Loaded {len(records)} records from CSV")

    dense_index = pc.Index(index_name)
    print(f"Upserting {len(records)} records to index '{index_name}'...")
    dense_index.upsert_records("policy-and-exemption-criterion", records)

    # Poll until the namespace has at least the number of upserted vectors
    namespace = "policy-and-exemption-criterion"
    expected_count = len(records)
    timeout = 60  # seconds
    interval = 5  # seconds
    start = time.time()

    print(f"Waiting for {expected_count} vectors to be indexed in namespace '{namespace}'...")
    while True:
        try:
            stats = dense_index.describe_index_stats()
            
            vector_count = 0
            if hasattr(stats, 'namespaces') and namespace in stats.namespaces:
                ns = stats.namespaces[namespace]
                vector_count = ns.get('vector_count', 0) if isinstance(ns, dict) else getattr(ns, 'vector_count', 0)
            
            print(f"Current vectors in namespace: {vector_count}")
            if int(vector_count) >= expected_count:
                print(f"Index ready!")
                break
        except Exception as e:
            # Keep trying until timeout
            print(f"(polling... error: {type(e).__name__}: {e})")
            pass

        if time.time() - start > timeout:
            raise TimeoutError(f"Timed out waiting for index namespace '{namespace}' to reach {expected_count} vectors")

        time.sleep(interval)

    # Once ready, print stats
    stats = dense_index.describe_index_stats()
    print("Index stats:")

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