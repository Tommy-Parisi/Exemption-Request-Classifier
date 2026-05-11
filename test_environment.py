#!/usr/bin/env python3
"""
Connectivity check for the Exception Request Classifier.
Run this after setup to verify all services are reachable before starting the server.
"""

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()


def test_environment_variables():
    print("=== Environment Variables ===")
    required = {
        "GOOGLE_CLOUD_PROJECT": "GCP project ID",
        "GOOGLE_APPLICATION_CREDENTIALS": "Path to service account key",
        "LLM_API_KEY": "Google API key for embeddings and LLM",
        "GOOGLE_API_KEY": "Google API key for chat assistant",
    }
    all_ok = True
    for var, description in required.items():
        value = os.getenv(var)
        if value:
            display = f"{value[:8]}..." if "KEY" in var or "CREDENTIALS" in var else value
            print(f"  [OK]   {var}: {display}  ({description})")
        else:
            print(f"  [FAIL] {var}: not set  ({description})")
            all_ok = False
    print()
    return all_ok


def test_firestore_connection():
    print("=== Firestore Connection ===")
    try:
        from google.cloud import firestore

        project = os.getenv("GOOGLE_CLOUD_PROJECT")
        database = os.getenv("FIRESTORE_DATABASE", "policies")
        collection = os.getenv("FIRESTORE_COLLECTION", "policies")

        db = firestore.Client(project=project, database=database)
        docs = list(db.collection(collection).limit(1).stream())
        count = len(docs)
        print(f"  [OK]   Connected to project={project} database={database}")
        print(f"  [OK]   Collection '{collection}' reachable — sample doc count: {count}")
        if count == 0:
            print("  [WARN] Collection is empty. Run `python database/vector_db.py` to load policies.")
        print()
        return True
    except Exception as e:
        print(f"  [FAIL] {e}")
        print()
        return False


def test_gemini_api():
    print("=== Gemini API (LLM) ===")
    try:
        api_key = os.getenv("LLM_API_KEY")
        api_url = os.getenv(
            "LLM_API_URL",
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
        )
        body = {
            "contents": [{"parts": [{"text": "Reply with exactly: ok"}]}],
            "generationConfig": {"temperature": 0.0, "maxOutputTokens": 10},
        }
        resp = requests.post(f"{api_url}?key={api_key}", json=body, timeout=15)
        resp.raise_for_status()
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        print(f"  [OK]   Gemini LLM reachable — response: '{text}'")
        print()
        return True
    except Exception as e:
        print(f"  [FAIL] {e}")
        print()
        return False


def test_embedding_api():
    print("=== Embedding API ===")
    try:
        api_key = os.getenv("LLM_API_KEY")
        url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-001:embedContent"
        resp = requests.post(
            url,
            params={"key": api_key},
            json={
                "model": "models/gemini-embedding-001",
                "content": {"parts": [{"text": "test"}]},
                "task_type": "RETRIEVAL_QUERY",
                "outputDimensionality": 768,
            },
            timeout=15,
        )
        resp.raise_for_status()
        dim = len(resp.json()["embedding"]["values"])
        print(f"  [OK]   Embedding API reachable — dimension: {dim}")
        print()
        return True
    except Exception as e:
        print(f"  [FAIL] {e}")
        print()
        return False


if __name__ == "__main__":
    print("Exception Request Classifier — Environment Check")
    print("=" * 50)
    print()

    results = [
        test_environment_variables(),
        test_firestore_connection(),
        test_gemini_api(),
        test_embedding_api(),
    ]

    if all(results):
        print("All checks passed. You're ready to start the server.")
    else:
        print("Some checks failed. Review the output above before starting the server.")
