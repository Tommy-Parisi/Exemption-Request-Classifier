from pinecone import Pinecone, ServerlessSpec as pc
from dotenv import load_dotenv
import os
import time
import csv
import json
import re

load_dotenv()


_PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
if _PINECONE_API_KEY:
   pc = Pinecone(api_key=_PINECONE_API_KEY)
else:
   pc = None


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
   # Load records from data/data.json (support list, dict with embedded list, or JSONL)
   records = []
   json_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'data.json')
   json_path = os.path.normpath(json_path)
   if not os.path.exists(json_path):
       raise FileNotFoundError(f"JSON file not found: {json_path}")


   with open(json_path, encoding='utf-8') as fh:
       raw = fh.read().strip()


   # Strip code fences if present
   if raw.startswith('```'):
       raw = raw.lstrip('`').rstrip('`').strip()


   # Try to parse JSON. Support several common shapes: list, dict, or JSONL (one JSON per line)
   items = None
   try:
       parsed = json.loads(raw)
       if isinstance(parsed, list):
           items = parsed
       elif isinstance(parsed, dict):
           # common wrappers
           if 'items' in parsed and isinstance(parsed['items'], list):
               items = parsed['items']
           elif 'data' in parsed and isinstance(parsed['data'], list):
               items = parsed['data']
           else:
               items = [parsed]
       else:
           items = [parsed]
   except json.JSONDecodeError:
       # Fall back to JSONL: try to parse each non-empty line as JSON
       items = []
       for line in raw.splitlines():
           line = line.strip()
           if not line:
               continue
           try:
               items.append(json.loads(line))
           except Exception:
               # If that fails, try to extract top-level JSON objects with a regex
               pattern = r'\{[^{}]*\}'
               matches = re.findall(pattern, raw, re.DOTALL)
               for match in matches:
                   try:
                       items.append(json.loads(match))
                   except Exception:
                       continue
               break


   # Normalize items to records expected by upsert
   for item in items:
       if not isinstance(item, dict):
           continue
       rec_id = item.get('_id') or item.get('id')
       # Build a useful text blob if no explicit text field exists in the JSON.
       text = item.get('chunk_text') or item.get('text') or item.get('content')
       if not text:
           parts = []
           # include control id/title
           if item.get('control_id'):
               parts.append(str(item.get('control_id')))
           if item.get('risk_area'):
               parts.append(str(item.get('risk_area')))
           # requirements may be a list — join into sentences
           reqs = item.get('requirements')
           if isinstance(reqs, list):
               parts.append(' '.join([r.strip() for r in reqs if isinstance(r, str) and r.strip()]))
           elif isinstance(reqs, str) and reqs.strip():
               parts.append(reqs.strip())
           # include note and references and nist_reference
           for fld in ('note', 'references', 'nist_reference'):
               val = item.get(fld)
               if isinstance(val, str) and val.strip():
                   parts.append(val.strip())


           text = ' '.join([p for p in parts if p]) or None
       category = item.get('category')
       if not rec_id:
           rec_id = f"rec-{len(records)+1}"
       records.append({"_id": rec_id, "chunk_text": text or "", "category": category or ""})


   print(f"Loaded {len(records)} records from JSON: {json_path}")


   # If Pinecone client is not configured, skip the upsert but return success info
   if pc is None:
       print("PINECONE_API_KEY not set; skipping upsert to Pinecone. Records prepared but not uploaded.")
       return


   # Filter out records with empty text — the embedding model requires non-empty inputs
   filtered = [r for r in records if r.get('chunk_text') and r['chunk_text'].strip()]
   dropped = len(records) - len(filtered)
   if dropped > 0:
       dropped_ids = [r.get('_id') for r in records if not (r.get('chunk_text') and r['chunk_text'].strip())]
       print(f"Dropped {dropped} records with empty text (sample ids: {dropped_ids[:5]})")
   records = filtered


   if len(records) == 0:
       print("No non-empty records to upsert after filtering — skipping Pinecone upsert.")
       return


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