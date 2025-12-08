#!/usr/bin/env python3
"""
Test script to verify environment configuration and API connectivity.
This script will test both Pinecone and Gemini API connections.
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_environment_variables():
    """Check if all required environment variables are set."""
    print("=== Environment Variables Check ===")
    
    required_vars = [
        'PINECONE_API_KEY',
        'PINECONE_INDEX', 
        'LLM_API_KEY',
        'LLM_API_URL'
    ]
    
    for var in required_vars:
        value = os.getenv(var)
        if value:
            print(f"{var}: {'*' * (len(value) - 10)}...{value[-6:]}")
        else:
            print(f"{var}: Not set")
    
    print()

def test_pinecone_connection():
    """Test Pinecone API connectivity."""
    print("=== Pinecone Connection Test ===")
    
    try:
        from pinecone import Pinecone
        
        api_key = os.getenv('PINECONE_API_KEY')
        index_name = os.getenv('PINECONE_INDEX', 'policies')
        
        if not api_key:
            print("PINECONE_API_KEY not set")
            return
            
        pc = Pinecone(api_key=api_key)
        
        indexes = pc.list_indexes()
        print("Pinecone connection successful")
        print(f"Available indexes: {[idx.name for idx in indexes]}")
        
        if index_name in [idx.name for idx in indexes]:
            print(f"Target index '{index_name}' found")
            
            index = pc.Index(index_name)
            stats = index.describe_index_stats()
            print(f"Index stats: {stats.total_vector_count} vectors")
        else:
            print(f"Target index '{index_name}' not found. Available: {[idx.name for idx in indexes]}")
            
    except Exception as e:
        print(f"Pinecone connection failed: {e}")
    
    print()

def test_gemini_connection():
    """Test Gemini API connectivity."""
    print("=== Gemini API Connection Test ===")
    
    try:
        import requests
        import json
        
        api_key = os.getenv('LLM_API_KEY')
        api_url = os.getenv('LLM_API_URL')
        
        if not api_key or not api_url:
            print("LLM_API_KEY or LLM_API_URL not set")
            return
            
        # Simple test prompt
        test_prompt = "Respond with exactly: 'API connection successful'"
        
        headers = {"Content-Type": "application/json"}
        body = {
            "contents": [{
                "parts": [{
                    "text": test_prompt
                }]
            }],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 50,
                "candidateCount": 1
            }
        }
        
        url_with_key = f"{api_url}?key={api_key}"
        
        response = requests.post(url_with_key, headers=headers, data=json.dumps(body), timeout=10)
        response.raise_for_status()
        
        data = response.json()
        candidates = data.get("candidates", [])
        
        if candidates:
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            if parts:
                response_text = parts[0].get("text", "").strip()
                print("Gemini API connection successful")
                print(f"Response: {response_text}")
            else:
                print("Unexpected response structure")
        else:
            print("No response candidates returned")
            
    except Exception as e:
        print(f"Gemini API connection failed: {e}")
    
    print()

def test_rag_integration():
    """Test the RAG integration initialization."""
    print("=== RAG Integration Test ===")
    
    try:
        from engine.rag_integration import RAGIntegrator
        
        # Initialize with real config
        rag = RAGIntegrator()
        print("RAGIntegrator initialized successfully")
        
        # Test with a simple mock compliance check
        test_request = {
            "id": "TEST-001",
            "exception_type": "test",
            "data_level": 1,
            "security_controls": ["basic_firewall"]
        }
        
        print("Running test compliance check...")
        
        # Note: This will use fallback embedding since we haven't set up a real embedding provider
        compliance = rag.policy_compliance_checker(test_request)
        print(f"Compliance check completed: {compliance['compliance_status']}")
        
        rag.close()
        
    except Exception as e:
        print(f"RAG integration test failed: {e}")
        import traceback
        traceback.print_exc()
    
    print()

if __name__ == "__main__":
    print("RAG Integration Environment Test")
    print("=" * 50)
    print()
    
    test_environment_variables()
    test_pinecone_connection()
    test_gemini_connection() 
    test_rag_integration()