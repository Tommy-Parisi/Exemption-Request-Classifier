#!/usr/bin/env python3
"""
RAG Integration Demonstration with Real Data

This script demonstrates the complete RAG (Retrieval Augmented Generation) workflow
using real policy data from the Pinecone vector database and Google Gemini LLM.

The demonstration includes:
1. Environment connectivity verification
2. Policy search across different security domains
3. Policy compliance checking for realistic exception requests
4. Risk narrative generation for executive reporting
5. Integration with decision engine workflow

Requirements:
- Configured .env file with valid API keys
- Active Pinecone index with policy data
- Google Gemini API access
"""

import os
import sys
import json
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

from engine.rag_integration import RAGIntegrator


def print_header(title: str, width: int = 70):
    """Print a formatted section header."""
    print("\n" + "=" * width)
    print(f" {title} ".center(width))
    print("=" * width)


def print_subheader(title: str, width: int = 70):
    """Print a formatted subsection header."""
    print(f"\n{'-' * width}")
    print(f" {title}")
    print(f"{'-' * width}")


def verify_environment():
    """Verify that the environment is properly configured."""
    print_header("Environment Verification")
    
    required_vars = [
        'PINECONE_API_KEY',
        'LLM_API_KEY',
        'PINECONE_INDEX',
        'LLM_API_URL'
    ]
    
    missing_vars = []
    for var in required_vars:
        value = os.getenv(var)
        if value:
            # Mask sensitive values
            if 'KEY' in var:
                display_value = f"{value[:8]}..." if len(value) > 8 else value
            else:
                display_value = value
            print(f"[PASS] {var}: {display_value}")
        else:
            missing_vars.append(var)
            print(f"[FAIL] {var}: Not set")
    
    if missing_vars:
        print(f"\nERROR: Missing required environment variables: {', '.join(missing_vars)}")
        print("Please check your .env file configuration.")
        return False
    
    print("\nSUCCESS: Environment configuration complete!")
    return True


def demonstrate_policy_search(rag: RAGIntegrator):
    """Demonstrate policy search capabilities."""
    print_header("Policy Search Demonstration")
    
    # Test queries across different security domains
    search_scenarios = [
        {
            "query": "cloud database encryption Level III",
            "description": "Cloud hosting security for sensitive data"
        },
        {
            "query": "access control authentication requirements",
            "description": "User authentication and access policies"
        },
        {
            "query": "incident response reporting procedures",
            "description": "Security incident handling protocols"
        },
        {
            "query": "vendor risk management assessment",
            "description": "Third-party vendor security evaluation"
        },
        {
            "query": "network security controls monitoring",
            "description": "Network infrastructure protection"
        }
    ]
    
    for scenario in search_scenarios:
        print_subheader(f"Search: {scenario['description']}")
        print(f"Query: '{scenario['query']}'")
        
        try:
            matches = rag.hybrid_search(scenario['query'], top_k=3)
            print(f"Found {len(matches)} relevant policies:\n")
            
            for i, match in enumerate(matches, 1):
                print(f"{i}. Policy ID: {match.id}")
                print(f"   Relevance Score: {match.score:.4f}")
                print(f"   Text Preview: {match.text[:200]}...")
                if match.metadata:
                    print(f"   Category: {match.metadata.get('category', 'N/A')}")
                print()
                
        except Exception as e:
            print(f"ERROR: Search failed: {e}")


def demonstrate_compliance_checking(rag: RAGIntegrator):
    """Demonstrate policy compliance checking with realistic scenarios."""
    print_header("Policy Compliance Analysis")
    
    # Realistic exception request scenarios
    exception_scenarios = [
        {
            "name": "AWS Cloud Database Migration",
            "request": {
                "id": "EXC-2025-001",
                "exception_type": "cloud database hosting",
                "data_level": "Level III",
                "security_controls": ["encryption at rest", "encryption in transit", "VPN access"],
                "description": "Migration of employee payroll database to AWS RDS with enhanced security controls",
                "business_justification": "Cost reduction and improved scalability for HR operations",
                "duration": "permanent",
                "affected_systems": ["payroll-db", "hr-portal"]
            }
        },
        {
            "name": "Temporary Legacy System Exception",
            "request": {
                "id": "EXC-2025-002", 
                "exception_type": "outdated operating system",
                "data_level": "Level II",
                "security_controls": ["network isolation", "enhanced monitoring"],
                "description": "Legacy manufacturing control system running Windows Server 2012",
                "business_justification": "Critical production system with vendor-specific software dependencies",
                "duration": "6 months",
                "affected_systems": ["manufacturing-control", "inventory-tracking"]
            }
        },
        {
            "name": "Mobile Device BYOD Policy",
            "request": {
                "id": "EXC-2025-003",
                "exception_type": "bring your own device",
                "data_level": "Level II", 
                "security_controls": ["MDM enrollment", "app containerization"],
                "description": "Executive mobile access to corporate email and documents",
                "business_justification": "Remote work flexibility for senior leadership",
                "duration": "12 months",
                "affected_systems": ["email", "document-management"]
            }
        }
    ]
    
    for scenario in exception_scenarios:
        print_subheader(scenario['name'])
        print(f"Request ID: {scenario['request']['id']}")
        print(f"Type: {scenario['request']['exception_type']}")
        print(f"Data Level: {scenario['request']['data_level']}")
        print(f"Description: {scenario['request']['description']}")
        
        try:
            # Perform compliance analysis
            compliance_result = rag.policy_compliance_checker(
                exception_request=scenario['request'],
                top_k=5
            )
            
            print(f"\nCompliance Analysis Results:")
            print(f"Status: {compliance_result['compliance_status']}")
            
            if compliance_result['violations']:
                print(f"\nPotential Violations ({len(compliance_result['violations'])}):")
                for i, violation in enumerate(compliance_result['violations'], 1):
                    print(f"  {i}. {violation}")
            
            if compliance_result['required_controls']:
                print(f"\nRequired Controls ({len(compliance_result['required_controls'])}):")
                for i, control in enumerate(compliance_result['required_controls'][:5], 1):
                    print(f"  {i}. {control}")
                if len(compliance_result['required_controls']) > 5:
                    print(f"     ... and {len(compliance_result['required_controls']) - 5} more")
            
            if compliance_result['policy_refs']:
                print(f"\nReferenced Policies: {', '.join(compliance_result['policy_refs'])}")
            
        except Exception as e:
            print(f"ERROR: Compliance check failed: {e}")
        
        print()


def demonstrate_risk_narrative(rag: RAGIntegrator):
    """Demonstrate risk narrative generation for executive reporting."""
    print_header("Executive Risk Narrative Generation")
    
    # Example risk scenarios
    risk_scenarios = [
        {
            "name": "High-Risk Cloud Migration",
            "risk_score": 78.5,
            "factors": {
                "data_classification": "Level III (PII, Financial)",
                "environment": "Public Cloud (AWS)",
                "compliance_requirements": ["SOX", "GDPR", "University Policy"],
                "existing_controls": ["Encryption at rest", "Network isolation", "Access logging"],
                "missing_controls": ["DLP", "Real-time monitoring", "Incident response plan"],
                "business_impact": "High - Critical HR operations",
                "implementation_timeline": "6 months"
            },
            "policy_refs": ["DM-3.2.3", "AS-2.1.5", "AQ-1.2.2"]
        },
        {
            "name": "Medium-Risk Legacy System",
            "risk_score": 65.0,
            "factors": {
                "data_classification": "Level II (Internal Use)",
                "environment": "On-premises legacy infrastructure",
                "compliance_requirements": ["Internal Security Standards"],
                "existing_controls": ["Network segmentation", "Enhanced monitoring"],
                "missing_controls": ["OS patching", "Modern authentication"],
                "business_impact": "Medium - Manufacturing operations",
                "implementation_timeline": "Temporary (6 months)"
            },
            "policy_refs": ["AS-1.1.1", "IA-1.1.1"]
        }
    ]
    
    for scenario in risk_scenarios:
        print_subheader(f"{scenario['name']} (Risk Score: {scenario['risk_score']}/100)")
        
        try:
            narrative = rag.generate_risk_narrative(
                risk_score=scenario['risk_score'],
                factors=scenario['factors'],
                policy_refs=scenario['policy_refs']
            )
            
            print("Executive Risk Assessment:")
            print()
            # Format the narrative with proper line breaks
            paragraphs = narrative.split('\n\n')
            for paragraph in paragraphs:
                if paragraph.strip():
                    print(f"   {paragraph.strip()}")
                    print()
            
        except Exception as e:
            print(f"ERROR: Risk narrative generation failed: {e}")

def run_full_demonstration():
    """Run the complete RAG demonstration."""
    print_header("RAG Integration", 80)
    
    # Verify environment
    if not verify_environment():
        return False
    
    try:
        # Initialize RAG system
        print("\nInitializing RAG Integration...")
        rag = RAGIntegrator()
        print("SUCCESS: RAG system initialized successfully!")
        
        # Display system information
        print(f"System Configuration:")
        print(f"   • Index dimension: {rag._index_dimension}")
        print(f"   • Available namespaces: {rag._namespaces}")
        print(f"   • Default namespace: '{rag._default_namespace}'")
        
        # Run demonstrations
        demonstrate_policy_search(rag)
        demonstrate_compliance_checking(rag)
        demonstrate_risk_narrative(rag)
        
        return True
        
    except Exception as e:
        print(f"\nERROR: Demonstration failed: {e}")
        print("Please check your configuration and try again.")
        return False


if __name__ == "__main__":
    success = run_full_demonstration()
    sys.exit(0 if success else 1)