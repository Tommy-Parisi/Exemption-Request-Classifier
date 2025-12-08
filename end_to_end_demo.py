#!/usr/bin/env python3
"""
End-to-End RAG Pipeline Demonstration

This script demonstrates ONE exception request flowing through the ENTIRE pipeline:
1. Exception Request Submission
2. Policy Search (Hybrid Search)
3. Compliance Analysis (RAG + LLM)
4. Risk Score Calculation
5. Risk Narrative Generation
6. Decision Engine Recommendation

This demnonstrates the production workflow
"""

import os
import sys
import json
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

from engine.rag_integration import RAGIntegrator
from engine.risk_scorrer import calculate_risk_score
from engine.decision_engine import make_exception_decision


def print_header(title: str, width: int = 80):
    print("\n" + "=" * width)
    print(f" {title} ".center(width))
    print("=" * width)


def print_subheader(title: str, width: int = 80):
    print(f"\n{'-' * width}")
    print(f"  {title}")
    print(f"{'-' * width}")


def print_step(step_num: int, title: str):
    print(f"\n[STEP {step_num}] {title}")


def convert_exception_request_to_form_data(exception_request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert exception request format to risk_scorer form_data format.

    This is a critical integration function that maps between the two data models.
    """
    # Extract data levels
    data_level_map = {
        "Level I": 1,
        "Level 1": 1,
        1: 1,
        "Level II": 2,
        "Level 2": 2,
        2: 2,
        "Level III": 3,
        "Level 3": 3,
        3: 3
    }

    data_level = data_level_map.get(exception_request.get('data_level'), 2)

    # Extract security controls
    security_controls = exception_request.get('security_controls', [])

    # Map controls to boolean flags
    has_vulnerability_scanning = any(
        'vuln' in ctrl.lower() or 'scan' in ctrl.lower()
        for ctrl in security_controls
    )
    has_edr = any(
        'edr' in ctrl.lower() or 'crowdstrike' in ctrl.lower() or 'endpoint' in ctrl.lower()
        for ctrl in security_controls
    )
    has_firewall = any(
        'firewall' in ctrl.lower() for ctrl in security_controls
    )

    # Determine firewall level
    if has_firewall:
        firewall_level = 'adequate'
    else:
        firewall_level = 'minimal'

    # Check for network exposure indicators
    description = exception_request.get('description', '').lower()
    has_public_ip = (
        'public ip' in description or
        'internet-facing' in description or
        'public-facing' in description or
        exception_request.get('exception_type', '').lower() in ['cloud hosting', 'cloud database hosting']
    )

    # Determine OS update status based on exception type
    exception_type = exception_request.get('exception_type', '').lower()
    os_up_to_date = 'outdated' not in exception_type and 'legacy' not in exception_type

    # Determine patch frequency based on exception type
    if 'legacy' in exception_type or 'outdated' in exception_type:
        os_patch_freq = 'yearly+'
        app_patch_freq = 'yearly+'
    else:
        os_patch_freq = 'quarterly'
        app_patch_freq = 'quarterly'

    # Determine impact based on description
    business_justification = exception_request.get('business_justification', '').lower()
    if 'critical' in business_justification or 'essential' in business_justification:
        server_dependencies = 'excessive'
        user_dependencies = 'excessive'
        university_importance = 'excessive'
    elif 'important' in business_justification or 'significant' in business_justification:
        server_dependencies = 'moderate'
        user_dependencies = 'moderate'
        university_importance = 'excessive'
    else:
        server_dependencies = 'low'
        user_dependencies = 'low'
        university_importance = 'moderate'

    form_data = {
        'data_stored_level': data_level,
        'data_access_level': data_level,
        'allow_vulnerability_scanning': has_vulnerability_scanning,
        'allow_edr_crowdstrike': has_edr,
        'local_firewall': firewall_level,
        'network_firewall': firewall_level,
        'os_up_to_date': os_up_to_date,
        'has_public_ip': has_public_ip,
        'management_network_access': has_public_ip,  # Conservative assumption
        'os_patch_frequency': os_patch_freq,
        'app_patch_frequency': app_patch_freq,
        'server_dependencies': server_dependencies,
        'user_dependencies': user_dependencies,
        'university_importance': university_importance
    }

    return form_data


def run_end_to_end_pipeline():
    """Run ONE exception request through the ENTIRE pipeline."""

    print_header("END-TO-END RAG PIPELINE DEMONSTRATION", 80)
    print("This demo shows ONE exception request flowing through ALL pipeline stages.")
    print("Each step builds on the results from the previous step.")

    # ========================================
    # STEP 0: Define the Exception Request
    # ========================================
    print_step(0, "Exception Request Submission")

    exception_request = {
        "id": "EXC-2025-001",
        "exception_type": "cloud database hosting",
        "data_level": "Level III",
        "security_controls": [
            "encryption at rest",
            "encryption in transit",
            "VPN access",
            "network isolation"
        ],
        "description": "Migration of employee payroll database to AWS RDS with enhanced security controls",
        "business_justification": "Critical cost reduction and improved scalability for HR operations. Legacy on-premises database reaching end-of-life.",
        "duration": "permanent",
        "affected_systems": ["payroll-db", "hr-portal", "benefits-system"],
        "requestor": "Jane Smith, VP of Human Resources",
        "department": "Human Resources"
    }

    print("\nException Request Details:")
    print(f"   Request ID: {exception_request['id']}")
    print(f"   Type: {exception_request['exception_type']}")
    print(f"   Data Classification: {exception_request['data_level']}")
    print(f"   Requestor: {exception_request['requestor']}")
    print(f"   Description: {exception_request['description']}")
    print(f"   Security Controls: {', '.join(exception_request['security_controls'])}")
    print(f"   Affected Systems: {', '.join(exception_request['affected_systems'])}")

    # Check environment
    print("\nChecking environment configuration...")
    required_vars = ['PINECONE_API_KEY', 'LLM_API_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]

    if missing_vars:
        print(f"[WARNING] Missing environment variables: {', '.join(missing_vars)}")
        print("          The demo will use fallback/mock data for missing services.")
    else:
        print("[SUCCESS] Environment configured successfully")

    # Initialize RAG system
    print("\nInitializing RAG Integration...")
    try:
        rag = RAGIntegrator()
        print(f"[SUCCESS] RAG system initialized")
        print(f"          Index dimension: {rag._index_dimension}")
        print(f"          Pinecone namespace: '{rag._default_namespace}'")
    except Exception as e:
        print(f"[ERROR] Failed to initialize RAG system: {e}")
        return False

    # ========================================
    # STEP 1: Policy Search
    # ========================================
    print_step(1, "Policy Search (Hybrid Search)")

    print(f"\nSearching for policies relevant to: '{exception_request['exception_type']}'")
    print(f"Data level: {exception_request['data_level']}")
    print(f"Note: Not using metadata filter since Pinecone uses 'classification_levels' (string)")
    print(f"      instead of 'classification_level' (int). Semantic search will find relevant policies.")

    try:
        # NOTE: The Pinecone index uses 'classification_levels': 'I, II, III' (string)
        # not 'classification_level': 3 (int), so we don't use metadata filters.
        # The semantic search and keywords will find the right policies anyway.

        # Build search query that includes data level
        search_query = f"{exception_request['exception_type']} {exception_request['data_level']}"

        # Perform hybrid search
        policy_matches = rag.hybrid_search(
            query=search_query,
            top_k=5,
            metadata_filter=None,  # Not using filter - see note above
            keywords=[exception_request['exception_type']] + exception_request['security_controls']
        )

        print(f"\n[RESULT] Found {len(policy_matches)} relevant policies:\n")

        for i, match in enumerate(policy_matches, 1):
            print(f"   {i}. Policy ID: {match.id}")
            print(f"      Relevance Score: {match.score:.4f}")
            print(f"      Preview: {match.text[:150]}...")
            if match.metadata:
                print(f"      Metadata: {match.metadata}")
            print()

        # Store for later use
        policy_search_results = policy_matches

    except Exception as e:
        print(f"[ERROR] Policy search failed: {e}")
        policy_search_results = []

    # ========================================
    # STEP 2: Compliance Analysis
    # ========================================
    print_step(2, "Policy Compliance Analysis (RAG + LLM)")

    print("\nAnalyzing exception request against retrieved policies...")
    print("This step uses the LLM to assess compliance and identify violations.")

    try:
        compliance_result = rag.policy_compliance_checker(
            exception_request=exception_request,
            top_k=5
        )

        print(f"\n[RESULT] Compliance Analysis Results:")
        print(f"         Status: {compliance_result['compliance_status']}")

        if compliance_result['violations']:
            print(f"\n         Potential Violations ({len(compliance_result['violations'])}):")
            for i, violation in enumerate(compliance_result['violations'], 1):
                if isinstance(violation, dict):
                    print(f"            {i}. Policy: {violation.get('policy', 'Unknown')}")
                    print(f"               Reason: {violation.get('reason', 'No reason provided')}")
                else:
                    print(f"            {i}. {violation}")
        else:
            print("         No policy violations identified")

        if compliance_result['required_controls']:
            print(f"\n         Required Compensating Controls ({len(compliance_result['required_controls'])}):")
            for i, control in enumerate(compliance_result['required_controls'], 1):
                print(f"            {i}. {control}")

        if compliance_result['policy_refs']:
            print(f"\n         Referenced Policies: {', '.join(compliance_result['policy_refs'])}")

        # Store for later use
        compliance_status = compliance_result['compliance_status']
        policy_refs = compliance_result['policy_refs']
        required_controls = compliance_result['required_controls']

    except Exception as e:
        print(f"[ERROR] Compliance analysis failed: {e}")
        compliance_status = "UNKNOWN"
        policy_refs = []
        required_controls = []

    # ========================================
    # STEP 3: Risk Score Calculation
    # ========================================
    print_step(3, "Risk Score Calculation (Rule-Based Algorithm)")

    print("\nConverting exception request to risk scoring format...")

    form_data = convert_exception_request_to_form_data(exception_request)

    print("Extracted risk factors:")
    print(f"   Data stored level: {form_data['data_stored_level']}")
    print(f"   Data access level: {form_data['data_access_level']}")
    print(f"   Vulnerability scanning allowed: {form_data['allow_vulnerability_scanning']}")
    print(f"   EDR/CrowdStrike allowed: {form_data['allow_edr_crowdstrike']}")
    print(f"   Local firewall: {form_data['local_firewall']}")
    print(f"   Network firewall: {form_data['network_firewall']}")
    print(f"   OS up to date: {form_data['os_up_to_date']}")
    print(f"   Public IP exposure: {form_data['has_public_ip']}")
    print(f"   OS patch frequency: {form_data['os_patch_frequency']}")
    print(f"   App patch frequency: {form_data['app_patch_frequency']}")
    print(f"   Business impact: {form_data['university_importance']}")

    print("\nCalculating risk score...")

    risk_score = calculate_risk_score(form_data)

    print(f"\n[RESULT] Risk Score: {risk_score}/100")

    # Determine risk level
    if risk_score > 90:
        risk_level = "CRITICAL"
    elif risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score >= 16:
        risk_level = "LOW-MEDIUM"
    else:
        risk_level = "LOW"

    print(f"         Risk Level: {risk_level}")

    # ========================================
    # STEP 4: Risk Narrative Generation
    # ========================================
    print_step(4, "Executive Risk Narrative Generation (LLM)")

    print("\nGenerating executive risk narrative...")
    print(f"Using risk score: {risk_score}")
    print(f"Using policy references: {', '.join(policy_refs) if policy_refs else 'None'}")

    try:
        narrative = rag.generate_risk_narrative(
            risk_score=risk_score,
            factors=form_data,  # Using actual calculated factors
            policy_refs=policy_refs  # Using actual policy references from compliance check
        )

        print("\n" + "=" * 80)
        print("EXECUTIVE RISK ASSESSMENT")
        print("=" * 80)
        print()

        # Format narrative with proper line breaks
        paragraphs = narrative.split('\n\n')
        for paragraph in paragraphs:
            if paragraph.strip():
                # Wrap text at 78 characters
                lines = paragraph.strip().split('\n')
                for line in lines:
                    print(f"   {line}")
                print()

        print("=" * 80)

    except Exception as e:
        print(f"[ERROR] Risk narrative generation failed: {e}")
        narrative = "Risk narrative generation failed."

    # ========================================
    # STEP 5: Decision Engine Recommendation
    # ========================================
    print_step(5, "Decision Engine Recommendation")

    print("\nProcessing decision engine workflow...")

    decision = make_exception_decision(risk_score, form_data)

    print(f"\n[RESULT] Decision Engine Output:")
    print(f"         Recommendation: {decision['recommendation']}")
    print(f"         Approval Status: {decision['approval_status']}")
    print(f"         Routing: {decision['routing']} Team")
    print(f"         Approval Required: {', '.join(decision['approval_required'])}")

    if decision['max_duration']:
        print(f"         Maximum Duration: {decision['max_duration']} days")
    else:
        print(f"         Maximum Duration: Not approved")

    if decision['conditions']:
        print(f"\n         Conditions ({len(decision['conditions'])}):")
        for i, condition in enumerate(decision['conditions'], 1):
            print(f"            {i}. {condition}")

    if decision['reasoning']:
        print(f"\n         Reasoning:")
        for reason in decision['reasoning']:
            print(f"            {reason}")

    # ========================================
    # STEP 6: Final Summary
    # ========================================
    print_step(6, "Pipeline Summary")

    print("\n" + "=" * 80)
    print(" COMPLETE PIPELINE RESULTS ".center(80, "="))
    print("=" * 80)

    print(f"\nException Request: {exception_request['id']}")
    print(f"   Type: {exception_request['exception_type']}")
    print(f"   Data Level: {exception_request['data_level']}")

    print(f"\nPolicy Analysis:")
    print(f"   Policies Found: {len(policy_search_results)}")
    print(f"   Compliance Status: {compliance_status}")
    print(f"   Required Controls: {len(required_controls)}")

    print(f"\nRisk Assessment:")
    print(f"   Risk Score: {risk_score}/100 ({risk_level})")

    print(f"\nDecision:")
    print(f"   Recommendation: {decision['recommendation']}")
    print(f"   Approval Required: {', '.join(decision['approval_required'])}")
    print(f"   Routing: {decision['routing']} Team")

    print("\n" + "=" * 80)

    # ========================================
    # Cleanup
    # ========================================
    print("\nCleaning up...")
    try:
        rag.close()
        print("[SUCCESS] RAG system closed successfully")
    except Exception as e:
        print(f"[WARNING] Cleanup failed: {e}")

    print("\n[COMPLETE] End-to-End Pipeline Demonstration Complete")
    print("=" * 80)

    return True


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print(" RAG Pipeline - End-to-End Demonstration ".center(80))
    print(" Showing ONE request through ALL pipeline stages ".center(80))
    print("=" * 80)

    success = run_end_to_end_pipeline()
    sys.exit(0 if success else 1)
