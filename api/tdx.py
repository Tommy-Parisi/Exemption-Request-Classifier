import logging
import os
import requests
import json
from dotenv import load_dotenv
import time
import base64
import mimetypes
from pathlib import Path
import pandas as pd
import io
from datetime import datetime

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.risk_scorer import calculate_risk_score
from engine.decision_engine import make_exception_decision
from engine.rag_integration import RAGIntegrator
from config import (
    DATA_LEVEL_MAP, DATA_LEVEL_ROMAN, PATCH_FREQ_MAP,
    FIREWALL_MAP, IMPACT_MAP, UNIVERSITY_MAP, RISK_LEVEL_MAP,
)


load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s   %(levelname)s: %(message)s', level=logging.DEBUG, datefmt='%m/%d/%Y %I:%M:%S %p')
#Web request information consisting of the URL, API key and header information to call TDX API
BASE_URL = os.getenv("TDX_API_URL", "")
TDX_API_KEY = os.getenv("TDX_API_KEY")
headers = {
            "Content-Type":"application/json",
            "apikey": f"{TDX_API_KEY}"
        }

#Makes the TDX API call and handles the different methods
def tdx_call(data):
     response = requests.post(BASE_URL, headers=headers, json=data, timeout=30)
     if response.status_code != 200:
          logger.error("TDX API error: status=%d, body=%s", response.status_code, response.text)
          return None
     return response.json()["data"]

#Gets all tickets using the TDX API
def get_all_open_tickets():
    data = {"Method": "Get_Tickets", "Only_Open":"true"}
    return tdx_call(data)

#Takes attachment encoded data, formats it
def interpret_attachment(ticket_id, attachment_name, base64_data):
    decoded_bytes = base64.b64decode(base64_data)

    save_dir = Path("attachments") / str(ticket_id)
    save_dir.mkdir(parents=True, exist_ok=True)

    file_path = save_dir / attachment_name
    file_path.write_bytes(decoded_bytes)

    mime_type = mimetypes.guess_type(attachment_name)[0]

    summary = {
        "filename": attachment_name,
        "filetype": mime_type or "unknown",
        "saved_path": str(file_path)
    }

    try:
        #CSV
        if mime_type == "text/csv":
            df = pd.read_csv(io.BytesIO(decoded_bytes), nrows = 1000)
            summary.update({
                "rows_sampled": len(df),
                "columns": list(df.columns),
                "sample_rows": df.head(3).to_dict(orient="records")
            })


        #Text
        elif mime_type == "text/plain":
            text = decoded_bytes.decode("utf-8", errors="ignore")
            summary["extracted_text_preview"] = text[:2000]


        #WordDocs
        elif mime_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
            from docx import Document
            doc = Document(io.BytesIO(decoded_bytes))
            text = "\n".join([para.text for para in doc.paragraphs])
            summary["extracted_text_preview"] = text[:2000]

        #Excel
        elif mime_type in ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.ms-excel"]:
            df = pd.read_excel(io.BytesIO(decoded_bytes), nrows=1000)
            summary.update({
                "rows_sampled": len(df),
                "columns": list(df.columns),
                "sample_rows": df.head(3).to_dict(orient="records")
            })

        #PDF
        elif mime_type == "application/pdf":
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(decoded_bytes))
            text = ""
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text+= page_text + '\n'
            summary["extracted_text_preview"] = text[:2000]

        #Image
        elif mime_type and mime_type.startswith("image/"):
            summary["note"] = "Image saved."

        else:
            summary["note"] = "File saved, no analysis or extraction performed."
    except Exception as e:
        summary["error"] = str(e)

    return summary

#Grabs relevant information fields from the requested ticket and returns the filtered data.
def process_ticket(ticket_id):
        request_header = {"Method": "Get_Ticket", "TicketID": str(ticket_id)}

        ticket_data = tdx_call(request_header)
        if not ticket_data:
            logger.warning("No ticket data returned for ticket ID: %s", ticket_id)
            return None

        #Check for attachments, if not present, produce empty array
        ticket_attachments = ticket_data.get("Attachments", [])
        attachments_data = []
        if ticket_attachments:
            for attachment in ticket_attachments:
                attachment_id = attachment.get("ID")
                attachment_name = attachment.get("Name")
                attachment_header = {
                    "Method": "Get_Attachment", "TicketID": str(ticket_id), "AttachmentID": str(attachment_id)
                    }
                attachment_response = tdx_call(attachment_header)

                if not attachment_response:
                    continue

                base64_data = attachment_response.strip()

                summary = interpret_attachment(ticket_id, attachment_name, base64_data)
                attachments_data.append(summary)

        else:
            attachments_data = []

        #Grab relevant data from the 'data' field of the ticket data and format it for json output
        filtered_data = {
            "requestor": ticket_data.get("RequestorName"),
            "department": ticket_data.get("AccountName"),
            "reason": ticket_data.get("Description"),
            "attachments": attachments_data
            }
        #Format the attribute field names to prepare them to be added to filtered_data
        filtered_attributes = {
            "Type of Exception" : "exceptionType",
            "If OTHER please specify": "exceptionSpecified",
            "Exception Start Date" : "startDate",
            "Exception End Date": "endDate",
            "Hostnames" : "hostnames",
            "Unit Head" : "unitHead",
            "Risk Assessment Justification" : "riskAssessment",
            "Level of Data": "dataLevelStored",
            "Level of Data: Specify" : "dataLevelStoredSpecified",
            "Level of data the device has access to" : "dataAccessLevel",
            "Level of data the device has access to: Specify": "dataAccessLevelSpecified",
            "Allow Vulnerability Scanning Agent on Client?" : "vulnScanner",
            "Allow EDR (Crowdstrike on Client)?" : "edrAllowed",
            "Local Firewall Rules" : "localFirewall",
            "Network Firewall Rules" : "networkFirewall",
            "Does system have access to management network?" : "managementAccess",
            "Does this machine have a public IP address?" : "publicIP",
            "Is the operating system up to date with the latest patch?" : "osUpToDate",
            "How often are OS patches installed?" : "osPatchFrequency",
            "How often are application patches installed?" : "appPatchFrequency",
            "How many assets or servers depend on this asset?" : "dependencyLevel",
            "How many users are impacted by the services this asset supports?" : "userImpact",
            "How important is this asset to the University as a whole?" : "universityImpact",
            "Impacted Systems, Services and Data" : "impactedSystems",
            "Summary of Compensating Information Security Controls" : "mitigation"
            }

        #Grab relevant data from the 'attributes' field of the 'data' field
        attributes = ticket_data.get("Attributes")
        for attr in attributes:
            #The 'Name' and 'ValueText' field are the names and data of the relavant input fields from the security policy exception form
            #See the 'filtered_attributes' keys for example of 'Name' values
            name = attr.get("Name")
            value = attr.get("ValueText")
            if name in filtered_attributes:
                mapped_key = filtered_attributes[name]
                filtered_data[mapped_key] = value

        return filtered_data


#Cache file path and name
cache_file = "api/ticket_cache.json"

#If the json file doesn't exist, create the file with ticket_ids and ticket_data fields, else return the file data
def load_cache():
    if not os.path.exists(cache_file):
        default_cache = {"ticket_ids":[], "ticket_data":{}}
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        with open(cache_file, "w") as f:
            json.dump(default_cache, f, indent=4)
        return default_cache

    with open(cache_file, "r") as f:
        return json.load(f)

#Writes current cache to the ticket_cache.json file
def save_cache(cache):
    with open(cache_file, "w") as f:
        json.dump(cache, f, indent=4)

REPORTS_DIR = Path("reports")


def _risk_level(score):
    for threshold, label in RISK_LEVEL_MAP:
        if score > threshold:
            return label
    return RISK_LEVEL_MAP[-1][1]


def _parse_data_level(text):
    """TDX sends full descriptions like 'Level I - Low impact: ...'; extract the numeric level."""
    text = (text or "").strip()
    if text.startswith("Level III"):
        return 3
    if text.startswith("Level II"):
        return 2
    if text.startswith("Level I"):
        return 1
    return DATA_LEVEL_MAP.get(text, 2)


def map_ticket_to_scorer(ticket):
    return {
        "data_stored_level": _parse_data_level(ticket.get("dataLevelStored")),
        "data_access_level": _parse_data_level(ticket.get("dataAccessLevel")),
        "allow_vulnerability_scanning": (ticket.get("vulnScanner") or "").strip().lower() == "yes",
        "allow_edr_crowdstrike": (ticket.get("edrAllowed") or "").strip().lower() == "yes",
        "local_firewall": FIREWALL_MAP.get(ticket.get("localFirewall") or "", "minimal"),
        "network_firewall": FIREWALL_MAP.get(ticket.get("networkFirewall") or "", "minimal"),
        "os_up_to_date": (ticket.get("osUpToDate") or "").strip().lower() == "yes",
        "has_public_ip": (ticket.get("publicIP") or "").strip().lower() == "yes",
        "management_network_access": (ticket.get("managementAccess") or "").strip().lower() == "yes",
        "os_patch_frequency": PATCH_FREQ_MAP.get(ticket.get("osPatchFrequency") or "", "quarterly"),
        "app_patch_frequency": PATCH_FREQ_MAP.get(ticket.get("appPatchFrequency") or "", "quarterly"),
        "server_dependencies": IMPACT_MAP.get(ticket.get("dependencyLevel") or "", "low"),
        "user_dependencies": IMPACT_MAP.get(ticket.get("userImpact") or "", "low"),
        "university_importance": UNIVERSITY_MAP.get(ticket.get("universityImpact") or "", "low"),
    }


def evaluate_ticket(ticket_id, ticket, rag):
    scorer_data = map_ticket_to_scorer(ticket)
    score_result = calculate_risk_score(scorer_data)
    decision = make_exception_decision(score_result["total"], scorer_data)

    compliance = None
    narrative = None

    if rag is not None:
        try:
            import uuid
            controls = []
            if scorer_data["allow_vulnerability_scanning"]:
                controls.append("vulnerability scanning")
            if scorer_data["allow_edr_crowdstrike"]:
                controls.append("edr crowdstrike endpoint detection")
            if scorer_data["local_firewall"] == "adequate":
                controls.append("local firewall")
            if scorer_data["network_firewall"] == "adequate":
                controls.append("network firewall")
            if scorer_data["os_up_to_date"]:
                controls.append("os up to date")
            if ticket.get("mitigation"):
                controls.append(ticket["mitigation"][:200])

            rag_request = {
                "id": str(uuid.uuid4()),
                "exception_type": (ticket.get("exceptionType") or "other").lower(),
                "data_level": DATA_LEVEL_ROMAN.get(scorer_data["data_stored_level"], "II"),
                "security_controls": controls,
            }
            compliance = rag.policy_compliance_checker(rag_request, top_k=6)
            narrative = rag.generate_risk_narrative(
                risk_score=score_result["total"],
                factors=score_result["breakdown"],
                policy_refs=compliance.get("policy_refs", []),
            )
        except Exception as exc:
            logger.error("RAG pipeline error for ticket %s: %s", ticket_id, exc)

    write_report(ticket_id, ticket, score_result, decision, compliance, narrative)


def write_report(ticket_id, ticket, score_result, decision, compliance, narrative):
    REPORTS_DIR.mkdir(exist_ok=True)

    total = score_result["total"]
    bd = score_result["breakdown"]
    level = _risk_level(total)
    duration = f"{decision['max_duration']} days" if decision.get("max_duration") else "Not approved"
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "SECURITY EXCEPTION REQUEST EVALUATION",
        "======================================",
        f"Ticket ID:  {ticket_id}",
        f"Generated:  {generated}",
        "",
        "REQUESTOR INFORMATION",
        f"  Requestor:  {ticket.get('requestor', 'N/A')}",
        f"  Department: {ticket.get('department', 'N/A')}",
        f"  Unit Head:  {ticket.get('unitHead', 'N/A')}",
        f"  Exception Type: {ticket.get('exceptionType', 'N/A')}",
        f"  Start Date: {ticket.get('startDate', 'N/A')}",
        f"  Hostnames:  {ticket.get('hostnames', 'N/A')}",
        "",
        "SECURITY ASSESSMENT",
        f"  Score: {total}  |  Risk Level: {level}",
        f"  Recommendation: {decision['recommendation']}",
        "",
        "SCORE BREAKDOWN",
        f"  Data Classification: {bd['data_classification']}/20",
        f"  Security Controls:   {bd['security_controls']}/40",
        f"  Network Posture:     {bd['network_posture']}/10",
        f"  Patch Management:    {bd['patch_management']}/20",
        f"  Impact Assessment:   {bd['impact_assessment']}/24",
        "",
        f"  Maximum Duration: {duration}",
    ]

    if decision.get("conditions"):
        lines += ["", "CONDITIONS"]
        for i, cond in enumerate(decision["conditions"], 1):
            lines.append(f"  {i}. {cond}")

    lines += ["", "POLICY COMPLIANCE"]
    if compliance is None:
        lines.append("  Policy analysis unavailable (RAG service error).")
    else:
        lines.append(f"  Status: {compliance['compliance_status']}")
        if compliance.get("policy_refs"):
            lines.append(f"  Referenced Policies: {', '.join(compliance['policy_refs'])}")
        if compliance.get("violations"):
            lines.append("  Violations:")
            for v in compliance["violations"]:
                if isinstance(v, dict):
                    lines.append(f"    - {v.get('policy', '')}: {v.get('reason', '')}")
                else:
                    lines.append(f"    - {v}")
        if compliance.get("required_controls"):
            lines.append("  Required Controls:")
            for ctrl in compliance["required_controls"]:
                lines.append(f"    - {ctrl}")

    if narrative:
        lines += ["", "EXECUTIVE RISK NARRATIVE", f"  {narrative}"]

    if ticket.get("reason"):
        lines += ["", "REQUESTOR'S REASON", f"  {ticket['reason']}"]

    if ticket.get("riskAssessment"):
        lines += ["", "RISK ASSESSMENT JUSTIFICATION", f"  {ticket['riskAssessment']}"]

    if ticket.get("mitigation"):
        lines += ["", "STATED MITIGATIONS", f"  {ticket['mitigation']}"]

    lines += ["", "======================================"]

    report_path = REPORTS_DIR / f"ticket_{ticket_id}.txt"
    report_path.write_text("\n".join(lines))
    logger.info("Report written to %s", report_path)


def main_loop():
    try:
        rag = RAGIntegrator()
        logger.info("RAGIntegrator initialized")
    except Exception as exc:
        logger.error("RAGIntegrator failed to initialize, reports will skip policy analysis: %s", exc)
        rag = None

    while True:
        logger.info("Checking for new tickets...")
        cache = load_cache()

        open_tickets = get_all_open_tickets()

        #Sleep timer to reduce making continuous API calls if something is wrong
        if not open_tickets:
            time.sleep(300)
            continue

        #Create an array of ticket ids for fetched open tickets
        current_ids = [ticket["TicketID"] for ticket in open_tickets]

        #Filter for new ids by checking the current cached ids
        new_ids = [ticket_id for ticket_id in current_ids if ticket_id not in cache["ticket_ids"]]

        if new_ids:
            logger.info("New ticket ID(s): %s", new_ids)
            for ticket_id in new_ids:
                processed = process_ticket(ticket_id)
                if processed:
                    cache["ticket_ids"].append(ticket_id)
                    cache["ticket_data"][ticket_id] = processed
                    save_cache(cache)
                    logger.info("Processed and cached ticket %s", ticket_id)
                    evaluate_ticket(ticket_id, processed, rag)
        else:
            logger.info("No new tickets found")

        #Check every hour for new tickets
        time.sleep(3600)


if __name__ == "__main__":
    main_loop()
