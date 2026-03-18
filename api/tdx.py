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


load_dotenv()
#Web request information consisting of the URL, API key and header information to call TDX API
BASE_URL = "https://us.ipaas.teamdynamix.com/tdapp/app/flow/api/v1/start/20/88398cb6-c77f-4f9d-b175-ba633ae09ab5?WaitForResults=true"
TDX_API_KEY = os.getenv("TDX_API_KEY")
headers = {
            "Content-Type":"application/json",
            "apikey": f"{TDX_API_KEY}"
        }

#Makes the TDX API call and handles the different methods
def tdx_call(data):
     response = requests.post(BASE_URL, headers=headers, json=data)
     if response.status_code != 200:
          print("Error calling TDX API: " + response.status_code, response.text)
          return None
     return response.json()["data"]

#Cache file path and name
cache_file = "api/ticket_cache.json"

#If the json file doesn't exist, create the file with ticket_ids and ticket_data fields, else return the file data
def load_cache():
    if not os.path.exists(cache_file):
        return {"ticket_ids":[], "ticket_data":{}}
    
    with open(cache_file, "r") as f:
        return json.load(f)

#Writes current cache to the ticket_cache.json file
def save_cache(cache):
    with open(cache_file, "w") as f:
        json.dump(cache, f, indent=4)

#Gets all tickets using the TDX API
def get_all_open_tickets():
    data = {"Method": "Get_Tickets", "Only_Open":"true"}
    return tdx_call(data)



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
        tix_data = {"Method": "Get_Ticket", "TicketID": str(ticket_id)}
        
        ticket_data = tdx_call(tix_data)
        if not ticket_data:
            print("Cannot find ticket based on ID")
            return None
        
        #Check for attachments, if not present, produce empty array
        ticket_attachments = ticket_data.get("Attachments", [])
        attachments_data = []
        if ticket_attachments:
            for attachment in ticket_attachments:
                attachment_id = attachment.get("ID")
                attachment_name = attachment.get("Name")
                fetch_att_data = {
                    "Method": "Get_Attachment", "TicketID": str(ticket_id), "AttachmentID": str(attachment_id)
                    }
                attachment_response = tdx_call(fetch_att_data)

                if not attachment_response:
                    continue

                base64_data = attachment_response.strip()

                summary = interpret_attachment(ticket_id, attachment_name, base64_data)
                attachments_data.append(summary)

        else:
            attachments_data = "None"

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
            "Hostnames" : "hostnames",
            "Unit Head" : "unitHead",
            "Risk Assessment Justification" : "riskAssessment",
            "Level of Data": "dataLevelStored",
            "Level of Data: Specify" : "dataLevelStoredSpecified",
            "Level of data the device has access to" : "dataAccessLevel",
            "Level of data the device has access to: Specify": "dataAccessLevelSpecified",
            "Allow Vulnerability Scanning Agent on Client?" : "vulnScanner",
            "Allow EDR (Crowdstrike on Client)" : "edrAllowed",
            "Local Firewall Rules" : "localFirewall",
            "Network Firewall Rules" : "networkFirewall",
            "Does system have access to management network?" : "managementAccess",
            "Does this machine have a public IP address?" : "publicIP",
            "Is the operating system up to date with the latest patch?" : "osUpToDate",
            "How often are OS patches installed" : "osPatchFrequency",
            "How often are application patches installed" : "appPatchFrequency",
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
            if name in filtered_attributes: #Check if should still write key value pair with value of "N/A" or "None" if key isn't present in ticket data
                mapped_key = filtered_attributes[name]
                filtered_data[mapped_key] = value

        return filtered_data


def main_loop():
    while True:
        print("Checking for new tickets...")
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
            print("New ticket ID(s):", new_ids)
            for ticket_id in new_ids:
                processed = process_ticket(ticket_id)
            
                if processed:
                    cache["ticket_ids"].append(ticket_id)
                    cache["ticket_data"][ticket_id] = processed
                    save_cache(cache)
                    print(f"Processed and cached ticket {ticket_id}")
        else:
            print("No new tickets found")

        #Check every hour for new tickets
        time.sleep(3600)
        print("Sleeping")
        

if __name__ == "__main__":
    main_loop()