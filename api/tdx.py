import os
import requests
import json
from dotenv import load_dotenv
import base64


load_dotenv()
BASE_URL = "https://us.ipaas.teamdynamix.com/tdapp/app/flow/api/v1/start/20/88398cb6-c77f-4f9d-b175-ba633ae09ab5?WaitForResults=true"
TDX_API_KEY = os.getenv("TDX_API_KEY")
headers = {
            "Content-Type":"application/json",
            "apikey": f"{TDX_API_KEY}"
        }
#Create a json file containing all the submitted security policy exception tickets.
#Look into fetching all tickets, individual tickets or a certain range of tickets.


'''data = {"Method": "Get_Tickets"}
request = requests.post(BASE_URL, headers=headers, json=data)
if request.status_code == 200:
    print("Success")
    request_data = request.json()
    all_tickets_data = request_data["data"]
    with open(f"api/all_tickets.json", "w", encoding='utf-8') as f:
         json.dump(all_tickets_data, f, indent=4)
    print("Successfully created all_tickets.json")
else:
    print("Error: " + request.status_code)
'''
with open("api/exceptions.json", "r") as f:
    all_ticket_data = json.load(f)
make_request = True

if make_request:
    for n in range(1):
        ticket_id = all_ticket_data["data"]["ID"]
        data = {
            #"Method": "Get_Tickets"
            "Method": "Get_Ticket", "TicketID": str(ticket_id)
            #"Method": "Get_Attachment", "TicketID": "151542", "AttachmentID": "cbbfb589-216c-4034-a76a-85bbef78a110"
        }

        request = requests.post(BASE_URL, headers=headers, json=data)

        if request.status_code == 200:
            print("Success")
            request_data = request.json()
            ticket_data = request_data["data"]
            filtered = {
                "requestor": ticket_data.get("RequestorName"),
                "department": ticket_data.get("AccountName"),
                "reason": ticket_data.get("Description"),
            }
            filtered_attributes = {
                "Type of Exception" : "exceptionType",
                "Exception Start Date" : "startDate",
                "Hostnames" : "hostnames",
                "Unit Head" : "unitHead",
                "Risk Assessment Justification" : "riskAssessment",
                #look into getting attachments
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
            attributes = ticket_data.get("Attributes")
            
            for attr in attributes:
                name = attr.get("Name")
                value = attr.get("ValueText")
                if name in filtered_attributes:
                    mapped_key = filtered_attributes[name]
                    filtered[mapped_key] = value
    with open("api/filtered_form_output.json", "w") as outfile:
        json.dump(filtered, outfile, indent=4)
        print("Output File successfully created")
    ''' file_name = "TicketID_" + str(ticket_id) + ".json"
            with open(f"api/individual_exceptions/{file_name}", 'w', encoding='utf-8') as f:
                json.dump(ticket_data, f, indent=4)
            print(f"Successfully fetched {n} ticket(s)")
        else:
            print(f"Error: {request.status_code}")
            print(request.text)

    if has_attachment:
        with open("api/exceptions_attachment_1.json", "r") as f:
            response = json.load(f)

        base64_data = response["data"]
        image_bytes = base64.b64decode(base64_data)
        
        with open("api/attachment.png", "wb") as img:
            img.write(image_bytes)
        
        print("image successfully saved")'''