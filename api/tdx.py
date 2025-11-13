import os
import requests
import json
from dotenv import load_dotenv
import base64


load_dotenv()
make_request = False
if make_request:
    BASE_URL = "https://us.ipaas.teamdynamix.com/tdapp/app/flow/api/v1/start/20/88398cb6-c77f-4f9d-b175-ba633ae09ab5?WaitForResults=true"
    TDX_API_KEY = os.getenv("TDX_API_KEY")
    headers = {
        "Content-Type":"application/json",
        "apikey": f"{TDX_API_KEY}"
    }
    data = {
        #"Method": "Get_Tickets"
        #"Method": "Get_Ticket", "TicketID": "151542"
        "Method": "Get_Attachment", "TicketID": "151542", "AttachmentID": "cbbfb589-216c-4034-a76a-85bbef78a110"
    }

    request = requests.post(BASE_URL, headers=headers, json=data)

    if request.status_code == 200:
        print("Success")
        request_data = request.json()
        file_name = "exceptions_attachment_1.json"
        with open(f"api/{file_name}", 'w', encoding='utf-8') as f:
            json.dump(request_data, f, indent=4)
        print("Successfully wrote exception json file")
    else:
        print(f"Error: {request.status_code}")
        print(request.text)
else:
    with open("api/exceptions_attachment_1.json", "r") as f:
        response = json.load(f)

    base64_data = response["data"]
    image_bytes = base64.b64decode(base64_data)
    
    with open("api/attachment.png", "wb") as img:
        img.write(image_bytes)
    
    print("image successfully saved")