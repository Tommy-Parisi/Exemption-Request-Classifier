from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Literal
import sys
import os

# Add parent directory to path to import services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.llm_service import chat_with_form_data

app = FastAPI()

# Configure CORS to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],  # Vite default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class ChatRequest(BaseModel):
    requestor: Optional[str] = ""
    department: Optional[str] = ""
    exceptionType: Optional[str] = ""
    reason: Optional[str] = ""
    startDate: Optional[str] = ""
    hostnames: Optional[str] = ""
    unitHead: Optional[str] = ""
    riskAssessment: Optional[str] = ""
    impactedSystems: Optional[str] = ""
    dataLevelStored: Optional[str] = ""
    dataAccessLevel: Optional[str] = ""
    vulnScanner: Optional[str] = ""
    edrAllowed: Optional[str] = ""
    managementAccess: Optional[str] = ""
    publicIP: Optional[str] = ""
    osUpToDate: Optional[str] = ""
    osPatchFrequency: Optional[str] = ""
    appPatchFrequency: Optional[str] = ""
    localFirewall: Optional[str] = ""
    networkFirewall: Optional[str] = ""
    dependencyLevel: Optional[str] = ""
    userImpact: Optional[str] = ""
    universityImpact: Optional[str] = ""
    mitigation: Optional[str] = ""
    message: Optional[str] = "Please review my exemption request form and provide feedback or generate a complete exception request."
    history: List[ChatMessage] = Field(default_factory=list)

@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    """
    Chat endpoint that receives form data and uses it to provide context-aware assistance.
    The LLM will use the form data to help the user complete the form and generate a proper exception request.
    """
    # Convert Pydantic model to dict, excluding None values
    form_data = request.model_dump(exclude_none=True, exclude={"history"})

    # Extract message if provided, otherwise use default
    message = form_data.pop(
        "message",
        "Please review my exemption request form and provide feedback or generate a complete exception request.",
    )

    # Remove empty strings from form_data
    form_data = {k: v for k, v in form_data.items() if v and str(v).strip()}

    # Convert history objects into OpenAI-compatible dicts
    history = [msg.model_dump() for msg in request.history]

    try:
        # Call LLM service with form data context and chat history
        reply = chat_with_form_data(message=message, form_data=form_data, history=history)

        return {"reply": reply}
    except Exception as e:
        return {"reply": f"Error processing request: {str(e)}"}

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


