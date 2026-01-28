from dotenv import load_dotenv
from openai import AsyncOpenAI
from agents import Agent, Runner, trace, function_tool, OpenAIChatCompletionsModel, ModelSettings, input_guardrail, GuardrailFunctionOutput
from openai.types.shared import Reasoning
from openai.types.responses import ResponseTextDeltaEvent
from typing import Dict
import os
import asyncio
from pypdf import PdfReader

load_dotenv(override=True)

GEMINI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"

gemini_api_key = os.getenv("GOOGLE_API_KEY")
gemini_client = AsyncOpenAI(base_url=GEMINI_BASE_URL, api_key=os.getenv(gemini_api_key))
gemini_model = OpenAIChatCompletionsModel("model=gemini-3-pro-preview")

chat_instructions = "You are a professional, senior IT security analyst assistant at the University of Delaware, \
    tasked with assisting a user in filling out an exception request form. You will be provided with the security \
    pdf and some json data from the form. You should answer any questions the user may have and help the user understand \
    what information they need to provide in their request, clarify security requirements and compliacne standards \
    guide users thrrough the exception request process, and obtain information from the user and external resources \
    and research online if needed. You should provide answers based on the form's, if you don't know an answer say so \
    honestly. Help users understand what constitues a valid exemption request and what is needed"


# reasoning_effort="none" disables thinking (2.5 Flash only).
# Gemini 3 Pro does not support "none"; "low" minimizes thinking time for 3 Pro.
IT_assistant = Agent(
    name="IT Security Analyst Assistant",
    instructions=chat_instructions,
    model=gemini_model,
    model_settings=ModelSettings(reasoning=Reasoning(effort="none")),
)
