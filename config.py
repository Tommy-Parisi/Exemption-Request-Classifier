"""
Centralised configuration for the Exemption Request Classifier.

All values are read from environment variables (loaded from .env via python-dotenv).
Import individual settings from this module rather than calling os.getenv() in
application code — this keeps configuration in one place and makes the required
variables easy to discover.
"""
import os
from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# TDX Integration
# ---------------------------------------------------------------------------

TDX_API_URL: str = os.getenv("TDX_API_URL", "")
TDX_API_KEY: str | None = os.getenv("TDX_API_KEY")

# ---------------------------------------------------------------------------
# Google / Gemini LLM
# ---------------------------------------------------------------------------

GOOGLE_API_KEY: str | None = os.getenv("GOOGLE_API_KEY")
LLM_API_KEY: str | None = os.getenv("LLM_API_KEY")
LLM_API_URL: str = os.getenv(
    "LLM_API_URL",
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
)
GEMINI_CHAT_MODEL: str = os.getenv("GEMINI_CHAT_MODEL", "gemini-2.5-flash")
GEMINI_EVAL_MODEL: str = os.getenv("GEMINI_EVAL_MODEL", GEMINI_CHAT_MODEL)

# ---------------------------------------------------------------------------
# Firestore Vector Database
# ---------------------------------------------------------------------------

GOOGLE_CLOUD_PROJECT: str | None = os.getenv("GOOGLE_CLOUD_PROJECT")
FIRESTORE_DATABASE: str = os.getenv("FIRESTORE_DATABASE", "policies")
FIRESTORE_COLLECTION: str = os.getenv("FIRESTORE_COLLECTION", "policies")

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

SERVER_HOST: str = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT: int = int(os.getenv("SERVER_PORT", "8000"))
# Set ENV=development to enable hot reload when running via `python main.py`
ENV: str = os.getenv("ENV", "production")

# ---------------------------------------------------------------------------
# Form field → scorer mapping tables
# Shared by api/routes.py and api/tdx.py so both use identical translations.
# ---------------------------------------------------------------------------

DATA_LEVEL_MAP: dict[str, int] = {"Level I": 1, "Level II": 2, "Level III": 3}
DATA_LEVEL_ROMAN: dict[int, str] = {1: "I", 2: "II", 3: "III"}

PATCH_FREQ_MAP: dict[str, str] = {
    "Monthly": "monthly",
    "Quarterly": "quarterly",
    "Every 3-6 months": "every 3-6 months",
    "Every 6-12 months": "every 6-12 months",
    "Yearly": "yearly+",
    "Unavailable": "patches unavailable",       # frontend form value
    "Patches Unavailable": "patches unavailable", # TDX API value
}

FIREWALL_MAP: dict[str, str] = {
    "High Coverage": "high",
    "Moderate Coverage": "moderate",
    "Minimal Coverage": "minimal",
    "No Coverage": "no",
}

IMPACT_MAP: dict[str, str] = {
    "Low": "low",
    "Moderate": "moderate",
    "Extensive": "excessive",
    "Widespread": "excessive",
}

UNIVERSITY_MAP: dict[str, str] = {
    "Non-Critical": "low",
    "Critical": "moderate",
    "Mission Critical": "excessive",
}

RISK_LEVEL_MAP: list[tuple[int, str]] = [
    (90, "LOW"),        # approval score > 90 → great security posture
    (70, "LOW-MEDIUM"),
    (40, "MEDIUM"),
    (16, "HIGH"),
    (0,  "CRITICAL"),   # approval score ≤ 0 → very poor security posture
]

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

# Comma-separated list of allowed frontend origins.
# Example: ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:4173")
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]
