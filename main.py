"""
Main entry point for the FastAPI application.

Development:
    python main.py
    # or
    uvicorn main:app --reload --port 8000

Production:
    ENV=production uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
"""
import logging
import os

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

from api.routes import app  # noqa: E402

if __name__ == "__main__":
    import uvicorn

    host = os.getenv("SERVER_HOST", "0.0.0.0")
    port = int(os.getenv("SERVER_PORT", "8000"))
    reload = os.getenv("ENV", "production").lower() == "development"

    uvicorn.run(app, host=host, port=port, reload=reload)
