"""
Main entry point for the FastAPI application.
Run with: uvicorn main:app --reload --port 8000
"""
from api.routes import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)



