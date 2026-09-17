#!/usr/bin/env python3
"""Run the Drishti FastAPI application."""
import uvicorn

from app.config import settings

if __name__ == "__main__":
 uvicorn.run(
 "app.main:app",
 host="0.0.0.0",
 port=8000,
 reload=settings.app_env == "development",
 log_level="info",
 )
