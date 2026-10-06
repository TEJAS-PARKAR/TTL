"""
SecureCodeGuard – FastAPI Application Entry Point
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.config import get_settings
from app.storage.database import init_db

# ── Logging Setup ───────────────────────────────────────────────────
settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(name)-30s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("securecodeguard")

# Optional file handler
try:
    log_file = settings.resolve_path(settings.log_file)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(str(log_file))
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(name)-30s | %(levelname)-8s | %(message)s"
    ))
    logging.getLogger().addHandler(fh)
except Exception:
    pass

# ── FastAPI App ─────────────────────────────────────────────────────
app = FastAPI(
    title="SecureCodeGuard",
    description=(
        "Secure Code Debugging and Review Assistant – "
        "AI-assisted engineering review for automotive/ECU C/C++ code. "
        "Findings require qualified human validation."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS for Streamlit
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(router, prefix="/api/v1")


@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    logger.info("SecureCodeGuard starting up...")
    init_db()
    logger.info("Database initialized.")
    logger.info("Ollama model: %s", settings.ollama_model)
    logger.info("Embedding model: %s", settings.embedding_model)


@app.get("/")
async def root():
    return {
        "name": "SecureCodeGuard",
        "version": "1.0.0",
        "description": "Secure Code Debugging and Review Assistant",
        "disclaimer": (
            "AI-assisted engineering review. "
            "Findings require qualified human validation."
        ),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
    )
