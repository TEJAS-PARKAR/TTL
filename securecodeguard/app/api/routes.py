"""
SecureCodeGuard – API Routes

FastAPI routes for code review, findings management, report export,
data ingestion, and system health.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse

from app.config import get_settings
from app.models import (
    FindingStatus,
    HealthResponse,
    ReviewReport,
    ReviewRequest,
    ReviewResponse,
    ReviewType,
)
from app.review.engine import run_review
from app.review.llm_client import get_llm_client
from app.review.report_exporter import export_json, export_markdown
from app.storage.database import (
    get_audit_log,
    get_evaluation_results,
    get_review,
    init_db,
    list_reviews,
    save_review,
    update_finding_status,
)
from app.rag.ingestion import ingest_all_data
from app.rag.vector_store import get_collection_count

logger = logging.getLogger(__name__)

router = APIRouter()


# ════════════════════════════════════════════════════════════════════════
# Health
# ════════════════════════════════════════════════════════════════════════

@router.get("/health", response_model=HealthResponse, tags=["system"])
async def health_check():
    """Check system health."""
    settings = get_settings()
    llm = get_llm_client()
    ollama_ok = llm.is_available()

    # Check ChromaDB
    try:
        count = get_collection_count(settings.chroma_collection_code)
        chroma_ok = True
    except Exception:
        chroma_ok = False

    return HealthResponse(
        status="ok" if ollama_ok and chroma_ok else "degraded",
        ollama_available=ollama_ok,
        chroma_available=chroma_ok,
        model=settings.ollama_model,
        embedding_model=settings.embedding_model,
    )


# ════════════════════════════════════════════════════════════════════════
# Code Review
# ════════════════════════════════════════════════════════════════════════

@router.post("/review", response_model=ReviewResponse, tags=["review"])
async def run_code_review(request: ReviewRequest):
    """
    Run a code review on submitted source code.

    Accepts C/C++ source code with optional compiler logs and
    static-analysis JSON. Returns structured findings.
    """
    try:
        report = run_review(
            source_code=request.source_code,
            file_name=request.file_name,
            compiler_log=request.compiler_log,
            static_analysis_json=request.static_analysis_json,
            review_type=request.review_type,
        )

        # Save to database
        save_review(report)

        return ReviewResponse(
            success=True,
            message=f"Review complete: {len(report.findings)} findings",
            report=report,
        )
    except Exception as e:
        logger.error("Review failed: %s", e, exc_info=True)
        return ReviewResponse(
            success=False,
            message=f"Review failed: {str(e)}",
            report=None,
        )


@router.post("/review/upload", response_model=ReviewResponse, tags=["review"])
async def upload_and_review(
    file: UploadFile = File(...),
    compiler_log: Optional[UploadFile] = File(default=None),
    static_analysis: Optional[UploadFile] = File(default=None),
    review_type: str = Form(default="full_review"),
):
    """Upload a source file and run review."""
    try:
        source_code = (await file.read()).decode("utf-8", errors="replace")
        file_name = file.filename or "uploaded.c"

        comp_log = None
        if compiler_log:
            comp_log = (await compiler_log.read()).decode("utf-8", errors="replace")

        sa_json = None
        if static_analysis:
            sa_json = (await static_analysis.read()).decode("utf-8", errors="replace")

        try:
            rt = ReviewType(review_type)
        except ValueError:
            rt = ReviewType.FULL_REVIEW

        report = run_review(
            source_code=source_code,
            file_name=file_name,
            compiler_log=comp_log,
            static_analysis_json=sa_json,
            review_type=rt,
        )

        save_review(report)

        return ReviewResponse(
            success=True,
            message=f"Review complete: {len(report.findings)} findings",
            report=report,
        )
    except Exception as e:
        logger.error("Upload review failed: %s", e, exc_info=True)
        return ReviewResponse(
            success=False,
            message=f"Review failed: {str(e)}",
        )


# ════════════════════════════════════════════════════════════════════════
# Reviews & Findings
# ════════════════════════════════════════════════════════════════════════

@router.get("/reviews", tags=["review"])
async def get_all_reviews():
    """List all stored reviews."""
    return list_reviews()


@router.get("/reviews/{review_id}", response_model=ReviewResponse, tags=["review"])
async def get_review_by_id(review_id: str):
    """Retrieve a specific review."""
    report = get_review(review_id)
    if not report:
        raise HTTPException(status_code=404, detail="Review not found")
    return ReviewResponse(success=True, report=report)


@router.post("/findings/{finding_id}/status", tags=["review"])
async def change_finding_status(
    finding_id: str,
    status: str,
    notes: str = "",
):
    """Update the disposition of a finding (accept/reject/needs-review)."""
    try:
        new_status = FindingStatus(status)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {[s.value for s in FindingStatus]}",
        )

    ok = update_finding_status(finding_id, new_status, notes)
    if not ok:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"success": True, "finding_id": finding_id, "new_status": status}


# ════════════════════════════════════════════════════════════════════════
# Reports Export
# ════════════════════════════════════════════════════════════════════════

@router.get("/reviews/{review_id}/export/json", tags=["export"])
async def export_review_json(review_id: str):
    """Export a review as JSON file."""
    report = get_review(review_id)
    if not report:
        raise HTTPException(status_code=404, detail="Review not found")
    path = export_json(report)
    return FileResponse(path, media_type="application/json", filename=Path(path).name)


@router.get("/reviews/{review_id}/export/markdown", tags=["export"])
async def export_review_markdown(review_id: str):
    """Export a review as Markdown file."""
    report = get_review(review_id)
    if not report:
        raise HTTPException(status_code=404, detail="Review not found")
    path = export_markdown(report)
    return FileResponse(path, media_type="text/markdown", filename=Path(path).name)


# ════════════════════════════════════════════════════════════════════════
# Ingestion
# ════════════════════════════════════════════════════════════════════════

@router.post("/ingest", tags=["data"])
async def trigger_ingestion():
    """Trigger full data ingestion into ChromaDB."""
    try:
        summary = ingest_all_data()
        return {"success": True, "summary": summary}
    except Exception as e:
        logger.error("Ingestion failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ════════════════════════════════════════════════════════════════════════
# Audit Log
# ════════════════════════════════════════════════════════════════════════

@router.get("/audit", tags=["audit"])
async def get_audit(review_id: Optional[str] = None, limit: int = 100):
    """Retrieve audit log entries."""
    return get_audit_log(review_id=review_id, limit=limit)


# ════════════════════════════════════════════════════════════════════════
# Evaluation
# ════════════════════════════════════════════════════════════════════════

@router.get("/evaluation", tags=["evaluation"])
async def get_evaluation():
    """Retrieve evaluation results."""
    return get_evaluation_results()


# ════════════════════════════════════════════════════════════════════════
# Configuration
# ════════════════════════════════════════════════════════════════════════

@router.get("/config", tags=["system"])
async def get_current_config():
    """Return current non-sensitive configuration."""
    settings = get_settings()
    return {
        "ollama_base_url": settings.ollama_base_url,
        "ollama_model": settings.ollama_model,
        "embedding_model": settings.embedding_model,
        "rag_top_k": settings.rag_top_k,
        "rag_similarity_threshold": settings.rag_similarity_threshold,
        "chroma_persist_dir": settings.chroma_persist_dir,
        "random_seed": settings.random_seed,
    }
