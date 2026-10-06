"""
SecureCodeGuard – Pydantic Data Models
All structured schemas for findings, reviews, evaluation, and RAG documents.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


# ════════════════════════════════════════════════════════════════════════
# Enumerations
# ════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class FindingStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class ReviewType(str, Enum):
    CODE_EXPLANATION = "code_explanation"
    BUG_ANALYSIS = "bug_analysis"
    SECURE_REVIEW = "secure_review"
    MISRA_REVIEW = "misra_review"
    FULL_REVIEW = "full_review"


class DocType(str, Enum):
    CODE = "code"
    GUIDELINES = "guidelines"
    LOGS = "logs"
    STATIC_ANALYSIS = "static_analysis"
    HISTORICAL = "historical"


# ════════════════════════════════════════════════════════════════════════
# Citation & Finding
# ════════════════════════════════════════════════════════════════════════

class Citation(BaseModel):
    """A citation linking a finding to a source artifact."""
    source: str = Field(..., description="Source file or document name")
    location: str = Field(..., description="Line range, section, or page")
    snippet: str = Field(default="", description="Relevant code/text snippet")


class Finding(BaseModel):
    """A single code-review finding with evidence and traceability."""
    finding_id: str = Field(
        default_factory=lambda: f"FND-{uuid.uuid4().hex[:8].upper()}"
    )
    category: str = Field(..., description="Defect category")
    severity: Severity = Field(default=Severity.MEDIUM)
    title: str = Field(..., description="Short finding title")
    file: str = Field(default="unknown")
    function: Optional[str] = Field(default=None)
    line_start: Optional[int] = Field(default=None)
    line_end: Optional[int] = Field(default=None)
    evidence: str = Field(
        ...,
        description="Evidence text or 'insufficient evidence'"
    )
    reasoning: str = Field(default="")
    rule_refs: List[str] = Field(default_factory=list)
    citations: List[Citation] = Field(default_factory=list)
    suggested_fix: str = Field(default="")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: FindingStatus = Field(default=FindingStatus.CANDIDATE)


# ════════════════════════════════════════════════════════════════════════
# Review Report
# ════════════════════════════════════════════════════════════════════════

class ReviewReport(BaseModel):
    """Complete structured review report."""
    review_id: str = Field(
        default_factory=lambda: f"REV-{uuid.uuid4().hex[:8].upper()}"
    )
    summary: str = Field(default="")
    overall_risk: RiskLevel = Field(default=RiskLevel.UNKNOWN)
    findings: List[Finding] = Field(default_factory=list)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    model_used: str = Field(default="")
    review_type: str = Field(default="full_review")
    source_file: str = Field(default="")
    disclaimer: str = Field(
        default="AI-assisted engineering review. "
                "Findings require qualified human validation. "
                "This tool does NOT certify code, replace MISRA/certified "
                "static-analysis tools, approve releases, or guarantee security."
    )


# ════════════════════════════════════════════════════════════════════════
# RAG Document Chunks
# ════════════════════════════════════════════════════════════════════════

class CodeChunkMeta(BaseModel):
    """Metadata for a code chunk stored in the vector database."""
    file_path: str
    function_name: Optional[str] = None
    line_start: int = 0
    line_end: int = 0
    language: str = "c"
    case_id: Optional[str] = None
    doc_type: str = "code"


class GuidelineChunkMeta(BaseModel):
    """Metadata for a guideline/rule chunk."""
    rule_id: str
    title: str
    summary: str
    applicability: str = ""
    safe_practice: str = ""
    doc_type: str = "guidelines"


class LogChunkMeta(BaseModel):
    """Metadata for a compiler/build log chunk."""
    file_path: str
    log_type: str = "compiler"  # compiler | linker | runtime
    doc_type: str = "logs"


class StaticAnalysisChunkMeta(BaseModel):
    """Metadata for static-analysis output chunk."""
    tool_name: str = "synthetic_analyzer"
    file_path: str
    rule_id: Optional[str] = None
    doc_type: str = "static_analysis"


# ════════════════════════════════════════════════════════════════════════
# Ground Truth / Evaluation
# ════════════════════════════════════════════════════════════════════════

class GroundTruthEntry(BaseModel):
    """One labeled defect in the evaluation ground truth."""
    case_id: str
    file: str
    function: str
    line: int
    category: str
    severity: str
    explanation: str
    evidence: str
    acceptable_fix: str


class EvaluationResult(BaseModel):
    """Evaluation metrics for a single test case or aggregate."""
    case_id: str = ""
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    citation_accuracy: float = 0.0
    retrieval_hit_rate: float = 0.0
    latency_seconds: float = 0.0
    prompt_injection_resistant: bool = True
    details: str = ""


class EvaluationSummary(BaseModel):
    """Aggregate evaluation summary."""
    total_cases: int = 0
    avg_precision: float = 0.0
    avg_recall: float = 0.0
    avg_f1: float = 0.0
    avg_citation_accuracy: float = 0.0
    avg_retrieval_hit_rate: float = 0.0
    avg_latency: float = 0.0
    prompt_injection_pass_rate: float = 0.0
    results: List[EvaluationResult] = Field(default_factory=list)


# ════════════════════════════════════════════════════════════════════════
# Audit Record
# ════════════════════════════════════════════════════════════════════════

class AuditRecord(BaseModel):
    """Audit log entry stored in SQLite."""
    audit_id: str = Field(
        default_factory=lambda: f"AUD-{uuid.uuid4().hex[:8].upper()}"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    action: str = ""
    user: str = "local_user"
    review_id: Optional[str] = None
    finding_id: Optional[str] = None
    old_status: Optional[str] = None
    new_status: Optional[str] = None
    notes: str = ""


# ════════════════════════════════════════════════════════════════════════
# API Request / Response
# ════════════════════════════════════════════════════════════════════════

class ReviewRequest(BaseModel):
    """Request payload for a code review."""
    source_code: str = Field(..., description="C/C++ source code text")
    file_name: str = Field(default="uploaded.c")
    compiler_log: Optional[str] = Field(default=None)
    static_analysis_json: Optional[str] = Field(default=None)
    review_type: ReviewType = Field(default=ReviewType.FULL_REVIEW)


class ReviewResponse(BaseModel):
    """Response payload wrapping a ReviewReport."""
    success: bool = True
    message: str = ""
    report: Optional[ReviewReport] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"
    ollama_available: bool = False
    chroma_available: bool = False
    model: str = ""
    embedding_model: str = ""
