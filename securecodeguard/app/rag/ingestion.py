"""
SecureCodeGuard – Data Ingestion Pipeline

Ingests C/C++ source files, guideline rules, compiler logs, static-analysis
outputs, and historical findings into ChromaDB collections.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import List, Optional

from app.config import get_settings
from app.parsers.code_chunker import CodeChunk, chunk_code_file
from app.parsers.log_parser import (
    GuidelineRule,
    LogEntry,
    StaticFinding,
    parse_compiler_log,
    parse_guidelines_json,
    parse_static_analysis_json,
)
from app.rag.vector_store import add_documents

logger = logging.getLogger(__name__)


def _make_id(prefix: str, content: str) -> str:
    """Generate a deterministic ID from content."""
    h = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{h}"


# ════════════════════════════════════════════════════════════════════════
# Code Ingestion
# ════════════════════════════════════════════════════════════════════════

def ingest_code_file(
    file_path: str,
    source_text: Optional[str] = None,
    case_id: Optional[str] = None,
) -> int:
    """
    Ingest a single C/C++ source file into the code collection.

    Returns the number of chunks added.
    """
    settings = get_settings()
    if source_text is None:
        p = Path(file_path)
        if not p.exists():
            logger.error("File not found: %s", file_path)
            return 0
        source_text = p.read_text(encoding="utf-8", errors="replace")

    chunks = chunk_code_file(source_text, file_path, case_id=case_id)
    if not chunks:
        logger.warning("No chunks extracted from %s", file_path)
        return 0

    ids = [_make_id("code", c.text) for c in chunks]
    texts = [c.text for c in chunks]
    metadatas = [c.metadata for c in chunks]

    return add_documents(
        collection_name=settings.chroma_collection_code,
        ids=ids,
        texts=texts,
        metadatas=metadatas,
    )


def ingest_code_directory(directory: str) -> int:
    """Ingest all C/C++ files in a directory."""
    total = 0
    dir_path = Path(directory)
    if not dir_path.exists():
        logger.error("Directory not found: %s", directory)
        return 0

    for ext in ("*.c", "*.h", "*.cpp", "*.hpp", "*.cc"):
        for fpath in dir_path.rglob(ext):
            try:
                count = ingest_code_file(str(fpath))
                total += count
                logger.info("Ingested %s → %d chunks", fpath.name, count)
            except Exception as e:
                logger.error("Failed to ingest %s: %s", fpath, e)
    return total


# ════════════════════════════════════════════════════════════════════════
# Guidelines Ingestion
# ════════════════════════════════════════════════════════════════════════

def ingest_guidelines_file(file_path: str) -> int:
    """Ingest a JSON file of guideline rules."""
    settings = get_settings()
    p = Path(file_path)
    if not p.exists():
        logger.error("Guidelines file not found: %s", file_path)
        return 0

    text = p.read_text(encoding="utf-8")
    rules = parse_guidelines_json(text)
    if not rules:
        return 0

    ids = [_make_id("rule", r.rule_id + r.title) for r in rules]
    texts = [r.text for r in rules]
    metadatas = [r.metadata for r in rules]

    return add_documents(
        collection_name=settings.chroma_collection_guidelines,
        ids=ids,
        texts=texts,
        metadatas=metadatas,
    )


def ingest_guidelines_directory(directory: str) -> int:
    """Ingest all JSON guideline files in a directory."""
    total = 0
    dir_path = Path(directory)
    if not dir_path.exists():
        return 0
    for fpath in dir_path.glob("*.json"):
        total += ingest_guidelines_file(str(fpath))
    return total


# ════════════════════════════════════════════════════════════════════════
# Log Ingestion
# ════════════════════════════════════════════════════════════════════════

def ingest_compiler_log(file_path: str) -> int:
    """Ingest a compiler log file."""
    settings = get_settings()
    p = Path(file_path)
    if not p.exists():
        return 0

    text = p.read_text(encoding="utf-8", errors="replace")
    entries = parse_compiler_log(text)
    if not entries:
        return 0

    ids = [_make_id("log", e.raw) for e in entries]
    texts = [e.raw for e in entries]
    metadatas = [e.metadata for e in entries]

    return add_documents(
        collection_name=settings.chroma_collection_logs,
        ids=ids,
        texts=texts,
        metadatas=metadatas,
    )


def ingest_logs_directory(directory: str) -> int:
    """Ingest all log files in a directory."""
    total = 0
    dir_path = Path(directory)
    if not dir_path.exists():
        return 0
    for fpath in dir_path.glob("*.log"):
        total += ingest_compiler_log(str(fpath))
    for fpath in dir_path.glob("*.txt"):
        total += ingest_compiler_log(str(fpath))
    return total


# ════════════════════════════════════════════════════════════════════════
# Static-Analysis Ingestion
# ════════════════════════════════════════════════════════════════════════

def ingest_static_analysis_file(file_path: str) -> int:
    """Ingest a static-analysis JSON file."""
    settings = get_settings()
    p = Path(file_path)
    if not p.exists():
        return 0

    text = p.read_text(encoding="utf-8")
    findings = parse_static_analysis_json(text)
    if not findings:
        return 0

    ids = [_make_id("sa", f.text) for f in findings]
    texts = [f.text for f in findings]
    metadatas = [f.metadata for f in findings]

    return add_documents(
        collection_name=settings.chroma_collection_static,
        ids=ids,
        texts=texts,
        metadatas=metadatas,
    )


def ingest_static_analysis_directory(directory: str) -> int:
    """Ingest all static-analysis JSON files in a directory."""
    total = 0
    dir_path = Path(directory)
    if not dir_path.exists():
        return 0
    for fpath in dir_path.glob("*.json"):
        total += ingest_static_analysis_file(str(fpath))
    return total


# ════════════════════════════════════════════════════════════════════════
# Historical Findings Ingestion
# ════════════════════════════════════════════════════════════════════════

def ingest_historical_findings(file_path: str) -> int:
    """Ingest a JSON file of historical approved findings."""
    settings = get_settings()
    p = Path(file_path)
    if not p.exists():
        return 0

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return 0

    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    if not isinstance(data, list):
        return 0

    ids = []
    texts = []
    metadatas = []
    for item in data:
        text = json.dumps(item, indent=2)
        ids.append(_make_id("hist", text))
        texts.append(text)
        metadatas.append({
            "doc_type": "historical",
            "finding_id": item.get("finding_id", ""),
            "category": item.get("category", ""),
            "file_path": item.get("file", ""),
            "status": item.get("status", "ACCEPTED"),
        })

    return add_documents(
        collection_name=settings.chroma_collection_historical,
        ids=ids,
        texts=texts,
        metadatas=metadatas,
    )


# ════════════════════════════════════════════════════════════════════════
# Full Ingestion
# ════════════════════════════════════════════════════════════════════════

def ingest_all_data() -> dict:
    """
    Ingest all data from configured directories.

    Returns a summary dict with counts per collection.
    """
    settings = get_settings()
    summary = {}

    code_dir = str(settings.resolve_path(settings.data_code_dir))
    summary["code_chunks"] = ingest_code_directory(code_dir)

    guidelines_dir = str(settings.resolve_path(settings.data_guidelines_dir))
    summary["guideline_rules"] = ingest_guidelines_directory(guidelines_dir)

    logs_dir = str(settings.resolve_path(settings.data_logs_dir))
    summary["log_entries"] = ingest_logs_directory(logs_dir)

    static_dir = str(settings.resolve_path(settings.data_static_dir))
    summary["static_findings"] = ingest_static_analysis_directory(static_dir)

    # Historical findings
    hist_dir = settings.resolve_path(settings.data_guidelines_dir)
    for fpath in hist_dir.glob("historical_*.json"):
        summary["historical_findings"] = ingest_historical_findings(str(fpath))

    logger.info("Ingestion summary: %s", summary)
    return summary
