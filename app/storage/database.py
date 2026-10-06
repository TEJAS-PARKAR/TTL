"""
SecureCodeGuard – SQLite Database Layer

Stores review reports, findings with disposition, audit logs,
and evaluation results.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from app.config import get_settings
from app.models import (
    AuditRecord,
    EvaluationResult,
    Finding,
    FindingStatus,
    ReviewReport,
)

logger = logging.getLogger(__name__)


def _get_db_path() -> str:
    """Resolve the SQLite database path."""
    settings = get_settings()
    db_path = settings.resolve_path(settings.sqlite_db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return str(db_path)


def init_db() -> None:
    """Create all tables if they don't exist."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS reviews (
            review_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            summary TEXT,
            overall_risk TEXT,
            model_used TEXT,
            review_type TEXT,
            source_file TEXT,
            report_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            review_id TEXT NOT NULL,
            category TEXT,
            severity TEXT,
            title TEXT,
            file TEXT,
            function TEXT,
            line_start INTEGER,
            line_end INTEGER,
            evidence TEXT,
            reasoning TEXT,
            suggested_fix TEXT,
            confidence REAL,
            status TEXT DEFAULT 'CANDIDATE',
            rule_refs TEXT,
            citations TEXT,
            FOREIGN KEY (review_id) REFERENCES reviews(review_id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            action TEXT,
            user TEXT DEFAULT 'local_user',
            review_id TEXT,
            finding_id TEXT,
            old_status TEXT,
            new_status TEXT,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS evaluation_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            timestamp TEXT,
            precision_score REAL,
            recall_score REAL,
            f1_score REAL,
            citation_accuracy REAL,
            retrieval_hit_rate REAL,
            latency_seconds REAL,
            prompt_injection_resistant INTEGER DEFAULT 1,
            details TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_findings_review
            ON findings(review_id);
        CREATE INDEX IF NOT EXISTS idx_findings_status
            ON findings(status);
        CREATE INDEX IF NOT EXISTS idx_audit_review
            ON audit_log(review_id);
    """)

    conn.commit()
    conn.close()
    logger.info("Database initialized at %s", db_path)


# ════════════════════════════════════════════════════════════════════════
# Reviews
# ════════════════════════════════════════════════════════════════════════

def save_review(report: ReviewReport) -> str:
    """Save a ReviewReport and its findings to the database."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Save review
    cursor.execute(
        """INSERT OR REPLACE INTO reviews
           (review_id, timestamp, summary, overall_risk, model_used,
            review_type, source_file, report_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            report.review_id,
            report.timestamp,
            report.summary,
            report.overall_risk.value,
            report.model_used,
            report.review_type,
            report.source_file,
            report.model_dump_json(),
        ),
    )

    # Save findings
    for finding in report.findings:
        cursor.execute(
            """INSERT OR REPLACE INTO findings
               (finding_id, review_id, category, severity, title,
                file, function, line_start, line_end, evidence,
                reasoning, suggested_fix, confidence, status,
                rule_refs, citations)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.finding_id,
                report.review_id,
                finding.category,
                finding.severity.value,
                finding.title,
                finding.file,
                finding.function,
                finding.line_start,
                finding.line_end,
                finding.evidence,
                finding.reasoning,
                finding.suggested_fix,
                finding.confidence,
                finding.status.value,
                json.dumps(finding.rule_refs),
                json.dumps([c.model_dump() for c in finding.citations]),
            ),
        )

    # Audit log
    cursor.execute(
        """INSERT INTO audit_log
           (audit_id, timestamp, action, review_id, notes)
           VALUES (?, ?, ?, ?, ?)""",
        (
            f"AUD-{report.review_id}",
            datetime.utcnow().isoformat(),
            "REVIEW_CREATED",
            report.review_id,
            f"Review created with {len(report.findings)} findings",
        ),
    )

    conn.commit()
    conn.close()
    logger.info("Saved review %s with %d findings", report.review_id, len(report.findings))
    return report.review_id


def get_review(review_id: str) -> Optional[ReviewReport]:
    """Retrieve a review report by ID."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT report_json FROM reviews WHERE review_id = ?",
        (review_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return ReviewReport.model_validate_json(row[0])
    return None


def list_reviews() -> List[dict]:
    """List all reviews (summary info only)."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """SELECT review_id, timestamp, summary, overall_risk,
                  model_used, review_type, source_file
           FROM reviews ORDER BY timestamp DESC"""
    )
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "review_id": r[0],
            "timestamp": r[1],
            "summary": r[2][:100] if r[2] else "",
            "overall_risk": r[3],
            "model_used": r[4],
            "review_type": r[5],
            "source_file": r[6],
        }
        for r in rows
    ]


# ════════════════════════════════════════════════════════════════════════
# Finding Disposition
# ════════════════════════════════════════════════════════════════════════

def update_finding_status(
    finding_id: str,
    new_status: FindingStatus,
    notes: str = "",
    user: str = "local_user",
) -> bool:
    """Update the disposition status of a finding."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get current status
    cursor.execute(
        "SELECT status, review_id FROM findings WHERE finding_id = ?",
        (finding_id,),
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    old_status = row[0]
    review_id = row[1]

    # Update
    cursor.execute(
        "UPDATE findings SET status = ? WHERE finding_id = ?",
        (new_status.value, finding_id),
    )

    # Audit
    cursor.execute(
        """INSERT INTO audit_log
           (audit_id, timestamp, action, user, review_id, finding_id,
            old_status, new_status, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            f"AUD-{finding_id}-{datetime.utcnow().strftime('%H%M%S')}",
            datetime.utcnow().isoformat(),
            "STATUS_CHANGE",
            user,
            review_id,
            finding_id,
            old_status,
            new_status.value,
            notes,
        ),
    )

    conn.commit()
    conn.close()
    logger.info("Finding %s: %s → %s", finding_id, old_status, new_status.value)
    return True


# ════════════════════════════════════════════════════════════════════════
# Audit Log
# ════════════════════════════════════════════════════════════════════════

def get_audit_log(
    review_id: Optional[str] = None,
    limit: int = 100,
) -> List[dict]:
    """Retrieve audit log entries."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    if review_id:
        cursor.execute(
            """SELECT audit_id, timestamp, action, user, review_id,
                      finding_id, old_status, new_status, notes
               FROM audit_log WHERE review_id = ?
               ORDER BY timestamp DESC LIMIT ?""",
            (review_id, limit),
        )
    else:
        cursor.execute(
            """SELECT audit_id, timestamp, action, user, review_id,
                      finding_id, old_status, new_status, notes
               FROM audit_log ORDER BY timestamp DESC LIMIT ?""",
            (limit,),
        )

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "audit_id": r[0],
            "timestamp": r[1],
            "action": r[2],
            "user": r[3],
            "review_id": r[4],
            "finding_id": r[5],
            "old_status": r[6],
            "new_status": r[7],
            "notes": r[8],
        }
        for r in rows
    ]


# ════════════════════════════════════════════════════════════════════════
# Evaluation Results
# ════════════════════════════════════════════════════════════════════════

def save_evaluation_result(result: EvaluationResult) -> None:
    """Save an evaluation result to the database."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """INSERT INTO evaluation_results
           (case_id, timestamp, precision_score, recall_score, f1_score,
            citation_accuracy, retrieval_hit_rate, latency_seconds,
            prompt_injection_resistant, details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            result.case_id,
            datetime.utcnow().isoformat(),
            result.precision,
            result.recall,
            result.f1,
            result.citation_accuracy,
            result.retrieval_hit_rate,
            result.latency_seconds,
            1 if result.prompt_injection_resistant else 0,
            result.details,
        ),
    )

    conn.commit()
    conn.close()


def get_evaluation_results() -> List[dict]:
    """Retrieve all evaluation results."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """SELECT case_id, timestamp, precision_score, recall_score,
                  f1_score, citation_accuracy, retrieval_hit_rate,
                  latency_seconds, prompt_injection_resistant, details
           FROM evaluation_results ORDER BY timestamp DESC"""
    )
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "case_id": r[0],
            "timestamp": r[1],
            "precision": r[2],
            "recall": r[3],
            "f1": r[4],
            "citation_accuracy": r[5],
            "retrieval_hit_rate": r[6],
            "latency_seconds": r[7],
            "prompt_injection_resistant": bool(r[8]),
            "details": r[9],
        }
        for r in rows
    ]
