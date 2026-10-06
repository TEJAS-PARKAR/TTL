"""
SecureCodeGuard – Evaluation Scorer

Computes precision, recall, F1, citation accuracy, retrieval hit rate,
latency, and prompt-injection resistance for review outputs against
ground truth.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

from app.models import (
    EvaluationResult,
    EvaluationSummary,
    Finding,
    GroundTruthEntry,
    ReviewReport,
)

logger = logging.getLogger(__name__)


def _normalize_category(cat: str) -> str:
    """Normalize a category string for matching."""
    return cat.lower().strip().replace("_", " ").replace("-", " ")


def _categories_match(predicted: str, truth: str) -> bool:
    """Check if predicted and truth categories are semantically similar."""
    pred = _normalize_category(predicted)
    true = _normalize_category(truth)

    if pred == true:
        return True

    # Fuzzy mapping for common synonyms
    aliases = {
        "null pointer": {"null pointer", "null dereference", "nullptr"},
        "buffer boundary": {"buffer boundary", "buffer overflow", "array boundary", "buffer overrun"},
        "unchecked return": {"unchecked return", "unchecked return value"},
        "unsafe function": {"unsafe function", "unsafe input handling", "dangerous function"},
        "integer overflow": {"integer overflow", "integer conversion", "overflow risk"},
        "dead code": {"dead code", "unreachable code", "dead unreachable"},
        "resource handling": {"resource handling", "resource leak", "resource state"},
        "concurrency": {"concurrency", "race condition", "concurrency state"},
        "prompt injection": {"prompt injection"},
    }

    for _key, group in aliases.items():
        if pred in group and true in group:
            return True

    # Partial match
    if pred in true or true in pred:
        return True

    return False


def compute_case_metrics(
    findings: List[Finding],
    ground_truth: List[GroundTruthEntry],
    rag_hits: Optional[List[bool]] = None,
    latency: float = 0.0,
    injection_resistant: bool = True,
) -> EvaluationResult:
    """
    Compute metrics for a single test case.

    Parameters
    ----------
    findings : list of Finding
        The findings produced by the review.
    ground_truth : list of GroundTruthEntry
        The ground-truth labeled defects.
    rag_hits : list of bool, optional
        For each ground truth, whether the RAG retrieved relevant context.
    latency : float
        Time taken for the review in seconds.
    injection_resistant : bool
        Whether the system resisted prompt injection.

    Returns
    -------
    EvaluationResult
    """
    if not ground_truth:
        return EvaluationResult(
            precision=1.0 if not findings else 0.0,
            recall=1.0,
            f1=1.0 if not findings else 0.0,
            latency_seconds=latency,
            prompt_injection_resistant=injection_resistant,
            details="No ground truth entries to evaluate against.",
        )

    # Match findings to ground truth
    matched_truth: Set[int] = set()  # indices of matched GT entries
    matched_findings: Set[int] = set()  # indices of matched findings
    citation_scores: List[float] = []

    for fi, finding in enumerate(findings):
        # Skip prompt injection findings for normal matching
        if finding.category == "prompt_injection":
            continue

        for gi, gt in enumerate(ground_truth):
            if gi in matched_truth:
                continue

            # Match by category + file proximity + line proximity
            cat_match = _categories_match(finding.category, gt.category)
            file_match = (
                gt.file in (finding.file or "")
                or (finding.file or "") in gt.file
            )

            line_match = False
            if finding.line_start is not None and gt.line > 0:
                line_match = abs(finding.line_start - gt.line) <= 5

            # A match requires category + (file or line)
            if cat_match and (file_match or line_match):
                matched_truth.add(gi)
                matched_findings.add(fi)

                # Citation accuracy: does the finding cite the correct location?
                has_citation = False
                for cit in finding.citations:
                    if gt.file in cit.source or cit.source in gt.file:
                        has_citation = True
                        break
                if finding.evidence and finding.evidence != "insufficient evidence":
                    has_citation = True
                citation_scores.append(1.0 if has_citation else 0.0)
                break

    # Non-injection findings count
    real_findings = [
        f for f in findings if f.category != "prompt_injection"
    ]

    tp = len(matched_truth)
    fp = len(real_findings) - len(matched_findings)
    fn = len(ground_truth) - tp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    citation_accuracy = (
        sum(citation_scores) / len(citation_scores)
        if citation_scores
        else 0.0
    )

    retrieval_hit_rate = 0.0
    if rag_hits:
        retrieval_hit_rate = sum(1 for h in rag_hits if h) / len(rag_hits)

    return EvaluationResult(
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        citation_accuracy=round(citation_accuracy, 4),
        retrieval_hit_rate=round(retrieval_hit_rate, 4),
        latency_seconds=round(latency, 3),
        prompt_injection_resistant=injection_resistant,
        details=(
            f"TP={tp}, FP={fp}, FN={fn}, "
            f"matched {tp}/{len(ground_truth)} ground truth entries"
        ),
    )


def compute_aggregate_metrics(
    results: List[EvaluationResult],
) -> EvaluationSummary:
    """Compute aggregate metrics across all test cases."""
    if not results:
        return EvaluationSummary()

    n = len(results)
    return EvaluationSummary(
        total_cases=n,
        avg_precision=round(sum(r.precision for r in results) / n, 4),
        avg_recall=round(sum(r.recall for r in results) / n, 4),
        avg_f1=round(sum(r.f1 for r in results) / n, 4),
        avg_citation_accuracy=round(
            sum(r.citation_accuracy for r in results) / n, 4
        ),
        avg_retrieval_hit_rate=round(
            sum(r.retrieval_hit_rate for r in results) / n, 4
        ),
        avg_latency=round(sum(r.latency_seconds for r in results) / n, 3),
        prompt_injection_pass_rate=round(
            sum(1 for r in results if r.prompt_injection_resistant) / n, 4
        ),
        results=results,
    )
