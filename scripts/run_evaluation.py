"""
SecureCodeGuard – Evaluation Runner

Runs the full evaluation pipeline against the labeled test set.
For each test case:
  1. Reads the source file
  2. Runs deterministic checks + optional LLM review
  3. Compares findings to ground truth
  4. Computes metrics
  5. Exports results

Usage:
    python -m scripts.run_evaluation [--no-llm]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# Add project root to path
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from app.config import get_settings
from app.models import (
    EvaluationResult,
    EvaluationSummary,
    Finding,
    GroundTruthEntry,
    ReviewType,
)
from app.review.engine import run_review
from app.evaluation.scorer import compute_case_metrics, compute_aggregate_metrics
from app.rag.ingestion import ensure_data_ingested
from app.rag.vector_store import query_multiple_collections
from app.security.prompt_guard import detect_prompt_injection
from app.storage.database import init_db, save_evaluation_result

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-25s | %(levelname)-8s | %(message)s",
)
logger = logging.getLogger("evaluation")


def load_ground_truth(gt_path: str) -> list:
    """Load ground truth entries from JSON file."""
    with open(gt_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    entries = []
    for item in data:
        entries.append(GroundTruthEntry(**item))
    return entries


def group_by_file(entries: list) -> dict:
    """Group ground truth entries by file name."""
    groups = {}
    for entry in entries:
        fname = entry.file
        if fname not in groups:
            groups[fname] = []
        groups[fname].append(entry)
    return groups


def _get_rag_hits(file_name: str, gt_entries: list, top_k: int) -> list[bool]:
    """Measure whether review retrieval returned context relevant to each case."""
    results = query_multiple_collections(
        query_text=(
            "C/C++ code review security bugs defects buffer overflow "
            f"null pointer {file_name}"
        ),
        doc_types=["guidelines", "historical", "code"],
        top_k=top_k,
    )
    hits = []
    for entry in gt_entries:
        expected_category = entry.category.lower().replace("_", " ")
        code_hit = any(
            Path(item.get("metadata", {}).get("file_path", "")).name == entry.file
            and item.get("metadata", {}).get("function_name") == entry.function
            for item in results.get("code", [])
        )
        category_hit = any(
            item.get("metadata", {}).get("category", "").lower().replace("_", " ")
            == expected_category
            for doc_type in ("guidelines", "historical")
            for item in results.get(doc_type, [])
        )
        hits.append(code_hit or category_hit)
    return hits


def run_evaluation(use_llm: bool = True) -> EvaluationSummary:
    """
    Run the full evaluation pipeline.
    
    Parameters
    ----------
    use_llm : bool
        Whether to use the LLM for review. If False, only
        deterministic checks are evaluated.
    
    Returns
    -------
    EvaluationSummary
    """
    settings = get_settings()
    init_db()
    ensure_data_ingested()
    
    # Load ground truth
    gt_path = settings.resolve_path(settings.data_eval_dir) / "ground_truth.json"
    if not gt_path.exists():
        logger.error("Ground truth file not found: %s", gt_path)
        return EvaluationSummary()
    
    all_gt = load_ground_truth(str(gt_path))
    logger.info("Loaded %d ground truth entries", len(all_gt))
    
    # Group by file
    gt_by_file = group_by_file(all_gt)
    
    # Code directory
    code_dir = settings.resolve_path(settings.data_code_dir)
    
    results: list = []
    sample_outputs_dir = settings.resolve_path(settings.reports_dir) / "sample_outputs"
    sample_outputs_dir.mkdir(parents=True, exist_ok=True)
    
    for file_name, gt_entries in gt_by_file.items():
        file_path = code_dir / file_name
        if not file_path.exists():
            logger.warning("Source file not found: %s", file_path)
            continue
        
        source_code = file_path.read_text(encoding="utf-8", errors="replace")
        case_ids = [e.case_id for e in gt_entries]
        logger.info("Evaluating %s (cases: %s)", file_name, ", ".join(case_ids))
        
        # Check for adversarial content
        is_adversarial = any("ADV" in cid for cid in case_ids)
        
        # Run review
        start_time = time.time()
        try:
            report = run_review(
                source_code=source_code,
                file_name=file_name,
                review_type=ReviewType.FULL_REVIEW,
                use_llm=use_llm,
            )
        except Exception as e:
            logger.error("Review failed for %s: %s", file_name, e)
            results.append(EvaluationResult(
                case_id=",".join(case_ids),
                precision=0.0,
                recall=0.0,
                f1=0.0,
                latency_seconds=time.time() - start_time,
                details=f"Review failed: {e}",
            ))
            continue
        
        latency = time.time() - start_time
        
        # Compute metrics
        result = compute_case_metrics(
            findings=report.findings,
            ground_truth=gt_entries,
            rag_hits=_get_rag_hits(file_name, gt_entries, settings.rag_top_k),
            latency=latency,
        )
        if is_adversarial:
            injection_detected = any(
                finding.category == "prompt_injection"
                for finding in report.findings
            )
            result.prompt_injection_resistant = injection_detected and result.recall == 1.0
            if not result.prompt_injection_resistant:
                logger.warning(
                    "Adversarial test %s failed: injection_detected=%s, recall=%.3f",
                    file_name,
                    injection_detected,
                    result.recall,
                )
        result.case_id = ",".join(case_ids)
        
        results.append(result)
        logger.info(
            "  → P=%.3f R=%.3f F1=%.3f Latency=%.1fs",
            result.precision, result.recall, result.f1, result.latency_seconds,
        )
        
        # Save sample output
        output_data = {
            "file": file_name,
            "case_ids": case_ids,
            "report": json.loads(report.model_dump_json()),
            "metrics": {
                "precision": result.precision,
                "recall": result.recall,
                "f1": result.f1,
                "citation_accuracy": result.citation_accuracy,
                "latency": result.latency_seconds,
                "injection_resistant": result.prompt_injection_resistant,
            },
            "ground_truth": [gt.model_dump() for gt in gt_entries],
        }
        sample_path = sample_outputs_dir / f"eval_{file_name.replace('.c', '')}.json"
        with open(sample_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)
        
        # Save to DB
        save_evaluation_result(result)
    
    # Aggregate
    summary = compute_aggregate_metrics(results)
    logger.info("=" * 60)
    logger.info("EVALUATION SUMMARY")
    logger.info("=" * 60)
    logger.info("Total cases:             %d", summary.total_cases)
    logger.info("Avg Precision:           %.4f", summary.avg_precision)
    logger.info("Avg Recall:              %.4f", summary.avg_recall)
    logger.info("Avg F1:                  %.4f", summary.avg_f1)
    logger.info("Avg Citation Accuracy:   %.4f", summary.avg_citation_accuracy)
    logger.info("Avg Retrieval Hit Rate:  %.4f", summary.avg_retrieval_hit_rate)
    logger.info("Avg Latency:             %.3fs", summary.avg_latency)
    logger.info("Injection Pass Rate:     %.4f", summary.prompt_injection_pass_rate)
    
    # Export results
    reports_dir = settings.resolve_path(settings.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # JSON
    results_json = reports_dir / "evaluation_results.json"
    with open(results_json, "w", encoding="utf-8") as f:
        json.dump(json.loads(summary.model_dump_json()), f, indent=2)
    logger.info("Results saved to %s", results_json)
    
    # CSV
    results_csv = reports_dir / "evaluation_summary.csv"
    with open(results_csv, "w", encoding="utf-8") as f:
        f.write("case_id,precision,recall,f1,citation_accuracy,retrieval_hit_rate,latency_seconds,injection_resistant\n")
        for r in results:
            f.write(
                f"{r.case_id},{r.precision},{r.recall},{r.f1},"
                f"{r.citation_accuracy},{r.retrieval_hit_rate},"
                f"{r.latency_seconds},{r.prompt_injection_resistant}\n"
            )
        f.write(
            f"AVERAGE,{summary.avg_precision},{summary.avg_recall},{summary.avg_f1},"
            f"{summary.avg_citation_accuracy},{summary.avg_retrieval_hit_rate},"
            f"{summary.avg_latency},{summary.prompt_injection_pass_rate}\n"
        )
    logger.info("CSV saved to %s", results_csv)
    
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run SecureCodeGuard evaluation")
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Run evaluation with deterministic checks only (no LLM)",
    )
    args = parser.parse_args()
    
    summary = run_evaluation(use_llm=not args.no_llm)
    
    if summary.total_cases == 0:
        logger.error("No test cases were evaluated!")
        sys.exit(1)
    
    logger.info("Evaluation complete.")
