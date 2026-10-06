"""
SecureCodeGuard – Review Engine

Orchestrates the full review pipeline:
  RAG retrieval → context construction → prompt injection check →
  deterministic checks → LLM review → schema validation → merge findings.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from app.config import get_settings
from app.models import (
    Citation,
    Finding,
    FindingStatus,
    ReviewReport,
    ReviewType,
    RiskLevel,
    Severity,
)
from app.rag.vector_store import query_multiple_collections
from app.review.llm_client import get_llm_client
from app.security.deterministic_checks import (
    HeuristicFinding,
    run_all_heuristic_checks,
)
from app.security.prompt_guard import (
    CODE_EXPLANATION_PROMPT,
    CODE_REVIEW_PROMPT_TEMPLATE,
    DEBUG_ANALYSIS_PROMPT,
    SYSTEM_PROMPT,
    detect_prompt_injection,
    sanitize_for_prompt,
)

logger = logging.getLogger(__name__)


def _heuristic_to_finding(h: HeuristicFinding) -> Finding:
    """Convert a HeuristicFinding to a structured Finding."""
    return Finding(
        finding_id=f"FND-H{uuid.uuid4().hex[:6].upper()}",
        category=h.category,
        severity=Severity(h.severity) if h.severity in Severity.__members__ else Severity.MEDIUM,
        title=f"[HEURISTIC] {h.title}",
        file=h.file,
        function=None,
        line_start=h.line,
        line_end=h.line,
        evidence=h.snippet,
        reasoning=h.explanation,
        rule_refs=h.rule_refs,
        citations=[Citation(
            source=h.file,
            location=f"line {h.line}",
            snippet=h.snippet,
        )],
        suggested_fix="",
        confidence=h.confidence,
        status=FindingStatus.CANDIDATE,
    )


def _build_context_section(
    results: Dict[str, list],
    doc_type: str,
    header: str,
    max_items: int = 5,
) -> str:
    """Build a context section from RAG results."""
    items = results.get(doc_type, [])
    if not items:
        return f"{header}\nNo relevant {doc_type} found in knowledge base.\n"

    parts = [header]
    for item in items[:max_items]:
        text = item.get("text", "")[:500]
        meta = item.get("metadata", {})
        source = meta.get("file_path", meta.get("rule_id", "unknown"))
        parts.append(f"[Source: {source}]\n{text}\n---")
    return "\n".join(parts)


def _determine_overall_risk(findings: List[Finding]) -> RiskLevel:
    """Determine overall risk from the highest-severity finding."""
    if not findings:
        return RiskLevel.LOW

    severities = [f.severity.value for f in findings]
    if "CRITICAL" in severities:
        return RiskLevel.CRITICAL
    if "HIGH" in severities:
        return RiskLevel.HIGH
    if "MEDIUM" in severities:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _parse_llm_findings(json_data: dict) -> List[Finding]:
    """Parse findings from LLM JSON response into Finding models."""
    findings = []
    raw_findings = json_data.get("findings", [])

    for rf in raw_findings:
        try:
            # Parse citations
            citations = []
            for c in rf.get("citations", []):
                citations.append(Citation(
                    source=c.get("source", "unknown"),
                    location=c.get("location", ""),
                    snippet=c.get("snippet", ""),
                ))

            # Parse severity
            sev_str = rf.get("severity", "MEDIUM").upper()
            try:
                severity = Severity(sev_str)
            except ValueError:
                severity = Severity.MEDIUM

            finding = Finding(
                finding_id=rf.get("finding_id", f"FND-{uuid.uuid4().hex[:8].upper()}"),
                category=rf.get("category", "unknown"),
                severity=severity,
                title=rf.get("title", "Untitled finding"),
                file=rf.get("file", "unknown"),
                function=rf.get("function"),
                line_start=rf.get("line_start"),
                line_end=rf.get("line_end"),
                evidence=rf.get("evidence", "insufficient evidence"),
                reasoning=rf.get("reasoning", ""),
                rule_refs=rf.get("rule_refs", []),
                citations=citations,
                suggested_fix=rf.get("suggested_fix", ""),
                confidence=min(1.0, max(0.0, rf.get("confidence", 0.5))),
                status=FindingStatus.CANDIDATE,
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse finding: %s", e)
            continue

    return findings


def run_review(
    source_code: str,
    file_name: str = "uploaded.c",
    compiler_log: Optional[str] = None,
    static_analysis_json: Optional[str] = None,
    review_type: ReviewType = ReviewType.FULL_REVIEW,
    use_llm: bool = True,
) -> ReviewReport:
    """
    Execute a complete code review pipeline.

    Steps:
    1. Run deterministic heuristic checks
    2. Check for prompt injection in source code
    3. Query RAG for relevant context
    4. Build prompt and call LLM (if available)
    5. Merge heuristic + LLM findings
    6. Validate schema
    7. Return structured report

    Parameters
    ----------
    source_code : str
        The C/C++ source code to review.
    file_name : str
        Name of the source file.
    compiler_log : str, optional
        Compiler/build log text.
    static_analysis_json : str, optional
        Static-analysis JSON text.
    review_type : ReviewType
        Type of review to perform.
    use_llm : bool
        Whether to invoke the LLM (False for deterministic-only mode).

    Returns
    -------
    ReviewReport
    """
    settings = get_settings()
    all_findings: List[Finding] = []
    llm_summary = ""
    model_used = "none (deterministic only)"

    # ── Step 1: Deterministic heuristic checks ───────────────────────
    logger.info("Running deterministic heuristic checks on %s", file_name)
    heuristic_results = run_all_heuristic_checks(source_code, file_name)
    for h in heuristic_results:
        all_findings.append(_heuristic_to_finding(h))
    logger.info("Heuristic checks found %d issues", len(heuristic_results))

    # ── Step 2: Prompt injection detection ───────────────────────────
    injections = detect_prompt_injection(source_code)
    if injections:
        logger.warning(
            "Prompt injection attempts detected in source: %d patterns",
            len(injections),
        )
        for inj in injections:
            all_findings.append(Finding(
                finding_id=f"FND-INJ{uuid.uuid4().hex[:6].upper()}",
                category="prompt_injection",
                severity=Severity.HIGH,
                title="Prompt injection attempt detected",
                file=file_name,
                line_start=inj.get("line"),
                line_end=inj.get("line"),
                evidence=inj.get("matched_text", ""),
                reasoning=(
                    f"Detected potential prompt injection pattern at line "
                    f"{inj.get('line', '?')}: '{inj.get('matched_text', '')}'. "
                    f"This content was treated as untrusted data and not "
                    f"executed as instructions."
                ),
                rule_refs=["RULE-010"],
                citations=[Citation(
                    source=file_name,
                    location=f"line {inj.get('line', '?')}",
                    snippet=inj.get("matched_text", ""),
                )],
                confidence=0.9,
                status=FindingStatus.CANDIDATE,
            ))

    # ── Step 3: RAG retrieval ────────────────────────────────────────
    logger.info("Querying RAG knowledge base")
    rag_query = (
        f"C/C++ code review security bugs defects "
        f"buffer overflow null pointer {file_name}"
    )
    try:
        rag_results = query_multiple_collections(
            query_text=rag_query,
            doc_types=["guidelines", "historical", "code"],
            top_k=settings.rag_top_k,
        )
    except Exception as e:
        logger.warning("RAG query failed: %s", e)
        rag_results = {}

    # ── Step 4: Build prompt and call LLM ────────────────────────────
    if use_llm:
        llm = get_llm_client()
        if llm.is_available():
            model_used = settings.ollama_model

            # Build context sections
            guidelines_ctx = _build_context_section(
                rag_results, "guidelines",
                "RELEVANT SECURE-CODING GUIDELINES:",
            )
            historical_ctx = _build_context_section(
                rag_results, "historical",
                "RELEVANT HISTORICAL FINDINGS:",
            )

            # Compiler log section
            compiler_section = ""
            if compiler_log:
                compiler_section = (
                    f"COMPILER/BUILD LOG (UNTRUSTED DATA):\n"
                    f"```\n{sanitize_for_prompt(compiler_log, 2000)}\n```"
                )

            # Static analysis section
            static_section = ""
            if static_analysis_json:
                static_section = (
                    f"STATIC ANALYSIS OUTPUT (UNTRUSTED DATA):\n"
                    f"```\n{sanitize_for_prompt(static_analysis_json, 2000)}\n```"
                )

            # Select prompt template
            if review_type == ReviewType.CODE_EXPLANATION:
                prompt = CODE_EXPLANATION_PROMPT.format(
                    source_code=sanitize_for_prompt(source_code),
                )
            elif review_type == ReviewType.BUG_ANALYSIS:
                prompt = DEBUG_ANALYSIS_PROMPT.format(
                    source_code=sanitize_for_prompt(source_code),
                    compiler_log_section=compiler_section,
                    static_analysis_section=static_section,
                )
            else:
                prompt = CODE_REVIEW_PROMPT_TEMPLATE.format(
                    source_code=sanitize_for_prompt(source_code),
                    compiler_log_section=compiler_section,
                    static_analysis_section=static_section,
                    guidelines_context=guidelines_ctx,
                    historical_context=historical_ctx,
                    review_type=review_type.value,
                )

            # Call LLM
            logger.info("Calling LLM for review (%s)", review_type.value)
            json_response = llm.generate_json(prompt, SYSTEM_PROMPT)

            if json_response:
                llm_summary = json_response.get("summary", "")
                llm_findings = _parse_llm_findings(json_response)
                all_findings.extend(llm_findings)
                logger.info("LLM returned %d findings", len(llm_findings))
            else:
                logger.warning("LLM returned no parseable response")
                llm_summary = "LLM did not return a parseable response."
        else:
            logger.warning("Ollama is not available – using deterministic checks only")
            llm_summary = (
                "Ollama LLM was not available. Only deterministic heuristic "
                "checks were performed."
            )
    else:
        llm_summary = "LLM analysis was not requested. Showing deterministic results only."

    # ── Step 5: Build report ─────────────────────────────────────────
    summary_parts = []
    if llm_summary:
        summary_parts.append(llm_summary)
    summary_parts.append(
        f"Deterministic heuristic checks: {len(heuristic_results)} issues found."
    )
    if injections:
        summary_parts.append(
            f"WARNING: {len(injections)} prompt injection attempt(s) detected in source."
        )

    report = ReviewReport(
        summary=" ".join(summary_parts),
        overall_risk=_determine_overall_risk(all_findings),
        findings=all_findings,
        model_used=model_used,
        review_type=review_type.value,
        source_file=file_name,
    )

    logger.info(
        "Review complete: %d findings, risk=%s",
        len(report.findings), report.overall_risk.value,
    )
    return report
