"""
SecureCodeGuard – Streamlit UI

Multi-page Streamlit application for secure code review.
Pages: Dashboard, Code Review, Debug Evidence, Rule Explorer,
       Findings, Evaluation, Audit/Configuration.

Run with: streamlit run ui/streamlit_app.py
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

# Add project root to path
_UI_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _UI_DIR.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from app.config import get_settings
from app.models import (
    FindingStatus,
    ReviewReport,
    ReviewType,
    Severity,
)
from app.review.engine import run_review
from app.review.report_exporter import export_json, export_markdown
from app.security.deterministic_checks import run_all_heuristic_checks
from app.security.prompt_guard import detect_prompt_injection
from app.storage.database import (
    get_audit_log,
    get_evaluation_results,
    get_review,
    init_db,
    list_reviews,
    save_review,
    update_finding_status,
)

# ════════════════════════════════════════════════════════════════════════
# Page Config
# ════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="SecureCodeGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ════════════════════════════════════════════════════════════════════════
# Custom CSS
# ════════════════════════════════════════════════════════════════════════

st.markdown("""
<style>
    /* Dark premium theme overrides */
    .main .block-container { padding-top: 1rem; }
    
    .disclaimer-banner {
        background: linear-gradient(135deg, #ff6b35 0%, #f7c948 100%);
        color: #1a1a2e;
        padding: 12px 20px;
        border-radius: 10px;
        font-weight: 600;
        text-align: center;
        margin-bottom: 20px;
        font-size: 14px;
        box-shadow: 0 4px 15px rgba(255, 107, 53, 0.3);
    }
    
    .metric-card {
        background: linear-gradient(135deg, #16213e 0%, #0f3460 100%);
        padding: 20px;
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.1);
        text-align: center;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    }
    
    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        background: linear-gradient(135deg, #00d2ff 0%, #3a7bd5 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .metric-label {
        font-size: 0.85rem;
        color: #a0aec0;
        margin-top: 4px;
    }
    
    .severity-critical {
        background: linear-gradient(135deg, #ff0844 0%, #ffb199 100%);
        color: white;
        padding: 3px 10px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 12px;
    }
    .severity-high {
        background: linear-gradient(135deg, #f12711 0%, #f5af19 100%);
        color: white;
        padding: 3px 10px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 12px;
    }
    .severity-medium {
        background: linear-gradient(135deg, #f7971e 0%, #ffd200 100%);
        color: #1a1a2e;
        padding: 3px 10px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 12px;
    }
    .severity-low {
        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        color: #1a1a2e;
        padding: 3px 10px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 12px;
    }
    
    .finding-card {
        background: rgba(22, 33, 62, 0.7);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 16px;
        margin: 8px 0;
        backdrop-filter: blur(10px);
    }
    
    .header-gradient {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2rem;
        font-weight: 800;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 8px 20px;
    }
</style>
""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════
# Initialize
# ════════════════════════════════════════════════════════════════════════

@st.cache_resource
def initialize():
    """Initialize database on first run."""
    init_db()
    return True

initialize()
settings = get_settings()


# ════════════════════════════════════════════════════════════════════════
# Disclaimer Banner
# ════════════════════════════════════════════════════════════════════════

st.markdown(
    '<div class="disclaimer-banner">'
    '⚠️ AI-assisted engineering review. Findings require qualified human validation. '
    'This tool does NOT certify code, replace MISRA/certified static-analysis tools, '
    'approve releases, or guarantee security.'
    '</div>',
    unsafe_allow_html=True,
)


# ════════════════════════════════════════════════════════════════════════
# Sidebar
# ════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown('<p class="header-gradient">🛡️ SecureCodeGuard</p>', unsafe_allow_html=True)
    st.caption("Secure Code Debugging & Review Assistant")
    st.divider()
    
    page = st.radio(
        "Navigation",
        [
            "📊 Dashboard",
            "🔍 Code Review",
            "🐛 Debug Evidence",
            "📖 Rule Explorer",
            "📋 Findings",
            "📈 Evaluation",
            "⚙️ Audit / Config",
        ],
        label_visibility="collapsed",
    )
    
    st.divider()
    st.caption(f"**Model:** {settings.ollama_model}")
    st.caption(f"**Embeddings:** {settings.embedding_model}")
    st.caption(f"**Version:** 1.0.0 (Academic Prototype)")


# ════════════════════════════════════════════════════════════════════════
# Helper Functions
# ════════════════════════════════════════════════════════════════════════

def severity_badge(sev: str) -> str:
    """Return HTML badge for severity level."""
    css_class = f"severity-{sev.lower()}"
    return f'<span class="{css_class}">{sev}</span>'


def render_metric(label: str, value: str, col):
    """Render a styled metric card."""
    col.markdown(
        f'<div class="metric-card">'
        f'<div class="metric-value">{value}</div>'
        f'<div class="metric-label">{label}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def load_sample_files() -> dict:
    """Load sample C files from data directory."""
    code_dir = settings.resolve_path(settings.data_code_dir)
    files = {}
    if code_dir.exists():
        for f in sorted(code_dir.glob("*.c")):
            files[f.name] = f.read_text(encoding="utf-8", errors="replace")
    return files


# ════════════════════════════════════════════════════════════════════════
# PAGE: Dashboard
# ════════════════════════════════════════════════════════════════════════

if page == "📊 Dashboard":
    st.markdown("## 📊 Dashboard")
    st.markdown("Overview of SecureCodeGuard system status and recent activity.")
    
    # Metrics row
    reviews = list_reviews()
    eval_results = get_evaluation_results()
    
    c1, c2, c3, c4 = st.columns(4)
    render_metric("Total Reviews", str(len(reviews)), c1)
    render_metric("Evaluations", str(len(eval_results)), c2)
    
    # Count findings by severity from recent reviews
    total_findings = 0
    critical_count = 0
    for r in reviews[:10]:
        report = get_review(r["review_id"])
        if report:
            total_findings += len(report.findings)
            critical_count += sum(
                1 for f in report.findings
                if f.severity.value in ("CRITICAL", "HIGH")
            )
    
    render_metric("Total Findings", str(total_findings), c3)
    render_metric("Critical/High", str(critical_count), c4)
    
    st.divider()
    
    # Recent reviews table
    st.markdown("### 📋 Recent Reviews")
    if reviews:
        for r in reviews[:10]:
            with st.expander(
                f"🔎 {r['review_id']} — {r['source_file']} "
                f"({r['overall_risk']}) — {r['timestamp'][:19]}"
            ):
                st.write(f"**Type:** {r['review_type']}")
                st.write(f"**Model:** {r['model_used']}")
                st.write(f"**Summary:** {r['summary']}")
    else:
        st.info("No reviews yet. Go to **Code Review** to analyze a file.")
    
    # System info
    st.divider()
    st.markdown("### 🔧 System Info")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"- **Ollama URL:** `{settings.ollama_base_url}`")
        st.markdown(f"- **LLM Model:** `{settings.ollama_model}`")
        st.markdown(f"- **Embedding:** `{settings.embedding_model}`")
    with col2:
        st.markdown(f"- **RAG Top-K:** `{settings.rag_top_k}`")
        st.markdown(f"- **Random Seed:** `{settings.random_seed}`")
        st.markdown(f"- **SQLite:** `{settings.sqlite_db_path}`")


# ════════════════════════════════════════════════════════════════════════
# PAGE: Code Review
# ════════════════════════════════════════════════════════════════════════

elif page == "🔍 Code Review":
    st.markdown("## 🔍 Code Review")
    
    # Source input
    st.markdown("### 📁 Source Code")
    input_method = st.radio(
        "Input method",
        ["Upload file", "Select sample", "Paste code"],
        horizontal=True,
    )
    
    source_code = ""
    file_name = "uploaded.c"
    
    if input_method == "Upload file":
        uploaded = st.file_uploader(
            "Upload C/C++ source file",
            type=["c", "h", "cpp", "hpp", "cc"],
        )
        if uploaded:
            source_code = uploaded.read().decode("utf-8", errors="replace")
            file_name = uploaded.name
    elif input_method == "Select sample":
        samples = load_sample_files()
        if samples:
            file_name = st.selectbox("Choose sample file", list(samples.keys()))
            source_code = samples.get(file_name, "")
        else:
            st.warning("No sample files found in data/code/")
    else:
        source_code = st.text_area(
            "Paste C/C++ code here",
            height=300,
            placeholder="// Paste your C/C++ code...",
        )
    
    if source_code:
        with st.expander("📄 View Source Code", expanded=False):
            st.code(source_code, language="c", line_numbers=True)
    
    # Optional evidence
    st.markdown("### 📎 Optional Evidence")
    col_a, col_b = st.columns(2)
    
    with col_a:
        compiler_log = st.text_area(
            "Compiler / Build Log (optional)",
            height=120,
            placeholder="Paste compiler warnings...",
        )
    
    with col_b:
        static_json = st.text_area(
            "Static Analysis JSON (optional)",
            height=120,
            placeholder='[{"tool": "...", "rule_id": "...", ...}]',
        )
    
    # Review type
    st.markdown("### ⚙️ Review Settings")
    col1, col2 = st.columns(2)
    with col1:
        review_type = st.selectbox(
            "Review Type",
            [
                "Full Review",
                "Code Explanation",
                "Bug Analysis",
                "Secure Review",
                "MISRA Review",
            ],
        )
        type_map = {
            "Full Review": ReviewType.FULL_REVIEW,
            "Code Explanation": ReviewType.CODE_EXPLANATION,
            "Bug Analysis": ReviewType.BUG_ANALYSIS,
            "Secure Review": ReviewType.SECURE_REVIEW,
            "MISRA Review": ReviewType.MISRA_REVIEW,
        }
    with col2:
        use_llm = st.checkbox("Use LLM (requires Ollama)", value=True)
    
    # Run button
    st.divider()
    if st.button("🚀 Run Analysis", type="primary", use_container_width=True):
        if not source_code.strip():
            st.error("Please provide source code to analyze.")
        else:
            with st.spinner("Running analysis..."):
                start = time.time()
                try:
                    report = run_review(
                        source_code=source_code,
                        file_name=file_name,
                        compiler_log=compiler_log if compiler_log.strip() else None,
                        static_analysis_json=static_json if static_json.strip() else None,
                        review_type=type_map[review_type],
                        use_llm=use_llm,
                    )
                    elapsed = time.time() - start
                    
                    # Save
                    save_review(report)
                    st.session_state["last_report"] = report
                    
                    st.success(
                        f"✅ Review complete in {elapsed:.1f}s — "
                        f"{len(report.findings)} findings "
                        f"(Risk: {report.overall_risk.value})"
                    )
                except Exception as e:
                    st.error(f"Review failed: {e}")
    
    # Display results
    if "last_report" in st.session_state:
        report = st.session_state["last_report"]
        
        st.divider()
        st.markdown("### 📊 Results")
        
        # Summary
        st.markdown(f"**Overall Risk:** {severity_badge(report.overall_risk.value)}", unsafe_allow_html=True)
        st.write(report.summary)
        
        # Findings
        if report.findings:
            st.markdown(f"### 🔎 Findings ({len(report.findings)})")
            
            for i, finding in enumerate(report.findings):
                sev = severity_badge(finding.severity.value)
                with st.expander(
                    f"#{i+1} [{finding.severity.value}] {finding.title} "
                    f"({finding.file}:{finding.line_start or '?'})"
                ):
                    st.markdown(f"**Severity:** {sev}", unsafe_allow_html=True)
                    st.markdown(f"**Category:** {finding.category}")
                    st.markdown(f"**File:** `{finding.file}`")
                    if finding.function:
                        st.markdown(f"**Function:** `{finding.function}`")
                    if finding.line_start:
                        st.markdown(f"**Lines:** {finding.line_start}–{finding.line_end or finding.line_start}")
                    st.markdown(f"**Confidence:** {finding.confidence:.0%}")
                    
                    st.markdown("**Evidence:**")
                    st.code(finding.evidence, language="c")
                    
                    if finding.reasoning:
                        st.markdown("**Reasoning:**")
                        st.write(finding.reasoning)
                    
                    if finding.rule_refs:
                        st.markdown(f"**Rule References:** {', '.join(finding.rule_refs)}")
                    
                    if finding.citations:
                        st.markdown("**Citations:**")
                        for c in finding.citations:
                            st.write(f"- [{c.source}] {c.location}: `{c.snippet[:80]}`")
                    
                    if finding.suggested_fix:
                        st.markdown("**Suggested Fix:**")
                        st.code(finding.suggested_fix, language="c")
                    
                    # Disposition
                    st.divider()
                    col_s1, col_s2, col_s3 = st.columns(3)
                    with col_s1:
                        if st.button("✅ Accept", key=f"accept_{finding.finding_id}"):
                            update_finding_status(
                                finding.finding_id, FindingStatus.ACCEPTED
                            )
                            st.success("Accepted")
                    with col_s2:
                        if st.button("❌ Reject", key=f"reject_{finding.finding_id}"):
                            update_finding_status(
                                finding.finding_id, FindingStatus.REJECTED
                            )
                            st.warning("Rejected")
                    with col_s3:
                        if st.button("🔄 Needs Review", key=f"review_{finding.finding_id}"):
                            update_finding_status(
                                finding.finding_id, FindingStatus.NEEDS_REVIEW
                            )
                            st.info("Marked for review")
        
        # Export
        st.divider()
        st.markdown("### 📤 Export Report")
        col_e1, col_e2 = st.columns(2)
        with col_e1:
            if st.button("📄 Export JSON"):
                path = export_json(report)
                st.success(f"Exported to {path}")
                with open(path, "r") as f:
                    st.download_button(
                        "⬇️ Download JSON",
                        data=f.read(),
                        file_name=Path(path).name,
                        mime="application/json",
                    )
        with col_e2:
            if st.button("📝 Export Markdown"):
                path = export_markdown(report)
                st.success(f"Exported to {path}")
                with open(path, "r") as f:
                    st.download_button(
                        "⬇️ Download Markdown",
                        data=f.read(),
                        file_name=Path(path).name,
                        mime="text/markdown",
                    )


# ════════════════════════════════════════════════════════════════════════
# PAGE: Debug Evidence
# ════════════════════════════════════════════════════════════════════════

elif page == "🐛 Debug Evidence":
    st.markdown("## 🐛 Debug Evidence Viewer")
    st.markdown("View compiler logs and static analysis findings.")
    
    tab1, tab2 = st.tabs(["📋 Compiler Logs", "🔬 Static Analysis"])
    
    with tab1:
        log_dir = settings.resolve_path(settings.data_logs_dir)
        if log_dir.exists():
            log_files = list(log_dir.glob("*.log")) + list(log_dir.glob("*.txt"))
            if log_files:
                selected_log = st.selectbox(
                    "Select log file",
                    [f.name for f in log_files],
                )
                log_path = log_dir / selected_log
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
                st.code(log_text, language="text", line_numbers=True)
                
                # Parse and show structured
                from app.parsers.log_parser import parse_compiler_log
                entries = parse_compiler_log(log_text)
                if entries:
                    st.markdown(f"### Parsed Entries ({len(entries)})")
                    for e in entries:
                        icon = "🔴" if e.level == "error" else "🟡"
                        st.write(
                            f"{icon} **{e.file}:{e.line}** [{e.level}] "
                            f"{e.message} `{e.code}`"
                        )
            else:
                st.info("No log files found.")
        else:
            st.info("Log directory not found.")
    
    with tab2:
        sa_dir = settings.resolve_path(settings.data_static_dir)
        if sa_dir.exists():
            sa_files = list(sa_dir.glob("*.json"))
            if sa_files:
                selected_sa = st.selectbox(
                    "Select analysis file",
                    [f.name for f in sa_files],
                )
                sa_path = sa_dir / selected_sa
                sa_text = sa_path.read_text(encoding="utf-8")
                
                from app.parsers.log_parser import parse_static_analysis_json
                findings = parse_static_analysis_json(sa_text)
                
                if findings:
                    st.markdown(f"### Static Analysis Findings ({len(findings)})")
                    for f in findings:
                        sev = severity_badge(f.severity)
                        st.markdown(
                            f'<div class="finding-card">'
                            f'{sev} <b>{f.rule_id}</b> — {f.message}<br>'
                            f'<small>📁 {f.file}:{f.line or "?"} | Tool: {f.tool}</small>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
                
                with st.expander("Raw JSON"):
                    st.json(json.loads(sa_text))
            else:
                st.info("No static analysis files found.")
        else:
            st.info("Static analysis directory not found.")


# ════════════════════════════════════════════════════════════════════════
# PAGE: Rule Explorer
# ════════════════════════════════════════════════════════════════════════

elif page == "📖 Rule Explorer":
    st.markdown("## 📖 Secure Coding Rule Explorer")
    st.markdown(
        "Browse synthetic academic rule summaries. "
        "These are NOT copyrighted MISRA standard text."
    )
    
    guidelines_dir = settings.resolve_path(settings.data_guidelines_dir)
    rules_file = guidelines_dir / "secure_coding_rules.json"
    
    if rules_file.exists():
        rules_data = json.loads(rules_file.read_text(encoding="utf-8"))
        rules = rules_data.get("rules", [])
        
        # Search
        search = st.text_input("🔍 Search rules", placeholder="e.g., buffer, null, overflow")
        
        filtered = rules
        if search:
            search_lower = search.lower()
            filtered = [
                r for r in rules
                if search_lower in r.get("title", "").lower()
                or search_lower in r.get("summary", "").lower()
                or search_lower in r.get("rule_id", "").lower()
                or search_lower in r.get("category", "").lower()
            ]
        
        st.markdown(f"**Showing {len(filtered)} / {len(rules)} rules**")
        
        for rule in filtered:
            with st.expander(f"📌 {rule['rule_id']}: {rule['title']}"):
                st.markdown(f"**Category:** `{rule.get('category', '')}`")
                st.markdown(f"**Summary:** {rule['summary']}")
                st.markdown(f"**Applicability:** {rule.get('applicability', '')}")
                st.markdown(f"**Safe Practice:** {rule.get('safe_practice', '')}")
    else:
        st.warning("Rules file not found. Run data ingestion first.")


# ════════════════════════════════════════════════════════════════════════
# PAGE: Findings
# ════════════════════════════════════════════════════════════════════════

elif page == "📋 Findings":
    st.markdown("## 📋 All Findings")
    
    reviews = list_reviews()
    if not reviews:
        st.info("No reviews found. Run a code review first.")
    else:
        # Filter controls
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            selected_review = st.selectbox(
                "Select Review",
                [f"{r['review_id']} — {r['source_file']}" for r in reviews],
            )
        
        review_id = selected_review.split(" — ")[0]
        report = get_review(review_id)
        
        if report:
            st.markdown(
                f"**Risk:** {severity_badge(report.overall_risk.value)} | "
                f"**Findings:** {len(report.findings)} | "
                f"**Model:** {report.model_used}",
                unsafe_allow_html=True,
            )
            st.write(report.summary)
            
            # Findings table
            for i, f in enumerate(report.findings):
                sev = severity_badge(f.severity.value)
                status_icons = {
                    "CANDIDATE": "🔵",
                    "ACCEPTED": "✅",
                    "REJECTED": "❌",
                    "NEEDS_REVIEW": "🔄",
                }
                s_icon = status_icons.get(f.status.value, "🔵")
                
                with st.expander(
                    f"{s_icon} [{f.severity.value}] {f.title} — {f.status.value}"
                ):
                    st.markdown(f"**ID:** `{f.finding_id}`")
                    st.markdown(f"**Severity:** {sev}", unsafe_allow_html=True)
                    st.markdown(f"**File:** `{f.file}` | **Line:** {f.line_start or 'N/A'}")
                    st.markdown(f"**Confidence:** {f.confidence:.0%}")
                    st.code(f.evidence, language="c")
                    if f.reasoning:
                        st.write(f.reasoning)


# ════════════════════════════════════════════════════════════════════════
# PAGE: Evaluation
# ════════════════════════════════════════════════════════════════════════

elif page == "📈 Evaluation":
    st.markdown("## 📈 Evaluation Results")
    st.markdown("Results from running the system against the labeled test set.")
    
    eval_results = get_evaluation_results()
    
    # Check for exported files
    reports_dir = settings.resolve_path(settings.reports_dir)
    eval_json = reports_dir / "evaluation_results.json"
    eval_csv = reports_dir / "evaluation_summary.csv"
    
    if eval_json.exists():
        data = json.loads(eval_json.read_text(encoding="utf-8"))
        
        # Summary metrics
        st.markdown("### Aggregate Metrics")
        c1, c2, c3, c4 = st.columns(4)
        render_metric("Avg Precision", f"{data.get('avg_precision', 0):.3f}", c1)
        render_metric("Avg Recall", f"{data.get('avg_recall', 0):.3f}", c2)
        render_metric("Avg F1", f"{data.get('avg_f1', 0):.3f}", c3)
        render_metric("Injection Pass", f"{data.get('prompt_injection_pass_rate', 0):.0%}", c4)
        
        st.markdown("")
        c5, c6, c7, c8 = st.columns(4)
        render_metric("Cases", str(data.get("total_cases", 0)), c5)
        render_metric("Citation Acc", f"{data.get('avg_citation_accuracy', 0):.3f}", c6)
        render_metric("Retrieval Hit", f"{data.get('avg_retrieval_hit_rate', 0):.3f}", c7)
        render_metric("Avg Latency", f"{data.get('avg_latency', 0):.1f}s", c8)
        
        # Per-case results
        st.divider()
        st.markdown("### Per-Case Results")
        case_results = data.get("results", [])
        if case_results:
            import pandas as pd
            df = pd.DataFrame(case_results)
            st.dataframe(df, use_container_width=True)
        
        # Download
        st.divider()
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                "⬇️ Download JSON",
                data=eval_json.read_text(),
                file_name="evaluation_results.json",
                mime="application/json",
            )
        with col2:
            if eval_csv.exists():
                st.download_button(
                    "⬇️ Download CSV",
                    data=eval_csv.read_text(),
                    file_name="evaluation_summary.csv",
                    mime="text/csv",
                )
    
    elif eval_results:
        st.markdown("### Database Results")
        import pandas as pd
        df = pd.DataFrame(eval_results)
        st.dataframe(df, use_container_width=True)
    else:
        st.info(
            "No evaluation results found. Run the evaluation script:\n\n"
            "```\npython -m scripts.run_evaluation --no-llm\n```"
        )


# ════════════════════════════════════════════════════════════════════════
# PAGE: Audit / Config
# ════════════════════════════════════════════════════════════════════════

elif page == "⚙️ Audit / Config":
    st.markdown("## ⚙️ Audit Log & Configuration")
    
    tab1, tab2 = st.tabs(["📜 Audit Log", "🔧 Configuration"])
    
    with tab1:
        audit_entries = get_audit_log(limit=50)
        if audit_entries:
            for entry in audit_entries:
                icon = "📝" if entry["action"] == "REVIEW_CREATED" else "🔄"
                st.write(
                    f"{icon} **{entry['timestamp'][:19]}** | "
                    f"{entry['action']} | "
                    f"Review: `{entry.get('review_id', 'N/A')}` | "
                    f"{entry.get('notes', '')}"
                )
                if entry.get("old_status") and entry.get("new_status"):
                    st.caption(
                        f"  Finding {entry['finding_id']}: "
                        f"{entry['old_status']} → {entry['new_status']}"
                    )
        else:
            st.info("No audit entries yet.")
    
    with tab2:
        st.markdown("### Current Configuration")
        config = {
            "Ollama URL": settings.ollama_base_url,
            "LLM Model": settings.ollama_model,
            "Embedding Model": settings.embedding_model,
            "Embedding Device": settings.embedding_device,
            "RAG Top-K": settings.rag_top_k,
            "Similarity Threshold": settings.rag_similarity_threshold,
            "ChromaDB Dir": settings.chroma_persist_dir,
            "SQLite Path": settings.sqlite_db_path,
            "Random Seed": settings.random_seed,
            "Log Level": settings.log_level,
        }
        
        for key, value in config.items():
            st.write(f"**{key}:** `{value}`")
        
        st.divider()
        st.markdown("### Data Ingestion")
        if st.button("🔄 Run Data Ingestion", type="primary"):
            with st.spinner("Ingesting data into ChromaDB..."):
                try:
                    from app.rag.ingestion import ingest_all_data
                    summary = ingest_all_data()
                    st.success(f"Ingestion complete: {summary}")
                except Exception as e:
                    st.error(f"Ingestion failed: {e}")
        
        st.divider()
        st.markdown(
            "### ⚠️ Limitations\n"
            "- This is an **academic prototype**\n"
            "- Does NOT certify or approve code\n"
            "- Does NOT replace certified static analysis\n"
            "- Requires human validation of all findings\n"
            "- Local-first: no source code sent to external APIs"
        )
