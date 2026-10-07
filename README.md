# SecureCodeGuard: Secure Code Debugging & Review Assistant

**PCCOE AI/ML Capstone – Case Study 4**  
*Author: Tejas Parkar (PRN: 123B1D063)*

---

## 1. Project Overview

**SecureCodeGuard** is a local-first, AI-assisted code debugging and secure code review assistant tailored for automotive ECU embedded software (C/C++). It blends deterministic AST/lexical static checks with a multi-collection Retrieval-Augmented Generation (RAG) pipeline and strict system prompt guardrails to identify vulnerabilities, suggest remediations, enforce synthetic MISRA-oriented guidelines, and maintain a verifiable human triage audit trail.

---

## 2. Key Features

- 🛡️ **Local-First & Privacy Preserving**: Zero code leakage to external cloud APIs. Runs entirely on local LLMs (via Ollama) and local embeddings.
- 🔍 **Dual-Layer Analysis Engine**: Combines deterministic high-precision rule checkers (unbounded functions, unhandled returns, null dereferences, dead code) with semantic LLM analysis.
- 📚 **Multi-Collection ChromaDB RAG**: Segregated collections for source code AST chunks, synthetic MISRA guidelines (`RULE-001` to `RULE-012`), compiler logs, static analysis findings, and approved historical reviews.
- 🛑 **Prompt Injection & Adversarial Guardrails**: Robust defenses against prompt injection attacks hidden inside comments or string literals.
- 👥 **Human-in-the-Loop Triage**: Interactive status management (`CANDIDATE` → `APPROVED`, `REJECTED`, `FALSE_POSITIVE`, `FIXED`) with complete SQLite audit trail.
- 📊 **Automated Benchmark & Evaluation**: Ground truth evaluation harness calculating Precision, Recall, F1, Citation Accuracy, Latency, and Adversarial Pass Rates.
- 📄 **Exportable Reports**: Structured reports in JSON and Markdown formats.
- 🎨 **Modern Streamlit Dashboard**: Clean dark-themed user interface with interactive tabs for code review, compiler debug evidence, rule explorer, triage, evaluation, and system diagnostics.

---

## 3. Project Directory Structure

```text
securecodeguard/
├── .env.example                # Configuration template
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Container definition
├── docker-compose.yml          # Container orchestration
├── app/
│   ├── config.py               # Settings & environment parser
│   ├── models.py               # Pydantic data schemas
│   ├── parsers/                # Code chunker, compiler log & static analysis parsers
│   ├── rag/                    # Embeddings & ChromaDB vector store
│   ├── security/               # Deterministic static checks & prompt injection defense
│   ├── review/                 # LLM client, review engine & report exporters
│   ├── storage/                # SQLite review & audit database
│   ├── evaluation/             # Precision/Recall/F1 metrics & benchmark scorer
│   ├── api/                    # FastAPI REST routes
│   └── main.py                 # FastAPI backend server
├── data/
│   ├── code/                   # Synthetic C/C++ ECU test cases & adversarial samples
│   ├── guidelines/             # Synthetic MISRA rules & historical approved findings
│   ├── logs/                   # Synthetic compiler warning logs
│   ├── static_analysis/        # Synthetic static analysis tool output
│   └── evaluation/             # Ground truth benchmark labels
├── docs/
│   ├── ARCHITECTURE.md         # Detailed system design & component diagrams
│   ├── THREAT_MODEL.md         # Threat model, STRIDE analysis & boundaries
│   ├── EVALUATION.md           # Evaluation methodology & benchmark details
│   └── DEMO_SCRIPT.md          # Step-by-step presentation demo script
├── scripts/
│   └── run_evaluation.py       # Automated evaluation benchmark runner
├── tests/
│   └── test_unit.py            # Comprehensive unit test suite (49 tests)
└── ui/
    └── streamlit_app.py        # Streamlit web application
```

---

## 4. Getting Started

### Prerequisites
- Python 3.10+
- (Optional for neural LLM generation) [Ollama](https://ollama.com/) with `mistral:7b-instruct-v0.3-q4_K_M` or `llama3:8b`

### Installation

1. **Clone the repository and enter the directory**:
   ```bash
   cd securecodeguard
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   # On Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**:
   ```bash
   cp .env.example .env
   ```

---

## 5. Running the Application

### Quick Start (Standalone Mode):
Simply run the single unified entrypoint:
```bash
python app.py
```
*(Or double-click `run.bat` on Windows)*

Alternatively, run directly via Streamlit:
```bash
streamlit run app.py
```
Open [http://localhost:8501](http://localhost:8501) in your web browser.

---

## 6. Running Tests & Benchmarks

### Run Unit Tests
```bash
pytest tests/test_unit.py -v
```
*(49 unit tests covering parsing, chunking, deterministic checks, RAG, prompt defense, schemas, and scoring)*

### Run Ground Truth Evaluation
```bash
python scripts/run_evaluation.py
```
Generates detailed benchmark evaluation metrics saved to `reports/evaluation_results.json` and `reports/evaluation_summary.csv`.

---

## 7. Synthetic Rule Set

The system ships with 12 synthetic automotive safe-coding rules modeled after MISRA C standards:
- `RULE-001`: Prohibition of Unbounded Input Functions (`gets`, `scanf("%s")`)
- `RULE-002`: Mandatory Bounds Checking on String Operations (`strcpy`, `strcat`)
- `RULE-003`: Format String Vulnerability Prevention (`sprintf`, `snprintf`)
- `RULE-004`: Mandatory Null-Pointer Validation Following Allocation (`malloc`, `calloc`)
- `RULE-005`: Dynamic Memory Allocation Prohibited in Safety-Critical Real-Time Paths
- `RULE-006`: Prohibition of Unchecked Return Values for Critical APIs
- `RULE-007`: Elimination of Dead / Unreachable Code
- `RULE-008`: Arithmetic Overflow & Wrap-Around Prevention
- `RULE-009`: Deterministic Termination & Bounds on Loops
- `RULE-010`: Resource Lifecycle Management & Leak Prevention
- `RULE-011`: Concurrency & Shared State Protection
- `RULE-012`: Explicit Switch Statement Termination & Break Statements

---

## 8. License

Developed for academic demonstration as part of the PCCOE AI/ML Capstone Project.
