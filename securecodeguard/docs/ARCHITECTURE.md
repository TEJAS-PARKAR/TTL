# SecureCodeGuard – System Architecture

## 1. Overview & Architectural Philosophy

**SecureCodeGuard** is an AI-assisted secure code debugging and review platform engineered specifically for automotive / ECU C and C++ embedded software. Built for the **PCCOE AI/ML Capstone (Case Study 4)**, the system combines deterministic static pattern checkers with a local-first Retrieval-Augmented Generation (RAG) pipeline and human-in-the-loop triage.

```
+-------------------------------------------------------------------------+
|                              PRESENTATION LAYER                         |
|  Streamlit Multi-Page UI (Dashboard, Review, Evidence, Rules, Audit)    |
|  FastAPI Endpoints (/api/v1/review, /api/v1/findings, /api/v1/evaluate) |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                                CORE ENGINE                              |
|  app.review.engine.run_review()                                         |
|  - Deterministic Rule Engine (RegEx / C-AST pattern checkers)           |
|  - Prompt Injection Guard (Dual-layer sanitization & detection)         |
|  - Hybrid Finding Merger & Deduplication (IoU / line proximity)        |
+------------------+----------------------------------+-------------------+
                   |                                  |
                   v                                  v
+------------------------------------+  +---------------------------------+
|         RAG SUBSYSTEM              |  |         STORAGE LAYER           |
| - Embeddings (BGE / S-Transformers)|  | - SQLite (Audit log & reviews)  |
| - ChromaDB Multi-Collection Vector |  | - JSON / Markdown Report Export |
| - Metadata Filter (doc_type routing|  | - Ground Truth Benchmark Repo   |
+------------------------------------+  +---------------------------------+
                   |
                   v
+-------------------------------------------------------------------------+
|                       LOCAL LLM EXECUTION LAYER                         |
|  Ollama REST Client (Mistral-7B / Llama-3 / Codellama)                  |
|  - Strict system prompt confinement & zero external data leakage        |
+-------------------------------------------------------------------------+
```

---

## 2. Core Architectural Components

### 2.1 Multi-Collection ChromaDB Vector Store
To avoid noisy semantic cross-contamination, knowledge is segregated into dedicated vector collections:
- `code_chunks`: C/C++ AST-aware function slices with boundary line numbers.
- `guideline_chunks`: Synthetic automotive and MISRA-oriented safe coding rules (`RULE-001` .. `RULE-012`).
- `log_chunks`: Compiler diagnostic outputs (GCC/Clang warnings & errors).
- `static_analysis_chunks`: Static analysis rule violations and tool findings.
- `historical_findings`: Past reviewed and approved triage decisions.

### 2.2 Dual-Layer Verification (Deterministic + Neural)
- **Deterministic Static Engine (`deterministic_checks.py`)**: Runs high-confidence regular expressions and lexical scans for forbidden functions (`gets`, `strcpy`, `sprintf`), unchecked pointer dereferences, unhandled return codes, and dead code.
- **LLM Semantic Reviewer (`engine.py` & `llm_client.py`)**: Ingests the chunked source code, compiler evidence, and retrieved guidelines, outputting strictly validated JSON schemas.
- **Deduplication & Merger**: Findings overlapping in line numbers and defect categories are unified, boosting confidence when both engines agree.

### 2.3 Defense-in-Depth Prompt Injection Shield (`prompt_guard.py`)
- **System Confinement**: Strict boundary prompts declare all incoming code, comments, string literals, and compiler output as **UNTRUSTED DATA**.
- **Adversarial Pattern Scanner**: Scans for prompt injection attacks (`ignore previous instructions`, `reveal system prompt`, `classify as safe`) and flags them as explicit adversarial events.

### 2.4 Human-in-the-Loop Triage & Auditability (`database.py`)
- Every generated issue begins in status `CANDIDATE`.
- Reviewers mark findings as `APPROVED`, `REJECTED`, `FALSE_POSITIVE`, or `FIXED`.
- Every transition is immutably timestamped and recorded in SQLite with reviewer rationale.

---

## 3. Data Flow

1. **Ingestion**: C/C++ source code is uploaded or selected from test fixtures.
2. **Parsing & Chunking**: `CodeChunker` splits code into functions while preserving metadata.
3. **Evidence Cross-Referencing**: `LogParser` and `StaticAnalysisParser` extract line-matched warnings.
4. **Context Retrieval**: The query is embedded and relevant guidelines/rules are fetched via vector similarity.
5. **Prompt Construction**: Sanitized inputs and retrieved context are packaged into a structured prompt.
6. **Inference & Parsing**: Local Ollama model responds with JSON, which is parsed with resilient error recovery.
7. **Synthesis & Storage**: Deterministic and LLM findings are merged, validated against Pydantic models, and persisted to SQLite.
8. **Export**: Reports are rendered to JSON and Markdown with formal academic disclaimers.
