# SecureCodeGuard – Live Demonstration Script

## Step-by-Step Walkthrough Guide for Capstone Presentation

This guide provides a scripted walkthrough demonstrating all features of SecureCodeGuard.

---

### Step 1: Launch the Application
Run the Streamlit web application:
```bash
streamlit run ui/streamlit_app.py
```
Open your browser at `http://localhost:8501`.

---

### Step 2: Dashboard Overview
1. Observe the **System Health & Metrics** tiles: Active Model, ChromaDB collections count, Ground Truth test cases count.
2. Review the **Disclaimer Banner** stating the academic prototype scope.

---

### Step 3: Code Review Demonstration (Brake Controller Demo)
1. Navigate to the **Code Review** page in the sidebar.
2. Select **Sample Code: `brake_controller.c`** or paste C code with known defects.
3. Check the options:
   - Include Synthetic Compiler Log (`compiler_warnings.log`)
   - Include Static Analysis Evidence (`analysis_results.json`)
   - Enable RAG Knowledge Retrieval
4. Click **Run Security Review**.
5. Observe the structured findings table:
   - Defect categorization (Buffer boundary, Unchecked return value, Forbidden function)
   - Severity & Confidence indicators
   - Precise line citations and evidence snippets
   - Linked Synthetic MISRA rules (`RULE-001`, `RULE-004`, `RULE-007`)
   - Actionable remediation advice

---

### Step 4: Human-in-the-Loop Triage
1. Navigate to the **Findings Management** page.
2. Click on a candidate finding.
3. Select a status transition: change `CANDIDATE` → `APPROVED`.
4. Add reviewer notes (e.g., *"Confirmed buffer overflow on line 42 during sprint review"*).
5. Click **Update Status**.
6. View the updated audit record in the **Audit Trail** table.

---

### Step 5: Rule Explorer & RAG Semantic Query
1. Go to the **Rule Explorer** page.
2. Search for `"pointer"` or `"buffer"`.
3. Examine the matched synthetic guidelines with rationales and code examples.

---

### Step 6: Adversarial Robustness Test
1. Select `adversarial_test_1.c` in the **Code Review** page.
2. Click **Run Security Review**.
3. Point out that the system prompt guard detected and safely neutralized the injected directives inside code comments.

---

### Step 7: Run Evaluation Benchmark
1. Navigate to the **Evaluation** tab.
2. Click **Run Ground Truth Evaluation**.
3. Watch real-time metrics update: Precision, Recall, F1 Score, Citation Accuracy, and Latency.
4. Export the evaluation report as CSV and JSON.
