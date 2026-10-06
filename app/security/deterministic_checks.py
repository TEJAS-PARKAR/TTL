"""
SecureCodeGuard – Deterministic Static Checks (Heuristic)

Lightweight regex/pattern-based checks independent of the LLM.
These are clearly labeled as **heuristics** – NOT certified static analysis.

Checks implemented:
1. Dangerous C functions (strcpy, sprintf, gets, etc.)
2. Suspicious array indexing patterns
3. Obvious null-pointer dereference patterns
4. Unchecked return values for selected functions
5. Integer conversion / overflow heuristics
6. Dead / unreachable code patterns
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class HeuristicFinding:
    """A finding produced by a deterministic heuristic check."""
    check_id: str
    category: str
    title: str
    file: str
    line: int
    snippet: str
    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    explanation: str
    rule_refs: List[str] = field(default_factory=list)
    confidence: float = 0.85  # heuristic confidence
    is_heuristic: bool = True

    @property
    def label(self) -> str:
        return f"[HEURISTIC] {self.check_id}: {self.title}"


# ════════════════════════════════════════════════════════════════════════
# Pattern libraries
# ════════════════════════════════════════════════════════════════════════

_DANGEROUS_FUNCS = {
    "gets":    ("CRITICAL", "RULE-001", "Use of gets() – unbounded input read"),
    "strcpy":  ("HIGH",     "RULE-002", "Use of strcpy() – no bounds checking"),
    "strcat":  ("HIGH",     "RULE-002", "Use of strcat() – no bounds checking"),
    "sprintf": ("HIGH",     "RULE-002", "Use of sprintf() – no bounds checking"),
    "scanf":   ("MEDIUM",   "RULE-006", "Use of scanf() without width specifier"),
    "atoi":    ("MEDIUM",   "RULE-005", "Use of atoi() – no error handling"),
    "atof":    ("MEDIUM",   "RULE-005", "Use of atof() – no error handling"),
}

_MUST_CHECK_RETURN = {
    "malloc", "calloc", "realloc", "fopen", "fread", "fwrite",
    "fclose", "pthread_create", "pthread_mutex_lock",
    "send", "recv", "read", "write",
}


def _lines_with_numbers(source: str) -> List[tuple]:
    """Return list of (1-indexed line number, line text)."""
    return [(i + 1, line) for i, line in enumerate(source.splitlines())]


# ════════════════════════════════════════════════════════════════════════
# Check 1: Dangerous C functions
# ════════════════════════════════════════════════════════════════════════

def check_dangerous_functions(
    source: str, file_path: str = "unknown"
) -> List[HeuristicFinding]:
    """Detect calls to known-dangerous C functions."""
    findings: List[HeuristicFinding] = []
    for lineno, line in _lines_with_numbers(source):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        for func, (sev, rule, desc) in _DANGEROUS_FUNCS.items():
            pattern = rf'\b{func}\s*\('
            if re.search(pattern, line):
                findings.append(HeuristicFinding(
                    check_id=f"DC-{func.upper()}",
                    category="unsafe_function",
                    title=desc,
                    file=file_path,
                    line=lineno,
                    snippet=stripped,
                    severity=sev,
                    explanation=(
                        f"Heuristic: detected call to {func}() at line {lineno}. "
                        f"This function is widely considered unsafe for production "
                        f"automotive/ECU code."
                    ),
                    rule_refs=[rule],
                ))
    return findings


# ════════════════════════════════════════════════════════════════════════
# Check 2: Suspicious array indexing
# ════════════════════════════════════════════════════════════════════════

_ARRAY_INDEX_RE = re.compile(
    r'\b(\w+)\s*\[\s*([^]]+)\s*\]'
)

_NEGATIVE_INDEX_RE = re.compile(r'-\s*\d+')
_VAR_MINUS_RE = re.compile(r'\w+\s*-\s*\d+')


def check_array_indexing(
    source: str, file_path: str = "unknown"
) -> List[HeuristicFinding]:
    """Detect suspicious array index expressions."""
    findings: List[HeuristicFinding] = []
    for lineno, line in _lines_with_numbers(source):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        for m in _ARRAY_INDEX_RE.finditer(line):
            idx_expr = m.group(2).strip()
            arr_name = m.group(1).strip()
            # Negative constant index
            if _NEGATIVE_INDEX_RE.fullmatch(idx_expr):
                findings.append(HeuristicFinding(
                    check_id="AI-NEG",
                    category="buffer_boundary",
                    title=f"Negative array index on '{arr_name}'",
                    file=file_path,
                    line=lineno,
                    snippet=stripped,
                    severity="HIGH",
                    explanation=(
                        f"Heuristic: array '{arr_name}' indexed with a "
                        f"negative expression '{idx_expr}' at line {lineno}."
                    ),
                    rule_refs=["RULE-003"],
                ))
            # Index expression uses subtraction (potential underflow)
            elif _VAR_MINUS_RE.search(idx_expr) and "sizeof" not in idx_expr:
                findings.append(HeuristicFinding(
                    check_id="AI-SUB",
                    category="buffer_boundary",
                    title=f"Array index subtraction on '{arr_name}'",
                    file=file_path,
                    line=lineno,
                    snippet=stripped,
                    severity="MEDIUM",
                    explanation=(
                        f"Heuristic: array '{arr_name}' index uses subtraction "
                        f"'{idx_expr}' which may underflow at line {lineno}."
                    ),
                    rule_refs=["RULE-003"],
                ))
    return findings


# ════════════════════════════════════════════════════════════════════════
# Check 3: Null-pointer dereference patterns
# ════════════════════════════════════════════════════════════════════════

_MALLOC_ASSIGN_RE = re.compile(
    r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\('
)
_NULL_CHECK_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*[!=]=\s*NULL\s*\)'
)


def check_null_pointer(
    source: str, file_path: str = "unknown"
) -> List[HeuristicFinding]:
    """Detect obvious null-pointer dereference risks after allocation."""
    findings: List[HeuristicFinding] = []
    lines = _lines_with_numbers(source)

    for i, (lineno, line) in enumerate(lines):
        m = _MALLOC_ASSIGN_RE.search(line)
        if not m:
            continue
        var = m.group(1)
        # Check next 5 lines for a NULL check
        next_lines = [l for _, l in lines[i + 1: i + 6]]
        has_null_check = any(
            re.search(rf'\b{re.escape(var)}\s*[!=]=\s*NULL', nl)
            or re.search(rf'if\s*\(\s*!?\s*{re.escape(var)}\s*\)', nl)
            for nl in next_lines
        )
        if not has_null_check:
            # Check if var is used (dereferenced) without check
            used = any(
                re.search(rf'\b{re.escape(var)}\s*[\[\->\.]', nl)
                or re.search(rf'\*\s*{re.escape(var)}', nl)
                for nl in next_lines
            )
            if used:
                findings.append(HeuristicFinding(
                    check_id="NP-ALLOC",
                    category="null_pointer",
                    title=f"Potential null-pointer dereference of '{var}'",
                    file=file_path,
                    line=lineno,
                    snippet=line.strip(),
                    severity="HIGH",
                    explanation=(
                        f"Heuristic: '{var}' assigned from allocation at line "
                        f"{lineno} and used without apparent NULL check."
                    ),
                    rule_refs=["RULE-004"],
                ))
    return findings


# ════════════════════════════════════════════════════════════════════════
# Check 4: Unchecked return values
# ════════════════════════════════════════════════════════════════════════

_CALL_RE = re.compile(r'\b(' + '|'.join(_MUST_CHECK_RETURN) + r')\s*\(')


def check_unchecked_return(
    source: str, file_path: str = "unknown"
) -> List[HeuristicFinding]:
    """Detect calls to functions whose return values should be checked."""
    findings: List[HeuristicFinding] = []
    for lineno, line in _lines_with_numbers(source):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        m = _CALL_RE.search(line)
        if not m:
            continue
        func_name = m.group(1)
        # If line doesn't contain an assignment or condition, flag it
        has_assignment = re.search(r'\w+\s*=', line[:m.start()])
        is_in_condition = re.search(r'if\s*\(', line) or re.search(r'while\s*\(', line)
        if not has_assignment and not is_in_condition:
            findings.append(HeuristicFinding(
                check_id=f"UR-{func_name.upper()}",
                category="unchecked_return",
                title=f"Unchecked return value of {func_name}()",
                file=file_path,
                line=lineno,
                snippet=stripped,
                severity="MEDIUM",
                explanation=(
                    f"Heuristic: return value of {func_name}() at line {lineno} "
                    f"is not assigned or checked. This may hide errors."
                ),
                rule_refs=["RULE-005"],
            ))
    return findings


# ════════════════════════════════════════════════════════════════════════
# Check 5: Integer conversion / overflow heuristics
# ════════════════════════════════════════════════════════════════════════

_INT_CAST_RE = re.compile(
    r'\(\s*(?:uint8_t|int8_t|uint16_t|int16_t|char|short|unsigned\s+char)\s*\)'
    r'\s*\(?(\w+)'
)

_INT_MULT_RE = re.compile(
    r'\b(\w+)\s*\*\s*(\w+)\b'
)


def check_integer_overflow(
    source: str, file_path: str = "unknown"
) -> List[HeuristicFinding]:
    """Detect suspicious integer casts and multiplication patterns."""
    findings: List[HeuristicFinding] = []
    for lineno, line in _lines_with_numbers(source):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        # Narrowing cast
        for m in _INT_CAST_RE.finditer(line):
            findings.append(HeuristicFinding(
                check_id="IO-NARROW",
                category="integer_overflow",
                title="Narrowing integer cast",
                file=file_path,
                line=lineno,
                snippet=stripped,
                severity="MEDIUM",
                explanation=(
                    f"Heuristic: narrowing cast at line {lineno} "
                    f"may truncate value of '{m.group(1)}'."
                ),
                rule_refs=["RULE-007"],
                confidence=0.6,
            ))
    return findings


# ════════════════════════════════════════════════════════════════════════
# Check 6: Dead / unreachable code
# ════════════════════════════════════════════════════════════════════════

_RETURN_THEN_CODE_RE = re.compile(
    r'^\s*return\b', re.MULTILINE
)


def check_dead_code(
    source: str, file_path: str = "unknown"
) -> List[HeuristicFinding]:
    """Detect obvious unreachable code after return statements."""
    findings: List[HeuristicFinding] = []
    lines = _lines_with_numbers(source)
    in_block = False
    for i, (lineno, line) in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        if _RETURN_THEN_CODE_RE.match(line):
            # Check next non-blank, non-brace line
            for j in range(i + 1, min(i + 4, len(lines))):
                nxt = lines[j][1].strip()
                if nxt and nxt != "}" and not nxt.startswith("//") \
                        and not nxt.startswith("/*") and not nxt.startswith("case ") \
                        and not nxt.startswith("default:") and not nxt.startswith("#"):
                    findings.append(HeuristicFinding(
                        check_id="DC-UNREACH",
                        category="dead_code",
                        title="Unreachable code after return",
                        file=file_path,
                        line=lines[j][0],
                        snippet=nxt,
                        severity="LOW",
                        explanation=(
                            f"Heuristic: code at line {lines[j][0]} appears "
                            f"unreachable after return at line {lineno}."
                        ),
                        rule_refs=["RULE-008"],
                        confidence=0.7,
                    ))
                    break
                elif nxt == "}" or nxt.startswith("case ") or nxt.startswith("default:"):
                    break
    return findings


# ════════════════════════════════════════════════════════════════════════
# Master runner
# ════════════════════════════════════════════════════════════════════════

def run_all_heuristic_checks(
    source: str, file_path: str = "unknown"
) -> List[HeuristicFinding]:
    """Run all deterministic heuristic checks and return combined findings."""
    results: List[HeuristicFinding] = []
    results.extend(check_dangerous_functions(source, file_path))
    results.extend(check_array_indexing(source, file_path))
    results.extend(check_null_pointer(source, file_path))
    results.extend(check_unchecked_return(source, file_path))
    results.extend(check_integer_overflow(source, file_path))
    results.extend(check_dead_code(source, file_path))
    return results
