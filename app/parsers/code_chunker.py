"""
SecureCodeGuard – C/C++ Code-Aware Chunker
Splits C/C++ source files into function-level chunks, preserving metadata
(file path, function name, line range, language).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class CodeChunk:
    """A single chunk of source code with metadata."""
    text: str
    file_path: str
    function_name: Optional[str] = None
    line_start: int = 1
    line_end: int = 1
    language: str = "c"
    case_id: Optional[str] = None

    @property
    def metadata(self) -> dict:
        return {
            "file_path": self.file_path,
            "function_name": self.function_name or "",
            "line_start": self.line_start,
            "line_end": self.line_end,
            "language": self.language,
            "case_id": self.case_id or "",
            "doc_type": "code",
        }


# ── Regex patterns for function detection ────────────────────────────
# Matches common C/C++ function definitions (not declarations).
_FUNC_DEF_RE = re.compile(
    r"^(?:(?:static|inline|extern|void|int|uint8_t|uint16_t|uint32_t|"
    r"int8_t|int16_t|int32_t|float|double|char|unsigned|signed|long|"
    r"short|bool|Std_ReturnType|StatusType|size_t|ssize_t|"
    r"[A-Z][A-Za-z0-9_]*_t)\s+)*"
    r"(\*?\s*[A-Za-z_]\w*)\s*\([^)]*\)\s*\{",
    re.MULTILINE,
)


def _detect_language(file_path: str) -> str:
    """Detect language from file extension."""
    ext = Path(file_path).suffix.lower()
    if ext in (".cpp", ".cxx", ".cc", ".hpp", ".hxx"):
        return "cpp"
    return "c"


def _find_matching_brace(lines: List[str], start_line_idx: int) -> int:
    """Find the line index of the closing brace that matches the opening
    brace on or after *start_line_idx*. Returns the index of the line
    containing the matching '}'."""
    depth = 0
    for i in range(start_line_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
    return len(lines) - 1


def chunk_code_file(
    source_text: str,
    file_path: str,
    case_id: Optional[str] = None,
    max_chunk_lines: int = 80,
) -> List[CodeChunk]:
    """
    Split a C/C++ source file into function-level chunks.

    Falls back to fixed-size overlapping windows for sections outside of
    recognised function bodies (e.g. includes, globals, macros).

    Parameters
    ----------
    source_text : str
        The full text of the source file.
    file_path : str
        Path to the source file (used in metadata).
    case_id : str, optional
        Optional test-case identifier.
    max_chunk_lines : int
        Maximum lines per non-function chunk.

    Returns
    -------
    List[CodeChunk]
    """
    lang = _detect_language(file_path)
    lines = source_text.splitlines(keepends=True)
    chunks: List[CodeChunk] = []
    consumed: set = set()  # line indices already assigned to a chunk

    # ── Pass 1: extract function-level chunks ────────────────────────
    for match in _FUNC_DEF_RE.finditer(source_text):
        func_name = match.group(1).strip().lstrip("*").strip()
        # Find line number of match start
        char_offset = match.start()
        line_idx = source_text[:char_offset].count("\n")

        # Walk back to grab preceding comment/doc block
        doc_start = line_idx
        while doc_start > 0 and (
            lines[doc_start - 1].strip().startswith("//")
            or lines[doc_start - 1].strip().startswith("/*")
            or lines[doc_start - 1].strip().startswith("*")
            or lines[doc_start - 1].strip() == ""
        ):
            doc_start -= 1
            if lines[doc_start].strip().startswith("/*"):
                break

        # Find closing brace
        end_idx = _find_matching_brace(lines, line_idx)

        chunk_text = "".join(lines[doc_start: end_idx + 1])
        if chunk_text.strip():
            chunks.append(CodeChunk(
                text=chunk_text,
                file_path=file_path,
                function_name=func_name,
                line_start=doc_start + 1,   # 1-indexed
                line_end=end_idx + 1,
                language=lang,
                case_id=case_id,
            ))
            for i in range(doc_start, end_idx + 1):
                consumed.add(i)

    # ── Pass 2: remaining lines → fixed-size chunks ──────────────────
    remaining_lines: List[tuple] = []  # (line_idx, text)
    for i, line in enumerate(lines):
        if i not in consumed:
            remaining_lines.append((i, line))

    if remaining_lines:
        buf_lines: List[tuple] = []
        for item in remaining_lines:
            buf_lines.append(item)
            if len(buf_lines) >= max_chunk_lines:
                text = "".join(t for _, t in buf_lines)
                if text.strip():
                    chunks.append(CodeChunk(
                        text=text,
                        file_path=file_path,
                        function_name=None,
                        line_start=buf_lines[0][0] + 1,
                        line_end=buf_lines[-1][0] + 1,
                        language=lang,
                        case_id=case_id,
                    ))
                buf_lines = []
        if buf_lines:
            text = "".join(t for _, t in buf_lines)
            if text.strip():
                chunks.append(CodeChunk(
                    text=text,
                    file_path=file_path,
                    function_name=None,
                    line_start=buf_lines[0][0] + 1,
                    line_end=buf_lines[-1][0] + 1,
                    language=lang,
                    case_id=case_id,
                ))

    # Sort by line_start
    chunks.sort(key=lambda c: c.line_start)
    return chunks


def extract_line_range(source_text: str, start: int, end: int) -> str:
    """Extract a 1-indexed inclusive line range from source text."""
    lines = source_text.splitlines()
    start_idx = max(0, start - 1)
    end_idx = min(len(lines), end)
    return "\n".join(lines[start_idx:end_idx])
