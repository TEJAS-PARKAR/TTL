"""
SecureCodeGuard – Log & Static-Analysis Parsers
Parse compiler logs, build warnings, and static-analysis JSON into chunks.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


# ════════════════════════════════════════════════════════════════════════
# Compiler / Build Log Parser
# ════════════════════════════════════════════════════════════════════════

@dataclass
class LogEntry:
    """A single parsed compiler/linker warning or error."""
    file: str
    line: Optional[int]
    column: Optional[int]
    level: str          # warning | error | note
    message: str
    code: str           # e.g. -Wunused-variable
    raw: str

    @property
    def metadata(self) -> dict:
        return {
            "file_path": self.file,
            "line": self.line or 0,
            "level": self.level,
            "code": self.code,
            "doc_type": "logs",
            "log_type": "compiler",
        }


# GCC/Clang style:  file.c:10:5: warning: ... [-Wfoo]
_GCC_RE = re.compile(
    r"^(?P<file>[^\s:]+):(?P<line>\d+):(?:(?P<col>\d+):)?\s*"
    r"(?P<level>warning|error|note):\s*(?P<msg>.+?)(?:\s*\[(?P<code>-W[^\]]+)\])?\s*$"
)


def parse_compiler_log(log_text: str) -> List[LogEntry]:
    """Parse a GCC/Clang-style compiler log into structured entries."""
    entries: List[LogEntry] = []
    for raw_line in log_text.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        m = _GCC_RE.match(raw_line)
        if m:
            entries.append(LogEntry(
                file=m.group("file"),
                line=int(m.group("line")) if m.group("line") else None,
                column=int(m.group("col")) if m.group("col") else None,
                level=m.group("level"),
                message=m.group("msg"),
                code=m.group("code") or "",
                raw=raw_line,
            ))
        elif "warning" in raw_line.lower() or "error" in raw_line.lower():
            # Fallback: generic entry
            entries.append(LogEntry(
                file="unknown",
                line=None,
                column=None,
                level="warning" if "warning" in raw_line.lower() else "error",
                message=raw_line,
                code="",
                raw=raw_line,
            ))
    return entries


# ════════════════════════════════════════════════════════════════════════
# Static-Analysis JSON Parser
# ════════════════════════════════════════════════════════════════════════

@dataclass
class StaticFinding:
    """A single finding from a static-analysis tool."""
    tool: str
    rule_id: str
    file: str
    line: Optional[int]
    severity: str
    message: str
    extra: Dict[str, Any]

    @property
    def metadata(self) -> dict:
        return {
            "tool_name": self.tool,
            "file_path": self.file,
            "rule_id": self.rule_id,
            "line": self.line or 0,
            "severity": self.severity,
            "doc_type": "static_analysis",
        }

    @property
    def text(self) -> str:
        return (
            f"[{self.tool}] {self.rule_id} | {self.severity} | "
            f"{self.file}:{self.line or '?'} – {self.message}"
        )


def parse_static_analysis_json(json_text: str) -> List[StaticFinding]:
    """Parse a JSON array of static-analysis findings.

    Expected shape per element::

        {
          "tool": "...",
          "rule_id": "...",
          "file": "...",
          "line": 42,
          "severity": "HIGH",
          "message": "..."
        }
    """
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return []

    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    if not isinstance(data, list):
        return []

    results: List[StaticFinding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        results.append(StaticFinding(
            tool=item.get("tool", "unknown"),
            rule_id=item.get("rule_id", ""),
            file=item.get("file", "unknown"),
            line=item.get("line"),
            severity=item.get("severity", "MEDIUM"),
            message=item.get("message", ""),
            extra={k: v for k, v in item.items()
                   if k not in ("tool", "rule_id", "file", "line",
                                "severity", "message")},
        ))
    return results


# ════════════════════════════════════════════════════════════════════════
# Guideline / Rule Parser
# ════════════════════════════════════════════════════════════════════════

@dataclass
class GuidelineRule:
    """A synthetic secure-coding / MISRA-oriented rule summary."""
    rule_id: str
    title: str
    summary: str
    applicability: str
    safe_practice: str
    category: str

    @property
    def metadata(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "applicability": self.applicability,
            "category": self.category,
            "doc_type": "guidelines",
        }

    @property
    def text(self) -> str:
        return (
            f"Rule {self.rule_id}: {self.title}\n"
            f"Summary: {self.summary}\n"
            f"Applicability: {self.applicability}\n"
            f"Safe Practice: {self.safe_practice}\n"
        )


def parse_guidelines_json(json_text: str) -> List[GuidelineRule]:
    """Parse a JSON array of guideline rules."""
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return []

    if isinstance(data, dict) and "rules" in data:
        data = data["rules"]
    if not isinstance(data, list):
        return []

    rules: List[GuidelineRule] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rules.append(GuidelineRule(
            rule_id=item.get("rule_id", "RULE-???"),
            title=item.get("title", ""),
            summary=item.get("summary", ""),
            applicability=item.get("applicability", ""),
            safe_practice=item.get("safe_practice", ""),
            category=item.get("category", "general"),
        ))
    return rules
