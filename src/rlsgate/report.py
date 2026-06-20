"""Render a ScanResult as a human report or JSON. Pure formatting, no I/O."""
from __future__ import annotations

import json
from typing import List

from .findings import Finding, Severity
from .scanner import ScanResult

_COLORS = {
    "CRITICAL": "\033[1;37;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;34m", "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
    "green": "\033[1;32m",
}
_ICON = {"CRITICAL": "✖", "HIGH": "▲", "MEDIUM": "●", "LOW": "○"}


def _c(s: str, key: str, color: bool) -> str:
    if not color:
        return s
    return f"{_COLORS.get(key, '')}{s}{_COLORS['reset']}"


def render_json(result: ScanResult) -> str:
    payload = {
        "tool": "rlsgate",
        "root": result.root,
        "summary": result.counts(),
        "files_scanned": result.files_scanned,
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_text(result: ScanResult, color: bool = True, show_ai: bool = False) -> str:
    lines: List[str] = []
    fs = result.files_scanned
    lines.append(_c("rlsgate", "bold", color) + _c(
        f"  ·  {fs.get('migrations',0)} migrations, {fs.get('env',0)} env, "
        f"{fs.get('source',0)} source files scanned", "dim", color))
    lines.append("")

    if not result.findings:
        lines.append(_c("  ✓ No high-signal security holes found.", "green", color))
        lines.append(_c("    (Static checks only — not a substitute for a full audit.)", "dim", color))
        lines.append("")
        if result.errors:
            lines.append(_c(f"  ! {len(result.errors)} rule error(s): " + "; ".join(result.errors), "MEDIUM", color))
        return "\n".join(lines)

    for f in result.findings:
        sev = f.severity.label
        head = f"{_ICON.get(sev,'•')} {sev:<8} {f.title}"
        lines.append(_c(head, sev, color))
        lines.append(_c(f"    where: {f.location}", "dim", color))
        if f.snippet:
            lines.append(_c(f"    code:  {f.snippet.strip()[:120]}", "dim", color))
        lines.append(f"    why:   {f.detail}")
        lines.append(_c(f"    fix:   {f.fix}", "green", color))
        if show_ai and f.ai_fix:
            lines.append(_c("    ai-suggested fix (review before applying):", "bold", color))
            for ln in f.ai_fix.strip().splitlines():
                lines.append(_c(f"      {ln}", "dim", color))
        lines.append("")

    counts = result.counts()
    summary = "  ".join(
        _c(f"{counts[s]} {s.lower()}", s, color)
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s])
    lines.append(_c("─" * 60, "dim", color))
    lines.append(f"  {summary}")
    if result.errors:
        lines.append(_c(f"  ! {len(result.errors)} rule error(s): " + "; ".join(result.errors), "MEDIUM", color))
    lines.append("")
    return "\n".join(lines)
