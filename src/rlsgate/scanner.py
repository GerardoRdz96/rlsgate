"""Run every rule over a project and assemble a deterministic, deduped result."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .context import ScanContext, build_context
from .findings import Finding, Severity
from .rules import ALL_RULES


@dataclass
class ScanResult:
    root: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    files_scanned: Dict[str, int] = field(default_factory=dict)

    def counts(self) -> Dict[str, int]:
        out = {s.label: 0 for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def at_or_above(self, threshold: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity >= threshold]


def scan(path, context: ScanContext = None) -> ScanResult:
    ctx = context or build_context(path)
    result = ScanResult(root=str(ctx.root))
    result.files_scanned = {
        "migrations": len(ctx.project.sql_files),
        "env": len(ctx.project.env_files),
        "source": len(ctx.project.source_files),
        "webhooks": len(ctx.project.webhook_files),
    }
    seen = set()
    for rule in ALL_RULES:
        try:
            for f in rule.check(ctx):
                k = f.key()
                if k in seen:
                    continue
                seen.add(k)
                result.findings.append(f)
        except Exception as e:  # noqa: BLE001 — one rule's crash must not hide the rest
            result.errors.append(f"{rule.id}: {type(e).__name__}: {e}")
    # Stable, worst-first ordering: severity desc, then rule, file, line.
    result.findings.sort(key=lambda f: (-int(f.severity), f.rule_id, f.file, f.line))
    return result
