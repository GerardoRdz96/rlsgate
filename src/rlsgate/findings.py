"""Core data model: severities and findings.

A Finding is the atomic unit rlsgate emits. Detection is deterministic; the only
non-deterministic part of the pipeline (the AI-drafted fix) lives elsewhere and is
always clearly labeled and never auto-applied.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any


class Severity(enum.IntEnum):
    """Ordered so a single ``--fail-on`` threshold is a simple comparison.

    Higher = worse. CRITICAL is reserved for "a stranger can read or write data
    they should never touch" — the class of hole that leaked the Lovable apps.
    """

    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:  # pragma: no cover - guarded by argparse choices
            raise ValueError(f"unknown severity: {name!r}")

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Finding:
    """One concrete security hole at one location.

    ``rule_id``  stable id of the rule that fired (e.g. ``rls-authenticated``).
    ``detail``   one sentence: *why this leaks*, in plain language.
    ``fix``      a deterministic remediation hint (the source of truth). An AI-drafted
                 fix may be attached later as ``ai_fix`` — advisory, never canonical.
    """

    rule_id: str
    severity: Severity
    title: str
    detail: str
    fix: str
    file: str
    line: int = 0
    snippet: str = ""
    ai_fix: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d

    # Stable identity for dedup + deterministic ordering across runs.
    def key(self) -> tuple:
        return (self.rule_id, self.file, self.line, self.title)
