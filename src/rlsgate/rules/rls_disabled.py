"""rls-disabled — a user/PII table created without Row Level Security enabled.

In Supabase, a table in a client-reachable schema with RLS *off* is wide open to the
anon/authenticated API roles: any caller with the public anon key can read every row.
Policies without ``ENABLE ROW LEVEL SECURITY`` are dead weight — the gate is the flag.
"""
from __future__ import annotations

from typing import List

from ..findings import Finding, Severity
from ._common import MANAGED_SCHEMAS, classify_table

RULE_ID = "rls-disabled"


def check(ctx) -> List[Finding]:
    findings: List[Finding] = []
    enabled = ctx.model.rls_enabled
    for t in ctx.model.tables:
        if t.schema in MANAGED_SCHEMAS:
            continue
        if t.qname in enabled:
            continue
        kind = classify_table(t.name, t.columns)
        if not kind:
            continue  # no PII / no per-user ownership signal — out of v1 scope
        severity = Severity.CRITICAL if kind == "sensitive" else Severity.HIGH
        what = "personal data" if kind == "sensitive" else "user-linked rows"
        findings.append(Finding(
            rule_id=RULE_ID,
            severity=severity,
            title=f"Table {t.qname} holds {what} but Row Level Security is never enabled",
            detail=("With RLS off in a client-reachable schema, anyone holding the public anon "
                    "key can read every row over the auto-generated API."),
            fix=(f"ALTER TABLE {t.qname} ENABLE ROW LEVEL SECURITY; then add an ownership "
                 f"policy, e.g. USING (auth.uid() = user_id)."),
            file=t.file, line=t.line,
            snippet=f"create table {t.qname} (...)  -- no ENABLE ROW LEVEL SECURITY found",
            meta={"table": t.qname, "kind": kind},
        ))
    return findings
