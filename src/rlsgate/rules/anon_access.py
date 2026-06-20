"""anon-access — data reachable by the unauthenticated public (the anon role).

Two shapes: an RLS policy whose roles include ``anon`` (or the public default) with a
permissive predicate, and an explicit ``GRANT ... TO anon`` on a sensitive table that
has no RLS to gate it. Either lets a stranger with just the anon key read the data.
"""
from __future__ import annotations

from typing import List

from ..findings import Finding, Severity
from ._common import classify_table, has_ownership, norm_expr

RULE_ID = "anon-access"
_WRITE = {"insert", "update", "delete", "all"}


def _table_kind(ctx, qname: str) -> str:
    t = ctx.model.table(qname)
    # Unknown table -> '' (skip). High-precision: only flag tables we can confirm hold
    # user/PII data, never a table we failed to parse.
    return classify_table(t.name, t.columns) if t else ""


def _permissive_for_anon(expr: str) -> bool:
    e = norm_expr(expr)
    if e in ("", "true"):
        return True
    if "auth.role()='authenticated'" in e:
        return False  # authenticated-scoped — anon can't pass; owned by rls-authenticated
    return False  # any other predicate may legitimately filter; stay high-precision


def check(ctx) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for p in ctx.model.policies:
        roles = [r.lower() for r in p.roles]
        reaches_anon = ("anon" in roles) or (not roles) or ("public" in roles)
        if not reaches_anon:
            continue
        expr = p.with_check if p.command == "insert" else p.using
        if not _permissive_for_anon(expr) or has_ownership(expr):
            continue
        kind = _table_kind(ctx, p.table)
        if not kind:
            continue
        # Private PII reachable by anon is the leak class (CRITICAL). A public-ish
        # profile/owned table reachable by anon is often intended — flag it for review
        # (MEDIUM) rather than blocking every social/community deploy.
        severity = Severity.CRITICAL if kind == "sensitive" else Severity.MEDIUM
        verb = "modify" if p.command in _WRITE else "read"
        key = (p.table, p.line)
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            rule_id=RULE_ID,
            severity=severity,
            title=f"Policy '{p.name}' lets the anonymous public {verb} {p.table}",
            detail=("The policy applies to the anon (unauthenticated) role with a permissive "
                    "predicate, so anyone with the public anon key can reach this data."),
            fix=("Scope the policy to authenticated owners, e.g. TO authenticated "
                 "USING (auth.uid() = user_id); drop the anon grant unless the table is "
                 "truly public."),
            file=p.file, line=p.line,
            snippet=f"create policy {p.name} on {p.table} to {','.join(p.roles) or 'public'} using ({p.using})",
            meta={"table": p.table, "policy": p.name},
        ))
    # explicit grants to anon on sensitive tables that are not RLS-gated
    for g in ctx.model.grants:
        if "anon" not in g.roles:
            continue
        if g.table in ctx.model.rls_enabled:
            continue  # RLS present — the grant is the Supabase-standard pattern, gate is the policy
        kind = _table_kind(ctx, g.table)
        if not kind:
            continue
        key = (g.table, g.line)
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            rule_id=RULE_ID,
            severity=Severity.CRITICAL if kind == "sensitive" else Severity.MEDIUM,
            title=f"GRANT to anon on {g.table} with no Row Level Security to gate it",
            detail=("Privileges are granted to the anonymous role on a table that never "
                    "enables RLS, so the rows are reachable with only the public anon key."),
            fix=(f"Revoke from anon (REVOKE {','.join(g.privileges)} ON {g.table} FROM anon) "
                 f"or ENABLE ROW LEVEL SECURITY and add an ownership policy."),
            file=g.file, line=g.line,
            snippet=f"grant {','.join(g.privileges)} on {g.table} to {','.join(g.roles)}",
            meta={"table": g.table},
        ))
    return findings
