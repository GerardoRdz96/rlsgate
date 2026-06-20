"""rls-authenticated — the CVE-2025-48757 class.

An RLS policy that authorizes by *mere authentication* (any logged-in user) instead
of by per-row ownership. With this, every authenticated user can read (or write)
everyone else's rows — the exact hole that leaked 170+ Lovable apps' data.

Covers every common shape of the "is this caller logged in?" check: the literal
``auth.role() = 'authenticated'``, the JWT-claim form ``auth.jwt() ->> 'role' =
'authenticated'``, the ``current_setting(... role ...) = 'authenticated'`` form,
``auth.uid() IS NOT NULL``, and a bare ``USING/WITH CHECK (true)`` scoped to the
authenticated role — on reads (USING) and writes (WITH CHECK) alike.
"""
from __future__ import annotations

from typing import List

from ..findings import Finding, Severity
from ._common import classify_table, has_ownership, norm_expr

RULE_ID = "rls-authenticated"


def _role_bypass(expr: str) -> bool:
    """True if the predicate authorizes on the caller's ROLE being 'authenticated',
    in any of the forms vibe-coded apps use."""
    e = norm_expr(expr)
    if not e or not ("='authenticated'" in e or "'authenticated'=" in e or "in('authenticated'" in e):
        return False
    if "auth.role()" in e:
        return True
    if "auth.jwt()->>'role'" in e:
        return True
    if "current_setting" in e and "role" in e:
        return True
    return False


def _uid_not_null(expr: str) -> bool:
    e = norm_expr(expr)
    return e in ("auth.uid()isnotnull", "(auth.uid()isnotnull)", "auth.uid()<>null")


def check(ctx) -> List[Finding]:
    findings: List[Finding] = []
    for p in ctx.model.policies:
        # The predicate(s) that actually govern this operation.
        exprs = []
        if p.command in ("all", "select", "update", "delete"):
            exprs.append(p.using)
        if p.command in ("all", "insert", "update"):
            exprs.append(p.with_check)
        roles = [r.lower() for r in p.roles]
        scoped_authenticated = "authenticated" in roles and "anon" not in roles and "public" not in roles
        # 'true' to the authenticated role = every logged-in user (reads or writes).
        true_perm = any(norm_expr(e) == "true" for e in exprs) and scoped_authenticated
        role_bypass = any(_role_bypass(e) for e in exprs)
        uid_notnull = any(_uid_not_null(e) for e in exprs)
        if not (role_bypass or uid_notnull or true_perm):
            continue
        # A real per-row owner check alongside makes it safe (authenticated AND owner).
        if any(has_ownership(e) for e in exprs):
            continue
        t = ctx.model.table(p.table)
        if not (classify_table(t.name, t.columns) if t else ""):
            continue  # catalog/reference table — broad read by authenticated users is fine
        gov = next((e for e in exprs if e), "")
        findings.append(Finding(
            rule_id=RULE_ID,
            severity=Severity.CRITICAL,
            title=f"RLS policy '{p.name}' grants every authenticated user access to {p.table}",
            detail=("The policy authorizes any logged-in user instead of binding rows to "
                    "their owner, so any authenticated account can read or modify all rows."),
            fix=("Bind the policy to the row owner, e.g. "
                 "USING (auth.uid() = user_id) (and WITH CHECK on writes). "
                 "Never authorize on the caller's role being 'authenticated' alone."),
            file=p.file, line=p.line,
            snippet=f"create policy {p.name} on {p.table} ... ({gov})",
            meta={"table": p.table, "policy": p.name, "command": p.command},
        ))
    return findings
