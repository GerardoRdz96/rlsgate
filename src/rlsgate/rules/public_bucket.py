"""public-bucket — a Supabase Storage bucket created public.

A public bucket serves every object to anyone with the URL, no auth. Sometimes that
is intended (marketing images); often it is where private uploads (IDs, invoices,
avatars tied to a user) leak. We flag it for a human decision rather than assume.
"""
from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ._common import line_of

RULE_ID = "public-bucket"

# SQL: insert/update into storage.buckets with public = true (column order-independent).
_SQL_BUCKET = re.compile(r"storage\.buckets", re.I)
_PUBLIC_TRUE_SQL = re.compile(r"\btrue\b", re.I)
# JS/TS: createBucket('name', { public: true }) / updateBucket(..., { "public": true }).
# `public` must sit in object-key position (preceded by { , or whitespace) so we do not
# match inside `notpublic: true`; the span is bounded to the call (no ';') to stay local.
_JS_BUCKET = re.compile(
    r"(create|update)Bucket\s*\([^;]*?[\s{,][\"']?public[\"']?\s*:\s*true", re.I | re.S)


def _bucket_name(stmt_text: str) -> str:
    m = re.search(r"values?\s*\(\s*'([^']+)'", stmt_text, re.I)
    return m.group(1) if m else "?"


def check(ctx) -> List[Finding]:
    findings: List[Finding] = []
    for st in ctx.statements:
        text = st.normalized
        if not _SQL_BUCKET.search(text):
            continue
        low = text.lower()
        if not low.startswith(("insert", "update")):
            continue
        # Require an explicit public=true intent, not merely the word 'true' anywhere.
        if not (re.search(r"public[^,)]*true", low) or re.search(r"true[^,(]*public", low)
                or re.search(r"'public'\s*,\s*true", low)):
            # Fallback: column list names public and a true appears in values.
            if not (re.search(r"\bpublic\b", low) and _PUBLIC_TRUE_SQL.search(low)):
                continue
        findings.append(Finding(
            rule_id=RULE_ID,
            severity=Severity.HIGH,
            title=f"Public storage bucket created ({_bucket_name(text)})",
            detail=("A public bucket serves every object to anyone with the URL, with no "
                    "authentication — private uploads stored here are exposed."),
            fix=("Create the bucket private (public => false) and serve files through "
                 "signed URLs (createSignedUrl) or an authenticated route."),
            file=st.file, line=st.line,
            snippet=text[:160],
            meta={"bucket": _bucket_name(text)},
        ))
    for rel, src in ctx.project.source_files:
        for m in _JS_BUCKET.finditer(src):
            findings.append(Finding(
                rule_id=RULE_ID,
                severity=Severity.HIGH,
                title="Public storage bucket created in code (public: true)",
                detail=("A public bucket serves every object to anyone with the URL, with no "
                        "authentication — private uploads stored here are exposed."),
                fix="Set public: false and use createSignedUrl for time-limited access.",
                file=rel, line=line_of(src, m.start()),
                snippet=m.group(0)[:160],
            ))
    return findings
