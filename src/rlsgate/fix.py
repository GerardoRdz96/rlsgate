"""Optional AI-drafted fix snippets.

STRICT division of labor: detection is 100% deterministic; the AI only rewrites the
*explanation/fix* for a finding the deterministic rules already proved. The result is
attached as ``finding.ai_fix``, always shown labeled as AI-drafted and review-required,
and NEVER applied automatically. If the anthropic SDK or an API key is absent, the tool
works exactly the same minus this enhancement.
"""
from __future__ import annotations

import os
from typing import List, Tuple

from .findings import Finding

_MODEL = os.environ.get("VIBEGATE_MODEL", "claude-haiku-4-5-20251001")
_MAX = 12  # never fan out unboundedly


def available() -> bool:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def enhance(findings: List[Finding], ctx) -> Tuple[List[Finding], str]:
    """Best-effort. Returns (findings, note). Never raises into the caller."""
    if not available():
        return findings, "ai fixes skipped (set ANTHROPIC_API_KEY and `pip install rlsgate[ai]`)"
    try:
        import anthropic
    except Exception as e:  # noqa: BLE001
        return findings, f"ai fixes unavailable: {e}"
    client = anthropic.Anthropic()
    done = 0
    for f in findings:
        if done >= _MAX:
            break
        try:
            f.ai_fix = _draft(client, f)
            done += 1
        except Exception:  # noqa: BLE001 — a single failed draft is not fatal
            continue
    return findings, f"ai fixes drafted for {done} finding(s) — review before applying"


def _draft(client, f: Finding) -> str:
    prompt = (
        "You are a security remediation assistant. A deterministic scanner already PROVED "
        "this finding is real; do not second-guess it. Write a concise, correct fix the "
        "developer can apply. Output only the fix (code + one short sentence), no preamble.\n\n"
        f"Rule: {f.rule_id}\nIssue: {f.title}\nWhy it leaks: {f.detail}\n"
        f"Location: {f.location}\nOffending: {f.snippet}\nDeterministic fix hint: {f.fix}\n"
    )
    msg = client.messages.create(
        model=_MODEL, max_tokens=400,
        messages=[{"role": "user", "content": prompt}],
    )
    parts = [b.text for b in msg.content if getattr(b, "type", "") == "text"]
    return "\n".join(parts).strip()
