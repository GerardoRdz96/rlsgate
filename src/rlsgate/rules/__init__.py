"""The frozen v1 rule registry. Six high-signal, high-precision checks — no more.

Adding a rule is a deliberate act (new fixtures, new tests, Codex review). The gate's
trust depends on staying precise, not on breadth.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List

from ..findings import Finding
from . import (
    anon_access, exposed_secrets, public_bucket, rls_authenticated,
    rls_disabled, unverified_webhook,
)


@dataclass(frozen=True)
class Rule:
    id: str
    summary: str
    check: Callable[["object"], List[Finding]]


ALL_RULES: List[Rule] = [
    Rule(rls_authenticated.RULE_ID, "RLS policy authorizes any authenticated user (CVE-2025-48757)", rls_authenticated.check),
    Rule(rls_disabled.RULE_ID, "User/PII table with Row Level Security never enabled", rls_disabled.check),
    Rule(anon_access.RULE_ID, "Data reachable by the unauthenticated anon role", anon_access.check),
    Rule(public_bucket.RULE_ID, "Public Supabase storage bucket", public_bucket.check),
    Rule(exposed_secrets.RULE_ID, "Secret committed or shipped to the browser", exposed_secrets.check),
    Rule(unverified_webhook.RULE_ID, "Webhook endpoint without signature verification", unverified_webhook.check),
]
