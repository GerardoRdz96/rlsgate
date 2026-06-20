"""unverified-webhook — a webhook endpoint that never checks the sender's signature.

A webhook handler that parses the body and acts on it without verifying the provider's
signature lets anyone POST forged events (fake a paid Stripe invoice, a fake auth
event). We only flag files that clearly receive external POSTs and show no sign of
verifying them — high precision over recall.
"""
from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity

RULE_ID = "unverified-webhook"

# An actual CALL to a verification routine means the handler verifies the sender. Each
# alternative requires a trailing `(` — a name in a comment or a variable does NOT
# suppress the finding. `.verify(` is intentionally omitted (too broad: response.verify(),
# ssl.verify()); svix verification is recognized by its `new Webhook(` construction.
_VERIFY = re.compile(
    r"\bconstructEvent(Async)?\s*\(|\bcreateHmac\s*\(|\btimingSafeEqual\s*\(|"
    r"new\s+Webhook\s*\(|\bverifyHeader\s*\(|\bvalidateSignature\s*\(|"
    r"\bverifySignature\s*\(|\bcheckSignature\s*\(",
    re.I)

# Signal that this file actually receives an external POST.
_HANDLER = re.compile(
    r"export\s+(async\s+)?function\s+POST|export\s+const\s+POST\s*=|"
    r"\.post\s*\(|module\.exports|req\.body|request\.json\s*\(|await\s+req\.|"
    r"export\s+default\s+(async\s+)?function",
    re.I)
_EXTERNAL = re.compile(r"webhook|stripe|svix|clerk|paddle|lemonsqueezy|resend|github|"
                       r"twilio|sendgrid", re.I)


def check(ctx) -> List[Finding]:
    findings: List[Finding] = []
    for rel, src in ctx.project.webhook_files:
        if not _HANDLER.search(src):
            continue
        if not _EXTERNAL.search(src):
            continue
        if _VERIFY.search(src):
            continue
        findings.append(Finding(
            rule_id=RULE_ID,
            severity=Severity.HIGH,
            title=f"Webhook handler does not verify the request signature ({rel})",
            detail=("The endpoint parses and acts on the request body without verifying the "
                    "provider's signature, so anyone can POST forged events to it."),
            fix=("Verify the signature before trusting the body — e.g. Stripe "
                 "stripe.webhooks.constructEvent(rawBody, sig, STRIPE_WEBHOOK_SECRET), or the "
                 "provider's svix/HMAC check — and reject on mismatch."),
            file=rel, line=1,
            snippet=rel,
            meta={"file": rel},
        ))
    return findings
