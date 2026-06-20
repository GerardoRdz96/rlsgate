"""exposed-secret — a real secret committed to the repo or shipped to the browser.

Two leaks: (1) a non-placeholder secret value sitting in a committed ``.env`` (not a
``.env.example``); (2) a secret that is client-public — a ``NEXT_PUBLIC_*`` /
``VITE_*`` variable that carries a service-role/secret, or a hardcoded service-role
JWT / ``sk-`` key / private key in the frontend source, all of which ship to the
browser bundle. The Supabase *anon* key is intentionally public and never flagged.
"""
from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ._common import (
    CLIENT_PREFIX, find_secret_token, is_placeholder, jwt_role, line_of,
    redact, secret_name,
)

RULE_ID = "exposed-secret"

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def _value(raw: str) -> str:
    v = raw.strip()
    if v and v[0] in "\"'" and v[-1:] == v[0]:
        return v[1:-1]
    # strip an inline comment on unquoted values
    return v.split(" #", 1)[0].strip()


def _scan_env(rel: str, text: str, status: str) -> List[Finding]:
    out: List[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _ENV_LINE.match(line)
        if not m:
            continue
        key, raw = m.group(1), m.group(2)
        val = _value(raw)
        if not val or is_placeholder(val):
            continue
        role = jwt_role(val)
        if role == "anon":
            continue  # the public anon key is safe to commit
        client_public = bool(CLIENT_PREFIX.match(key))
        is_secret = role == "service_role" or secret_name(key) or bool(
            re.search(r"\b(sk-[A-Za-z0-9]{16,}|sk_live_|-----BEGIN)", val))
        if not is_secret:
            continue
        if client_public:
            # gitignore does NOT protect these: NEXT_PUBLIC_/VITE_ vars are inlined into
            # the client bundle at build time, so a secret here always ships to the browser.
            sev = Severity.CRITICAL
            title = f"Client-public env var {key} carries a secret (ships to the browser)"
            detail = ("Variables with a NEXT_PUBLIC_/VITE_/PUBLIC_ prefix are inlined into the "
                      "client bundle — a service-role/secret here is readable by every visitor.")
            fix = (f"Rename {key} without the public prefix and use it only in server code "
                   f"(API route / server action); rotate the leaked key now.")
        else:
            # A gitignored secret file is correct hygiene — not a leak. Only flag a secret
            # that is committed (tracked), sitting unprotected (untracked), or where we
            # cannot tell because there is no git repo.
            if status == "ignored":
                continue
            if status == "tracked":
                sev = Severity.CRITICAL
                title = f"Secret committed to the repo in {rel}: {key}"
                detail = ("This secret value is tracked by git; anyone with repo access (or a "
                          "leaked clone) holds the key.")
                fix = (f"git rm --cached {rel}, add it to .gitignore, move the value to an "
                       f"untracked secret store, and ROTATE {key} (it must be considered leaked).")
            elif status == "untracked":
                sev = Severity.HIGH
                title = f"Secret in a non-gitignored file {rel}: {key}"
                detail = ("The file holds a real secret and is not gitignored — one `git add .` "
                          "away from being committed and leaked.")
                fix = f"Add {rel} to .gitignore now (before it is committed)."
            else:  # no-git
                sev = Severity.HIGH
                title = f"Secret in {rel}: {key}"
                detail = ("A real secret value is present in this env file. Confirm the file is "
                          "gitignored so it never reaches the repo.")
                fix = f"Ensure {rel} is gitignored and the value lives only in a secret store."
        out.append(Finding(
            rule_id=RULE_ID, severity=sev, title=title, detail=detail, fix=fix,
            file=rel, line=i, snippet=f"{key}={redact(val)}",
            meta={"key": key, "client_public": client_public, "jwt_role": role, "git": status},
        ))
    return out


def _scan_source(rel: str, src: str) -> List[Finding]:
    out: List[Finding] = []
    for kind, token, idx in find_secret_token(src):
        label = {
            "service-role-jwt": "Hardcoded Supabase service-role key in client source",
            "api-key": "Hardcoded API secret key in source",
            "private-key": "Hardcoded private key in source",
        }[kind]
        out.append(Finding(
            rule_id=RULE_ID, severity=Severity.CRITICAL, title=label,
            detail=("This secret is hardcoded in source that is bundled to the browser; every "
                    "visitor can read it from the shipped JavaScript."),
            fix="Remove the literal, load it from a server-only env var, and rotate it immediately.",
            file=rel, line=line_of(src, idx), snippet=redact(token),
            meta={"kind": kind},
        ))
    # client-public reference to a service-role/secret env var name in source
    for m in re.finditer(r"(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_)[A-Z0-9_]*"
                         r"(SERVICE_ROLE|SECRET|PRIVATE_KEY)[A-Z0-9_]*", src):
        out.append(Finding(
            rule_id=RULE_ID, severity=Severity.HIGH,
            title=f"Client-public reference to a secret env var: {m.group(0)}",
            detail=("A NEXT_PUBLIC_/VITE_ variable named like a service-role/secret is read in "
                    "client code and inlined into the browser bundle."),
            fix="Drop the public prefix and read the value only in server code; rotate the key.",
            file=rel, line=line_of(src, m.start()), snippet=m.group(0),
        ))
    return out


def check(ctx) -> List[Finding]:
    findings: List[Finding] = []
    for rel, text in ctx.project.env_files:
        findings.extend(_scan_env(rel, text, ctx.env_status.get(rel, "no-git")))
    for rel, src in ctx.project.source_files:
        findings.extend(_scan_source(rel, src))
    return findings
