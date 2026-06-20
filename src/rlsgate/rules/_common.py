"""Shared heuristics for the rules: PII detection, secret/JWT shapes, RLS expression
analysis. Kept deliberately conservative — rlsgate's v1 ruleset is high-precision by
design (a noisy gate gets disabled and never re-enabled)."""
from __future__ import annotations

import base64
import json
import re
from typing import Optional

# Supabase-managed schemas: the user does not own RLS on these, so don't flag them.
MANAGED_SCHEMAS = {
    "auth", "storage", "vault", "realtime", "extensions", "graphql",
    "graphql_public", "pgbouncer", "supabase_functions", "supabase_migrations",
    "net", "cron", "pgsodium", "pgsodium_masks", "information_schema", "pg_catalog",
}

# Column names that clearly carry personal / sensitive data. NOTE: bare `name` is
# deliberately excluded — catalogs (badges, products, categories) all have a `name`.
# Truly-private columns: anon access to one of these is the data-leak class.
_SENSITIVE_COL = re.compile(
    r"^(email|email_address|phone|phone_number|address|street|city|zip|"
    r"postal_code|ssn|social_security|dob|date_of_birth|birthdate|password|"
    r"password_hash|secret|access_token|refresh_token|credit_card|card_number|"
    r"iban|tax_id|rfc|curp|passport|national_id|ip_address|geolocation|"
    r"stripe_customer_id)$",
    re.I,
)
# Personal-identity columns: lower stakes, and often public on purpose (a member
# directory). Bare `name` is excluded — a catalog row also has a `name`.
_IDENTITY_COL = re.compile(r"^(full_name|first_name|last_name|display_name|username)$", re.I)
# Per-user ownership signal.
_OWNER_COL = re.compile(r"^(user_id|owner_id|account_id|profile_id|created_by|author_id|customer_id|tenant_id|org_id)$", re.I)
# Table names that denote a person / profile record (optionally project-prefixed).
_PROFILE_TABLE = re.compile(
    r"^(\w+_)?(users?|profiles?|accounts?|members?|subscribers?|patients?|"
    r"clients?|contacts?|leads?|people|employees?|customers?)$",
    re.I,
)


def classify_table(name: str, columns) -> str:
    """Classify a table's sensitivity (most → least):
      'sensitive' — private PII (email/phone/etc); anon access is a leak.
      'identity'  — a person/profile record (username/display_name); often public on purpose.
      'owned'     — per-user rows (user_id) with no obvious PII.
      ''          — reference/catalog data, not user-specific.
    """
    cols = [c.lower() for c in columns]
    if any(_SENSITIVE_COL.match(c) for c in cols):
        return "sensitive"
    if _PROFILE_TABLE.match(name) or any(_IDENTITY_COL.match(c) for c in cols):
        return "identity"
    if any(_OWNER_COL.match(c) for c in cols):
        return "owned"
    return ""


def norm_expr(expr: str) -> str:
    """Whitespace-free, lowercased policy expression for pattern matching."""
    return re.sub(r"\s+", "", (expr or "").lower())


def has_ownership(expr: str) -> bool:
    """True if the expression binds rows to the current user — i.e. a proper per-row
    predicate, not a blanket 'anyone authenticated' check.

    Deliberately narrow: only ``auth.uid()`` bindings and a JWT *sub/user* claim count.
    Bare ``auth.jwt()->>`` and ``current_setting`` are NOT ownership — they are how the
    role-based bypass (``auth.jwt()->>'role' = 'authenticated'``) disguises itself."""
    e = norm_expr(expr)
    if not e:
        return False
    # An owner-identity source only counts as ownership when it is COMPARED to a
    # column (equality / IN). A bare `auth.jwt()->>'sub' IS NOT NULL` is NOT ownership
    # — it is just "is anyone logged in", which must not suppress a role-bypass finding.
    sources = ("auth.uid()", "(selectauth.uid())", "auth.jwt()->>'sub'", "auth.jwt()->>'user_id'")
    for s in sources:
        if f"{s}=" in e or f"={s}" in e or f"{s}in(" in e:
            return True
    return False


# ---- secrets ---------------------------------------------------------------

_PLACEHOLDER = re.compile(
    r"(your[-_ ]?|my[-_ ]?|the[-_ ]?)?(key|token|secret|password|value)?[-_ ]?(here|goes|placeholder)|"
    r"x{4,}|<[^>]+>|\.\.\.|changeme|example|todo|dummy|test[-_]?key|fake|replace[-_ ]?me|^$",
    re.I,
)

# env var NAMES that should never hold a non-placeholder value in a committed file,
# or should never be prefixed as client-public.
_SECRET_NAME = re.compile(
    r"(service[_-]?role[_-]?key|service[_-]?key|.*_secret$|.*secret_key.*|"
    r"stripe_secret|.*_api_key$|.*private_key.*|.*_token$|jwt_secret|"
    r"db_password|database_url|.*_password$|access_key_id|secret_access_key|"
    r"openai_api_key|anthropic_api_key|sendgrid|resend_api_key|webhook_secret)",
    re.I,
)
# Prefixes that ship a variable into the client bundle.
CLIENT_PREFIX = re.compile(r"^(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|NUXT_PUBLIC_)", re.I)

_SK_KEY = re.compile(r"\b(sk-[A-Za-z0-9]{16,}|sk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,})\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")


def is_placeholder(value: str) -> bool:
    v = (value or "").strip().strip("\"'")
    if not v:
        return True
    return bool(_PLACEHOLDER.search(v))


def jwt_role(token: str) -> Optional[str]:
    """Decode a JWT's payload (no verification) and return its ``role`` claim, if any.
    Supabase's anon key carries role=anon (safe to expose); the service_role key
    carries role=service_role (must NEVER reach a client or a committed file)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = base64.urlsafe_b64decode(pad.encode())
        data = json.loads(payload)
        role = data.get("role")
        return role if isinstance(role, str) else None
    except Exception:  # noqa: BLE001 - malformed token is simply not a JWT we care about
        return None


def secret_name(name: str) -> bool:
    return bool(_SECRET_NAME.search(name or ""))


def find_secret_token(text: str):
    """Yield (kind, token, start_index) for hardcoded secret-shaped tokens in text."""
    for m in _SK_KEY.finditer(text):
        yield ("api-key", m.group(0), m.start())
    for m in _PRIVATE_KEY.finditer(text):
        yield ("private-key", m.group(0), m.start())
    for m in _JWT.finditer(text):
        role = jwt_role(m.group(0))
        if role == "service_role":
            yield ("service-role-jwt", m.group(0), m.start())


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def redact(token: str) -> str:
    if len(token) <= 12:
        return token[:3] + "…"
    return f"{token[:6]}…{token[-4:]}"
