"""A small structured model of the SQL that matters, parsed once and shared by rules.

Regex-driven, not a full grammar. It recognizes exactly the statement shapes the
detectors reason about and normalizes table names so ``public.users``, ``users`` and
``"users"`` compare equal. Anything it cannot confidently parse it simply ignores —
a missed parse becomes a non-finding, never a crash.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Set, Tuple

from .sql import Statement


@dataclass
class TableInfo:
    qname: str            # normalized schema.table (lowercased, unquoted)
    schema: str
    name: str
    columns: List[str]
    line: int
    file: str


@dataclass
class PolicyInfo:
    name: str
    table: str            # normalized qname
    command: str          # all | select | insert | update | delete
    roles: List[str]      # lowercased; empty list means the SQL default (public)
    using: str            # lowercased USING expression text, '' if none
    with_check: str
    line: int
    file: str


@dataclass
class GrantInfo:
    privileges: List[str]
    table: str            # normalized qname
    roles: List[str]
    line: int
    file: str


@dataclass
class SqlModel:
    tables: List[TableInfo] = field(default_factory=list)
    rls_enabled: Set[str] = field(default_factory=set)
    policies: List[PolicyInfo] = field(default_factory=list)
    grants: List[GrantInfo] = field(default_factory=list)

    def table(self, qname: str):
        for t in self.tables:
            if t.qname == qname:
                return t
        return None


_IDENT = r'(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)'
_QUALIFIED = rf'(?:{_IDENT}\s*\.\s*)?{_IDENT}'


def normalize_qname(raw: str) -> str:
    raw = raw.strip()
    parts = [p.strip().strip('"').lower() for p in _split_qualified(raw)]
    if len(parts) == 1:
        return f"public.{parts[0]}"
    return ".".join(parts[-2:])


def _split_qualified(raw: str) -> List[str]:
    # split on dots that are not inside quotes
    out, cur, inq = [], "", False
    for ch in raw:
        if ch == '"':
            inq = not inq
            cur += ch
        elif ch == "." and not inq:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def _balanced(s: str, open_idx: int) -> Tuple[str, int]:
    depth = 0
    for j in range(open_idx, len(s)):
        if s[j] == "(":
            depth += 1
        elif s[j] == ")":
            depth -= 1
            if depth == 0:
                return s[open_idx + 1:j], j
    return s[open_idx + 1:], len(s)


def _split_top_commas(s: str) -> List[str]:
    out, cur, depth = [], "", 0
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


_NON_COLUMN_LEADERS = {
    "constraint", "primary", "foreign", "unique", "check", "exclude", "like", "key",
}

_RE_CREATE_TABLE = re.compile(
    rf"^\s*create\s+table\s+(?:if\s+not\s+exists\s+)?({_QUALIFIED})\s*\(", re.I | re.S)
_RE_ENABLE_RLS = re.compile(
    rf"^\s*alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?({_QUALIFIED})\s+enable\s+row\s+level\s+security", re.I)
_RE_CREATE_POLICY = re.compile(
    rf"^\s*create\s+policy\s+({_IDENT})\s+on\s+(?:table\s+)?({_QUALIFIED})", re.I)
_RE_GRANT = re.compile(
    rf"^\s*grant\s+(.+?)\s+on\s+(?:table\s+)?({_QUALIFIED})\s+to\s+(.+)$", re.I | re.S)


def build_model(statements: List[Statement]) -> SqlModel:
    model = SqlModel()
    for st in statements:
        text = st.normalized
        low = text.lower()
        if low.startswith("create table"):
            _parse_table(st, text, model)
        elif low.startswith("alter table"):
            m = _RE_ENABLE_RLS.match(text)
            if m:
                model.rls_enabled.add(normalize_qname(m.group(1)))
        elif low.startswith("create policy"):
            _parse_policy(st, text, model)
        elif low.startswith("grant"):
            _parse_grant(st, text, model)
    return model


def _parse_table(st: Statement, text: str, model: SqlModel) -> None:
    m = _RE_CREATE_TABLE.match(text)
    if not m:
        return
    qname = normalize_qname(m.group(1))
    schema, name = qname.split(".", 1)
    open_idx = text.index("(", m.end() - 1)
    body, _ = _balanced(text, open_idx)
    columns = []
    for chunk in _split_top_commas(body):
        toks = chunk.strip().split()
        if not toks:
            continue
        lead = toks[0].strip('"').lower()
        if lead in _NON_COLUMN_LEADERS:
            continue
        columns.append(toks[0].strip('"').lower())
    model.tables.append(TableInfo(qname=qname, schema=schema, name=name,
                                  columns=columns, line=st.line, file=st.file))


def _parse_policy(st: Statement, text: str, model: SqlModel) -> None:
    m = _RE_CREATE_POLICY.match(text)
    if not m:
        return
    low = text.lower()
    command = "all"
    cmd_m = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", low)
    if cmd_m:
        command = cmd_m.group(1)
    roles: List[str] = []
    to_m = re.search(r"\bto\s+(.+?)(?:\busing\b|\bwith\s+check\b|$)", low)
    if to_m:
        roles = [r.strip().strip('"') for r in to_m.group(1).split(",") if r.strip()]
    using = _extract_clause(low, r"\busing\b")
    with_check = _extract_clause(low, r"\bwith\s+check\b")
    model.policies.append(PolicyInfo(
        name=m.group(1).strip('"'), table=normalize_qname(m.group(2)), command=command,
        roles=roles, using=using, with_check=with_check, line=st.line, file=st.file))


def _extract_clause(low: str, keyword_re: str) -> str:
    m = re.search(keyword_re + r"\s*\(", low)
    if not m:
        return ""
    expr, _ = _balanced(low, m.end() - 1)
    return expr.strip()


def _parse_grant(st: Statement, text: str, model: SqlModel) -> None:
    m = _RE_GRANT.match(text)
    if not m:
        return
    privs = [p.strip().lower() for p in m.group(1).split(",") if p.strip()]
    roles = [r.strip().strip('"').lower() for r in m.group(3).split(",") if r.strip()]
    model.grants.append(GrantInfo(privileges=privs, table=normalize_qname(m.group(2)),
                                  roles=roles, line=st.line, file=st.file))
