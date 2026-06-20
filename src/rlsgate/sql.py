"""Lightweight, dependency-free SQL splitting for Postgres/Supabase migrations.

We are NOT building a full SQL parser. We need just enough structure to find the
handful of statements that matter (CREATE TABLE / CREATE POLICY / ALTER TABLE ...
ENABLE RLS / GRANT / storage.buckets inserts) and to know which line each lives on,
without being fooled by ``;`` inside comments, string literals, or dollar-quoted
function bodies. Getting THAT right is what keeps the detectors precise.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


@dataclass
class Statement:
    text: str          # raw statement text (without the trailing ;)
    line: int          # 1-based line where the statement begins
    file: str = ""     # filled in by the scanner

    @property
    def normalized(self) -> str:
        """Whitespace-collapsed, comment-free text for regex matching."""
        return _strip_comments(self.text)


def split_statements(sql: str) -> List[Statement]:
    """Split a SQL string into top-level statements with start line numbers.

    Walks character by character so that ``;`` inside ``-- line comments``,
    ``/* block comments */``, ``'string literals'`` (with ``''`` escaping), and
    ``$tag$ dollar-quoted $tag$`` bodies never ends a statement.
    """
    statements: List[Statement] = []
    i, n = 0, len(sql)
    line = 1
    start_idx = 0
    start_line = 1

    def flush(end_idx: int):
        chunk = sql[start_idx:end_idx]
        if chunk.strip():
            statements.append(Statement(text=chunk.strip(), line=_first_content_line(sql, start_idx, start_line)))

    while i < n:
        ch = sql[i]
        # line comment ----------------------------------------------------------
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            while i < n and sql[i] != "\n":
                i += 1
            continue
        # block comment ---------------------------------------------------------
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            i += 2
            while i + 1 < n and not (sql[i] == "*" and sql[i + 1] == "/"):
                if sql[i] == "\n":
                    line += 1
                i += 1
            i += 2
            continue
        # single-quoted string --------------------------------------------------
        if ch == "'":
            i += 1
            while i < n:
                if sql[i] == "'" and i + 1 < n and sql[i + 1] == "'":
                    i += 2
                    continue
                if sql[i] == "'":
                    i += 1
                    break
                if sql[i] == "\n":
                    line += 1
                i += 1
            continue
        # dollar-quoted string $tag$ ... $tag$ ----------------------------------
        if ch == "$":
            m = re.match(r"\$[A-Za-z0-9_]*\$", sql[i:])
            if m:
                tag = m.group(0)
                i += len(tag)
                end = sql.find(tag, i)
                if end == -1:
                    end = n
                line += sql.count("\n", i, end)
                i = end + len(tag)
                continue
        # statement terminator --------------------------------------------------
        if ch == ";":
            flush(i)
            i += 1
            start_idx = i
            start_line = line
            continue
        if ch == "\n":
            line += 1
        i += 1

    flush(n)
    return statements


def _first_content_line(sql: str, start_idx: int, start_line: int) -> int:
    """Advance past leading whitespace AND comments so the reported line points at the
    first real SQL token of the statement, not a blank line or a leading comment."""
    j = start_idx
    line = start_line
    n = len(sql)
    while j < n:
        ch = sql[j]
        if ch in " \t\r\n":
            if ch == "\n":
                line += 1
            j += 1
        elif ch == "-" and j + 1 < n and sql[j + 1] == "-":
            while j < n and sql[j] != "\n":
                j += 1
        elif ch == "/" and j + 1 < n and sql[j + 1] == "*":
            j += 2
            while j + 1 < n and not (sql[j] == "*" and sql[j + 1] == "/"):
                if sql[j] == "\n":
                    line += 1
                j += 1
            j += 2
        else:
            break
    return line


_LINE_COMMENT = re.compile(r"--[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _strip_comments(text: str) -> str:
    text = _BLOCK_COMMENT.sub(" ", text)
    text = _LINE_COMMENT.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


def offset_to_line(text: str, match_start: int, base_line: int) -> int:
    """Map a regex match offset within a statement back to a file line number."""
    return base_line + text.count("\n", 0, match_start)
