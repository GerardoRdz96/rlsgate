"""Find the files rlsgate cares about inside a project tree.

Static-only by design: rlsgate never connects to a database. Everything it knows
comes from migrations, env files, and the source bundle already in the repo.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

# Directories that are never the user's own code — skip for speed and to avoid
# scanning dependencies' env samples / fixtures and raising noise.
IGNORE_DIRS = {
    ".git", "node_modules", ".next", "dist", "build", "out", ".turbo",
    ".vercel", ".venv", "venv", "__pycache__", ".pytest_cache", "coverage",
    ".svelte-kit", ".nuxt", ".output", "vendor", ".cache",
}

SOURCE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".astro", ".mjs", ".cjs"}

# Real secret-bearing env files — explicitly NOT the committed-on-purpose samples.
_ENV_SAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist")


@dataclass
class Project:
    root: Path
    sql_files: List[Tuple[str, str]] = field(default_factory=list)      # (relpath, text)
    env_files: List[Tuple[str, str]] = field(default_factory=list)
    source_files: List[Tuple[str, str]] = field(default_factory=list)
    webhook_files: List[Tuple[str, str]] = field(default_factory=list)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return ""


def is_env_file(name: str) -> bool:
    if not name.startswith(".env"):
        return False
    lower = name.lower()
    return not any(lower.endswith(suf) or f"{suf}." in lower for suf in _ENV_SAMPLE_SUFFIXES)


def is_webhook_file(relpath: str) -> bool:
    p = relpath.lower()
    if not any(p.endswith(e) for e in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        return False
    return "webhook" in p or "/hooks/" in p


def discover(root: os.PathLike) -> Project:
    root = Path(root).resolve()
    proj = Project(root=root)
    if root.is_file():
        # Allow pointing rlsgate at a single file (mostly for tests).
        rel = root.name
        text = _read(root)
        _classify(proj, rel, root, text)
        return proj

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]
        for fn in filenames:
            full = Path(dirpath) / fn
            rel = str(full.relative_to(root))
            text = _read(full)
            _classify(proj, rel, full, text)
    # Deterministic order so output is stable run to run.
    for bucket in (proj.sql_files, proj.env_files, proj.source_files, proj.webhook_files):
        bucket.sort(key=lambda t: t[0])
    return proj


def _classify(proj: Project, rel: str, full: Path, text: str) -> None:
    name = full.name
    suffix = full.suffix.lower()
    if suffix == ".sql":
        proj.sql_files.append((rel, text))
    if is_env_file(name):
        proj.env_files.append((rel, text))
    if suffix in SOURCE_EXTS:
        proj.source_files.append((rel, text))
        if is_webhook_file(rel):
            proj.webhook_files.append((rel, text))
