"""Git awareness for the env scanner — distinguish a *committed* secret (a real leak)
from a gitignored ``.env.local`` (correct hygiene, not a finding).

All calls are read-only git invocations. If git is missing or the path is not in a
repo, we fall back to ``no-git`` and let the caller flag conservatively. Never raises.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List


def _git(root: Path, args: List[str], stdin: str = None):
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            input=stdin, capture_output=True, text=True, timeout=15,
        )
    except Exception:  # noqa: BLE001 - git absent / timeout / etc
        return None


def env_status(root: Path, relpaths: List[str]) -> Dict[str, str]:
    """Map each relative path to 'tracked' | 'ignored' | 'untracked' | 'no-git'."""
    if not relpaths:
        return {}
    inside = _git(root, ["rev-parse", "--is-inside-work-tree"])
    if inside is None or inside.returncode != 0 or inside.stdout.strip() != "true":
        return {r: "no-git" for r in relpaths}

    tracked = set()
    ls = _git(root, ["ls-files", "-z", "--", *relpaths])
    if ls is not None and ls.returncode == 0:
        tracked = {p for p in ls.stdout.split("\0") if p}

    ignored = set()
    ci = _git(root, ["check-ignore", "--stdin"], stdin="\n".join(relpaths))
    if ci is not None:
        ignored = {p.strip() for p in ci.stdout.splitlines() if p.strip()}

    out = {}
    for r in relpaths:
        if r in tracked:
            out[r] = "tracked"
        elif r in ignored:
            out[r] = "ignored"
        else:
            out[r] = "untracked"
    return out
