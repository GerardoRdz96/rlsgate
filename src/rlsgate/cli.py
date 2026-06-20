"""rlsgate command-line interface.

    rlsgate scan [PATH] [--json] [--fail-on LEVEL] [--ai] [--no-color]
    rlsgate rules
    rlsgate version

Exit codes:  0 = clean (or only findings below --fail-on);  1 = blocking findings
at or above --fail-on;  2 = usage / path error. The non-zero exit is what makes it a
gate in CI / a pre-deploy hook.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .findings import Severity
from .report import render_json, render_text
from .rules import ALL_RULES
from .scanner import scan

_LEVELS = ["critical", "high", "medium", "low"]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rlsgate",
        description="The pre-deploy gate for vibe-coded apps — catch the Supabase/RLS leak before your users do.",
    )
    p.add_argument("--version", action="version", version=f"rlsgate {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a project for security holes")
    s.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    s.add_argument("--json", action="store_true", help="machine-readable JSON output")
    s.add_argument("--fail-on", choices=_LEVELS, default="high",
                   help="minimum severity that fails the gate (default: high)")
    s.add_argument("--ai", action="store_true", help="add AI-drafted fix snippets (needs ANTHROPIC_API_KEY)")
    s.add_argument("--no-color", action="store_true", help="disable ANSI color")

    sub.add_parser("rules", help="list the checks rlsgate runs")
    sub.add_parser("version", help="print version")
    return p


def _use_color(args) -> bool:
    if getattr(args, "no_color", False):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _cmd_scan(args) -> int:
    root = Path(args.path)
    if not root.exists():
        print(f"rlsgate: path not found: {args.path}", file=sys.stderr)
        return 2
    result = scan(root)
    if args.ai:
        from .context import build_context
        from .fix import enhance
        # rebuild context once for the fixer (cheap; keeps scan() pure)
        _, note = enhance(result.findings, build_context(root))
        if not args.json:
            print(f"# {note}", file=sys.stderr)
    if args.json:
        print(render_json(result))
    else:
        print(render_text(result, color=_use_color(args), show_ai=args.ai))
    threshold = Severity.parse(args.fail_on)
    blocking = result.at_or_above(threshold)
    if result.errors and not args.json:
        print(f"rlsgate: {len(result.errors)} rule error(s) — failing the gate (cannot "
              f"certify clean): {'; '.join(result.errors)}", file=sys.stderr)
    # A rule that crashed might have hidden a real hole — never report a false 'all clear'.
    return 1 if (blocking or result.errors) else 0


def _cmd_rules() -> int:
    print("rlsgate v1 checks:\n")
    for r in ALL_RULES:
        print(f"  {r.id:<20} {r.summary}")
    print("\nStatic, high-precision checks only — not a substitute for a full security audit.")
    return 0


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        # bare `rlsgate` defaults to scanning the current directory
        args = parser.parse_args(["scan"])
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "rules":
        return _cmd_rules()
    if args.command == "version":
        print(f"rlsgate {__version__}")
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
