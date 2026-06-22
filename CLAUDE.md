# rlsgate — project context for Claude Code

`rlsgate` is **the pre-deploy security gate for vibe-coded Supabase apps** — it catches the RLS holes and secret leaks before they ship. Public OSS, **MIT**, repo `GerardoRdz96/rlsgate`, on PyPI (`pip install rlsgate`). It runs as a CLI, a GitHub Action, and a Claude Code skill.

This file is authoritative project context. Verify every claim against the code before acting; do not improvise facts about this repo.

---

## Why it exists

In 2026 a wave of AI-built ("vibe-coded") apps shipped with the same handful of holes. **CVE-2025-48757** and the Lovable disclosure cataloged **170+ live apps leaking user PII** — most through one anti-pattern: an RLS policy that lets *any logged-in user* read *everyone's* rows. ~80% of vibe-coded apps repeat that RLS mistake; ~72% ship a hardcoded secret. rlsgate is a **finite, high-precision** set of checks for the holes that actually leak — small enough that you leave it on, unlike breadth scanners you mute.

---

## What it does

Deterministic scanner → findings with severity → **non-zero exit blocks the deploy**. The non-zero exit IS the gate. Six rules (`src/rlsgate/rules/`):

| Rule ID | Severity | What it catches |
|---|---|---|
| `rls-authenticated` | CRITICAL | RLS policy authorizes any *authenticated* user instead of the row owner — **the CVE-2025-48757 class** |
| `rls-disabled` | CRITICAL/HIGH | A user/PII table created without `ENABLE ROW LEVEL SECURITY` (wide open to the anon key) |
| `anon-access` | CRITICAL/HIGH | Data reachable by the unauthenticated `anon` role via a permissive policy or grant |
| `public-bucket` | HIGH | A Supabase Storage bucket created `public` (every object served to anyone with the URL) |
| `exposed-secret` | CRITICAL/HIGH | A real secret committed to `.env`, or a service-role / `sk-` key shipped to the browser bundle |
| `unverified-webhook` | HIGH | A webhook endpoint that acts on the body without verifying the provider's signature |

**Detection is deterministic. AI is opt-in and only drafts fix snippets — it never decides whether a hole exists.** Never claim a finding rlsgate did not report.

---

## Stack & packaging (verified)

- **Pure Python, zero runtime dependencies** (`pyproject.toml` → `dependencies = []`). `requires-python = ">=3.9"`. Keep the core dep-free — that's what makes it trivial to run anywhere (`uvx rlsgate scan`).
- Optional extras: `ai` = `anthropic>=0.40` (the `--ai` fix-snippet path), `dev` = `pytest>=8.0`.
- Build: **hatchling**, package `src/rlsgate` (src layout). Console entry point: `rlsgate = "rlsgate.cli:main"`; also `python -m rlsgate`.
- **sdist hygiene:** `tool.hatch.build.targets.sdist` ships **package + docs only** (`src/rlsgate`, `README.md`, `LICENSE`, `skill`). The test fixtures include **deliberately-fake secret samples** (`tests/fixtures/bad/.env`) that must never land on PyPI — don't add fixtures to the sdist allowlist.

---

## CLI

```sh
rlsgate scan [PATH]          # scan a project (default: .)
rlsgate scan --json          # machine-readable output
rlsgate scan --fail-on LEVEL # critical | high (default) | medium | low
rlsgate scan --ai            # add AI-drafted fix snippets (needs ANTHROPIC_API_KEY)
rlsgate scan --no-color
rlsgate rules                # list the checks
rlsgate version
```

**Exit codes (the contract — do not change lightly):** `0` = clean, or only findings **below** `--fail-on`; `1` = blocking findings **at or above** `--fail-on`; `2` = usage / path error. CI relies on these.

---

## Package layout (`src/rlsgate/`)

- `cli.py` — argparse entry (`scan` / `rules` / `version`), exit-code contract, output orchestration.
- `discover.py` — locates the Supabase project (migrations, SQL, config) in the target.
- `scanner.py` — walks the project and runs the rules over the discovered surface.
- `rules/` — the six checks above + `_common.py` (shared helpers) + `__init__.py` (registry). **One rule = one file**; add a rule here and register it, don't bloat the scanner.
- `sql.py` — parses Postgres/Supabase migration SQL (policies, grants, `ENABLE ROW LEVEL SECURITY`, bucket creation).
- `model.py` — the `Finding` / severity data types. `findings.py` — finding collection/aggregation.
- `report.py` — human (colorized) + `--json` output. `fix.py` — the opt-in AI fix-snippet drafting (anthropic).
- `context.py` + `gitinfo.py` — file/git context for findings.
- `__main__.py` — `python -m rlsgate`.

---

## Tests

`pytest` (testpaths `tests`, `-q`). **46 test functions** across `test_cli.py`, `test_scanner.py`, `test_sql.py`, `test_model.py`, `test_common.py`, `test_git_aware.py`, and `test_codex_fixes.py` (regression tests pinning the Codex-review fixes — keep them green). Fixtures in `tests/fixtures/` include intentionally-vulnerable sample projects.

```sh
uv run pytest          # or: pip install -e ".[dev]" && pytest
```

---

## The other two surfaces

- **GitHub Action** (`action.yml`) — composite action. Inputs: `path` (default `.`), `fail-on` (default `high`), `ai` (default `false`). It sets up Python, `pip install`s the action ref, and runs the scan so a failing gate fails the check. Keep `action.yml` inputs in lockstep with the CLI flags.
- **Claude Code skill** (`skill/SKILL.md`, name `rlsgate`) — runs the scan, brings findings into the conversation, helps fix the blocking ones. The skill's hard rule mirrors this file's: detection is deterministic; the model only reasons over reported findings and proposes fixes — **never invents a hole**.

---

## Standing rules

- **Deterministic core, never invent findings.** Every reported hole must come from a rule firing on real evidence. AI only drafts fixes.
- **Keep the runtime dependency-free.** New core logic uses the stdlib; `anthropic` stays behind the `ai` extra.
- **Protect the exit-code contract** (0 / 1 / 2) and the `--fail-on` semantics — CI and the Action depend on them.
- **Precision over count.** The pitch is a finite, trustworthy rule set. Resist adding noisy low-signal rules; a rule people mute is worse than no rule.
- **Never ship fixtures to PyPI.** The fake-secret samples stay out of the sdist.

## Keeping this file honest

This file is re-read every turn — keep it accurate. When you add a rule, change a CLI flag or exit code, or touch packaging, update this file (and `action.yml` + the skill where they overlap) in the same change, and re-verify against the code. Stale context here causes a gate you can't trust.
