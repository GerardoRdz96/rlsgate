---
name: rlsgate
description: Run the rlsgate pre-deploy security gate on a Supabase-backed project. Use when about to deploy a vibe-coded / Supabase / Lovable / Bolt / Cursor app, or when the user asks to check for RLS holes, exposed secrets, anon-readable tables, public buckets, or unverified webhooks before shipping.
---

# rlsgate — pre-deploy security gate

Run rlsgate against the project, bring the findings into the conversation, and help fix the blocking ones before the user ships. Detection is deterministic; you only reason over the findings and propose fixes — never claim a hole exists that rlsgate did not report.

## Steps

1. **Run the scan** from the project root. Prefer JSON so you can reason over it:
   ```bash
   rlsgate scan . --json          # if installed
   # or, zero-install:
   uvx rlsgate scan . --json
   # or, from a source checkout:
   python -m rlsgate scan . --json
   ```
   If rlsgate is not installed, install it first: `pip install rlsgate` (add `[ai]` for AI-drafted fixes).

2. **Summarize** the result for the user: the counts by severity and a one-line-per-finding list (severity, rule, `file:line`, title). Lead with CRITICAL and HIGH.

3. **For each blocking finding** (CRITICAL/HIGH by default), explain in plain language *why it leaks* (from the finding's `detail`) and propose the concrete fix (from `fix`). Open the cited `file:line`, show the exact change, and apply it **only after the user agrees** — rlsgate's deterministic finding is the source of truth; never auto-apply a fix blind.

4. **MEDIUM/LOW findings** are review notes (often intended-public tables). Surface them, but don't block on them — ask the user to confirm the exposure is intentional.

5. **Re-run** `rlsgate scan .` after fixes and confirm the gate is green (exit 0) before the user deploys.

## Notes

- rlsgate is **static and finite** — a clean run means "none of the known high-signal holes are present," not "this app is secure." Say so; never imply a full audit.
- The Supabase **anon** key is public by design and is never flagged; only the **service_role** key is.
- Gitignored secret files are correct hygiene and are not flagged; a `NEXT_PUBLIC_`/`VITE_` secret is flagged even if gitignored, because it inlines into the browser bundle.
- Exit codes: `0` clean (or only sub-threshold findings) · `1` blocking findings · `2` usage error. Tune the gate with `--fail-on critical|high|medium|low`.
