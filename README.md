# rlsgate

**The Supabase deploy-gate that runs where you vibe-code — and blocks only on the holes that are truly dangerous.**

In 2026, a wave of AI-built ("vibe-coded") apps shipped to production with the same handful of security holes. [CVE-2025-48757](https://nvd.nist.gov/) and the Lovable disclosure cataloged **170+ live apps leaking user PII** — most through one anti-pattern: a Row Level Security policy that lets *any logged-in user* read *everyone's* rows. Studies of vibe-coded apps found ~80% repeat the same RLS mistake and ~72% ship a hardcoded secret somewhere.

`rlsgate` is a **local-first, static** scanner that reads your Supabase migrations, RLS policies, env files, and frontend bundle and **blocks the deploy** when it finds the finite set of high-signal holes that actually leak. No database connection, no telemetry, no account. It runs in seconds, as a CLI, a Claude Code skill, or a GitHub Action.

```
$ rlsgate scan
rlsgate  ·  1 migrations, 1 env, 2 source files scanned

✖ CRITICAL  Table public.profiles holds personal data but Row Level Security is never enabled
    where: supabase/migrations/0001_init.sql:2
    why:   With RLS off in a client-reachable schema, anyone holding the public anon key can read every row.
    fix:   ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY; then add an ownership policy.

✖ CRITICAL  RLS policy 'read all posts' grants every authenticated user access to public.posts
    where: supabase/migrations/0001_init.sql:15
    fix:   Bind the policy to the row owner, e.g. USING (auth.uid() = user_id).

▲ HIGH      Webhook handler does not verify the request signature (app/api/stripe/webhook/route.ts)
    ...
  3 critical  2 high
$ echo $?
1
```

## Why it's different

Plenty of tools scan vibe-coded apps. `rlsgate` is the one that is **local-first, runs inside your build loop, and blocks at deploy** — not a dashboard you visit, not a sidecar you run in production.

- **vs hosted SaaS scanners** — they guess at your security from *outside* your live URL and want a token to your repo. `rlsgate` reads your actual migrations and RLS policies locally. No DB connection, no account, no token handoff, no telemetry.
- **vs runtime sidecars / firewalls** — they filter requests *after* deploy, in front of your app. `rlsgate` catches the hole *before* deploy, in your repo, where it's a one-line fix instead of an incident.
- **vs broad scanners** — they compete on rule count (hundreds to thousands), which means noise, which means you turn them off. `rlsgate` ships a finite, high-precision set of checks for the holes that actually leak — including the CVE-2025-48757 "any authenticated user can read any row" class that breadth scanners miss — so it's a gate you'll actually leave on.

It's the same checks across three surfaces with full parity: a **CLI**, a **Claude Code skill** that fires mid-build (inside the AI tool generating your app), and a **GitHub Action** that blocks the merge. Works across any builder — Lovable, Bolt, Cursor, v0, or hand-rolled.

## Install

```bash
pip install rlsgate         # or: uv tool install rlsgate
rlsgate scan                # scan the current directory
```

No Python project? A zero-install run:

```bash
uvx rlsgate scan ./my-app
```

## Usage

```bash
rlsgate scan [PATH]              # scan a project (default: .)
rlsgate scan --json             # machine-readable output
rlsgate scan --fail-on critical # only CRITICAL fails the gate (default: high)
rlsgate scan --ai               # add AI-drafted fix snippets (needs ANTHROPIC_API_KEY)
rlsgate rules                   # list the checks
```

**Exit codes:** `0` clean (or only findings below `--fail-on`) · `1` blocking findings · `2` usage error. The non-zero exit is what makes it a gate.

## What it checks (v1)

| Rule | Severity | The hole |
|---|---|---|
| `rls-authenticated` | CRITICAL | RLS policy authorizes any *authenticated* user instead of the row owner — the CVE-2025-48757 class |
| `rls-disabled` | CRITICAL/HIGH | A user/PII table created without `ENABLE ROW LEVEL SECURITY` (wide open to the anon key) |
| `anon-access` | CRITICAL/HIGH | Data reachable by the unauthenticated `anon` role via a permissive policy or grant |
| `public-bucket` | HIGH | A Supabase Storage bucket created `public` (every object served to anyone with the URL) |
| `exposed-secret` | CRITICAL/HIGH | A real secret committed to `.env`, or a service-role key / `sk-` key shipped to the browser bundle |
| `unverified-webhook` | HIGH | A webhook endpoint that acts on the body without verifying the provider's signature |

The Supabase **anon** key (a public JWT with `role: anon`) is intentionally public and is **never** flagged — only the dangerous `service_role` key is.

## GitHub Action

```yaml
# .github/workflows/rlsgate.yml
name: rlsgate
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: GerardoRdz96/rlsgate@v0.1.0
        with:
          path: .
          fail-on: high
```

## Claude Code skill

Copy `skill/` into your project's `.claude/skills/rlsgate/` (or install the repo as a plugin). Then, in the agent loop before deploy:

```
/rlsgate
```

The skill runs the gate and brings the findings into the conversation so the agent fixes them before shipping.

## What rlsgate is NOT

- **Not a full security audit.** It checks a finite, high-signal ruleset, statically. It will not catch logic bugs, business-rule auth flaws, or holes that only appear at runtime.
- **Not a database scanner.** v1 reads files only — it never connects to your Supabase project. A policy that *looks* correct but behaves differently at runtime is out of scope.
- **Not an auto-fixer.** The deterministic finding is the source of truth. The optional `--ai` fix is clearly labeled AI-drafted and must be reviewed before you apply it.

A clean `rlsgate` run means "none of the known high-signal holes are present," not "this app is secure."

## License

MIT © 2026 [Penguin Alley](https://penguinalley.com)
