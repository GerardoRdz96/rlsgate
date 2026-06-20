"""Regression tests for the five issues Codex's adversarial review found.
Each test encodes a real input that previously slipped through (or wrongly fired)."""
from rlsgate import cli
from rlsgate.scanner import ScanResult, scan


def _scan_sql(tmp_path, sql):
    mig = tmp_path / "supabase" / "migrations"
    mig.mkdir(parents=True, exist_ok=True)
    (mig / "x.sql").write_text(
        "create table public.notes (id uuid primary key, user_id uuid, body text);\n"
        "alter table public.notes enable row level security;\n" + sql + "\n")
    return scan(tmp_path).findings


def _ids(findings):
    return {f.rule_id for f in findings}


# --- Codex #1: role bypass via JWT claim and current_setting ----------------

def test_jwt_role_claim_bypass_is_caught(tmp_path):
    f = _scan_sql(tmp_path, "create policy r on public.notes for select using (auth.jwt() ->> 'role' = 'authenticated');")
    assert "rls-authenticated" in _ids(f)


def test_current_setting_role_bypass_is_caught(tmp_path):
    f = _scan_sql(tmp_path, "create policy r on public.notes for select using (current_setting('request.jwt.claim.role') = 'authenticated');")
    assert "rls-authenticated" in _ids(f)


def test_ownership_alongside_role_check_is_safe(tmp_path):
    f = _scan_sql(tmp_path, "create policy r on public.notes for select using (auth.role() = 'authenticated' and auth.uid() = user_id);")
    assert "rls-authenticated" not in _ids(f)


def test_jwt_sub_ownership_is_safe(tmp_path):
    f = _scan_sql(tmp_path, "create policy r on public.notes for select using (auth.jwt() ->> 'sub' = user_id::text);")
    assert "rls-authenticated" not in _ids(f)


# --- Codex #2: WITH CHECK (true) on INSERT TO authenticated -----------------

def test_with_check_true_insert_is_caught(tmp_path):
    f = _scan_sql(tmp_path, "create policy w on public.notes for insert to authenticated with check (true);")
    assert "rls-authenticated" in _ids(f)


# --- Codex #3: webhook secret variable without a verification call ----------

def test_webhook_secret_name_without_call_is_flagged(tmp_path):
    p = tmp_path / "app" / "api" / "webhook"
    p.mkdir(parents=True)
    (p / "route.ts").write_text(
        "const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;\n"
        "export async function POST(req: Request) {\n"
        "  const event = await req.json();\n"
        "  return new Response('ok');\n}\n")
    assert "unverified-webhook" in _ids(scan(tmp_path).findings)


# --- Codex #4: quoted public:true in the JS storage API ---------------------

def test_quoted_public_bucket_in_js_is_caught(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "storage.ts").write_text('await supabase.storage.createBucket("docs", { "public": true });\n')
    assert "public-bucket" in _ids(scan(tmp_path).findings)


# --- Codex #5: a rule crash must fail the gate, not report a false all-clear -

def test_rule_error_fails_the_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda p: ScanResult(root=str(p), errors=["some-rule: boom"]))
    assert cli.main(["scan", str(tmp_path)]) == 1


# --- Codex round-2: ownership/role-bypass/webhook/bucket tightenings ---------

def test_fake_ownership_not_null_does_not_suppress(tmp_path):
    # `auth.jwt()->>'sub' IS NOT NULL` is not real ownership — the role bypass must fire
    f = _scan_sql(tmp_path, "create policy r on public.notes for select using (auth.role() = 'authenticated' and auth.jwt() ->> 'sub' is not null);")
    assert "rls-authenticated" in _ids(f)


def test_role_in_list_form_is_caught(tmp_path):
    f = _scan_sql(tmp_path, "create policy r on public.notes for select using (auth.role() in ('authenticated'));")
    assert "rls-authenticated" in _ids(f)


def test_genuine_ownership_still_safe(tmp_path):
    f = _scan_sql(tmp_path, "create policy r on public.notes for select using (auth.role() = 'authenticated' and (select auth.uid()) = user_id);")
    assert "rls-authenticated" not in _ids(f)


def test_webhook_verify_name_in_comment_still_flagged(tmp_path):
    p = tmp_path / "app" / "api" / "webhook"
    p.mkdir(parents=True)
    (p / "route.ts").write_text(
        "// TODO: call stripe constructEvent later for signature verification\n"
        "export async function POST(req: Request) {\n"
        "  const event = await req.json();  // from stripe webhook\n"
        "  return new Response('ok');\n}\n")
    assert "unverified-webhook" in _ids(scan(tmp_path).findings)


def test_notpublic_key_not_flagged(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "storage.ts").write_text('await supabase.storage.createBucket("docs", { notpublic: true });\n')
    assert "public-bucket" not in _ids(scan(tmp_path).findings)
