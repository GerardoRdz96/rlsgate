"""Git-aware env scanning: a gitignored secret is correct hygiene (not a finding);
a committed secret is a real leak; a client-public secret leaks regardless of git."""
import subprocess

from rlsgate.scanner import scan


def _git(p, *args):
    subprocess.run(["git", "-C", str(p), *args], capture_output=True, text=True)


def _secrets(root):
    return [f for f in scan(root).findings if f.rule_id == "exposed-secret"]


def test_gitignored_env_is_not_flagged(tmp_path):
    _git(tmp_path, "init")
    (tmp_path / ".gitignore").write_text(".env.local\n")
    (tmp_path / ".env.local").write_text(
        "SUPABASE_SERVICE_ROLE_KEY=sb_secret_8f3a9c2b7e1d4f6a0c5b8e2d\n")
    assert _secrets(tmp_path) == []


def test_committed_env_is_critical(tmp_path):
    _git(tmp_path, "init")
    (tmp_path / ".env").write_text(
        "STRIPE_SECRET_KEY=committed_secret_value_abc123def456\n")
    _git(tmp_path, "add", ".env")
    _git(tmp_path, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "x")
    secs = _secrets(tmp_path)
    assert secs and secs[0].severity.label == "CRITICAL"
    assert secs[0].meta.get("git") == "tracked"


def test_untracked_env_is_high(tmp_path):
    _git(tmp_path, "init")
    (tmp_path / ".env").write_text(
        "STRIPE_SECRET_KEY=committed_secret_value_abc123def456\n")
    secs = _secrets(tmp_path)
    assert secs and secs[0].severity.label == "HIGH"
    assert secs[0].meta.get("git") == "untracked"


def test_client_public_secret_flagged_even_if_gitignored(tmp_path):
    _git(tmp_path, "init")
    (tmp_path / ".gitignore").write_text(".env.local\n")
    (tmp_path / ".env.local").write_text(
        "NEXT_PUBLIC_SERVICE_ROLE_KEY=sb_secret_8f3a9c2b7e1d4f6a0c5b8e2d\n")
    secs = _secrets(tmp_path)
    assert any(f.meta.get("client_public") for f in secs)
    assert secs[0].severity.label == "CRITICAL"


def test_catalog_table_not_flagged_for_authenticated_read(tmp_path):
    # a reference/catalog table readable by all authenticated users is NOT a leak
    mig = tmp_path / "supabase" / "migrations"
    mig.mkdir(parents=True)
    (mig / "x.sql").write_text(
        "create table public.badges (slug text primary key, name text, icon text);\n"
        "alter table public.badges enable row level security;\n"
        "create policy badges_read on public.badges for select to authenticated using (true);\n")
    findings = scan(tmp_path).findings
    assert findings == [], [f.title for f in findings]
