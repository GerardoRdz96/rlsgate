from pathlib import Path

from rlsgate.scanner import scan

FIX = Path(__file__).parent / "fixtures"
ALL_SIX = {
    "rls-disabled", "rls-authenticated", "anon-access",
    "public-bucket", "exposed-secret", "unverified-webhook",
}


def test_good_project_is_clean():
    r = scan(FIX / "good")
    assert r.findings == [], [f.title for f in r.findings]
    assert r.errors == []


def test_bad_project_flags_every_rule():
    r = scan(FIX / "bad")
    assert {f.rule_id for f in r.findings} == ALL_SIX
    assert r.errors == []


def test_bad_critical_rules_are_critical():
    r = scan(FIX / "bad")
    crit = {f.rule_id for f in r.findings if f.severity.label == "CRITICAL"}
    assert {"rls-disabled", "rls-authenticated", "anon-access"} <= crit


def test_exposed_secret_source_and_anon_safe():
    r = scan(FIX / "bad")
    secs = [f for f in r.findings if f.rule_id == "exposed-secret"]
    # the hardcoded service-role key in client source is always caught (git-independent)
    assert any("client source" in f.title for f in secs)
    # the PUBLIC anon key must never be flagged
    assert all("ANON" not in (f.meta.get("key", "") or "").upper() for f in secs)


def test_findings_sorted_worst_first():
    r = scan(FIX / "bad")
    sevs = [int(f.severity) for f in r.findings]
    assert sevs == sorted(sevs, reverse=True)
