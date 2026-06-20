import contextlib
import io
import json
from pathlib import Path

from rlsgate.cli import main

FIX = Path(__file__).parent / "fixtures"


def _run(args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(args)
    return rc, buf.getvalue()


def test_exit_clean_on_good():
    rc, _ = _run(["scan", str(FIX / "good")])
    assert rc == 0


def test_exit_blocking_on_bad():
    rc, _ = _run(["scan", str(FIX / "bad")])
    assert rc == 1


def test_json_output_is_valid():
    rc, out = _run(["scan", str(FIX / "bad"), "--json"])
    data = json.loads(out)
    assert data["tool"] == "rlsgate"
    assert data["summary"]["CRITICAL"] >= 1
    assert rc == 1


def test_rules_command():
    rc, out = _run(["rules"])
    assert rc == 0
    assert "rls-authenticated" in out


def test_path_not_found_is_usage_error():
    rc, _ = _run(["scan", "/no/such/path/xyz123"])
    assert rc == 2


def test_fail_on_threshold(tmp_path):
    mig = tmp_path / "supabase" / "migrations"
    mig.mkdir(parents=True)
    (mig / "x.sql").write_text("insert into storage.buckets (id,name,public) values ('a','a',true);")
    # only a HIGH finding (public bucket): passes when gate is critical, fails when high
    assert _run(["scan", str(tmp_path), "--fail-on", "critical"])[0] == 0
    assert _run(["scan", str(tmp_path), "--fail-on", "high"])[0] == 1
