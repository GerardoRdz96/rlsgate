from rlsgate.model import build_model, normalize_qname
from rlsgate.sql import split_statements


def _model(sql):
    return build_model(split_statements(sql))


def test_normalize_qname():
    assert normalize_qname("users") == "public.users"
    assert normalize_qname("public.users") == "public.users"
    assert normalize_qname('"Public"."Users"') == "public.users"
    assert normalize_qname("app.accounts") == "app.accounts"


def test_parse_table_columns():
    m = _model("create table public.profiles (id uuid primary key, email text, constraint c unique(id));")
    t = m.table("public.profiles")
    assert t is not None
    assert "email" in t.columns
    assert "id" in t.columns
    # the table constraint is not a column
    assert "constraint" not in t.columns


def test_rls_enabled_tracked():
    m = _model("create table public.t (id int); alter table public.t enable row level security;")
    assert "public.t" in m.rls_enabled


def test_parse_policy_roles_and_using():
    m = _model("create policy p on public.t for select to anon, authenticated using (auth.uid() = user_id);")
    assert len(m.policies) == 1
    p = m.policies[0]
    assert p.table == "public.t"
    assert p.command == "select"
    assert set(p.roles) == {"anon", "authenticated"}
    assert "auth.uid()" in p.using.replace(" ", "")


def test_parse_policy_with_check():
    m = _model("create policy p on t for insert with check (auth.uid() = user_id);")
    p = m.policies[0]
    assert "auth.uid()" in p.with_check.replace(" ", "")


def test_parse_grant():
    m = _model("grant select, insert on public.t to anon;")
    g = m.grants[0]
    assert g.table == "public.t"
    assert "anon" in g.roles
    assert "select" in g.privileges
