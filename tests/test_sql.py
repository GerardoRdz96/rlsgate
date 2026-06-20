from rlsgate.sql import split_statements


def test_splits_simple_statements():
    sts = split_statements("create table a (id int);\ncreate table b (id int);")
    assert len(sts) == 2
    assert sts[0].text.startswith("create table a")
    assert sts[1].line == 2


def test_semicolon_in_string_does_not_split():
    sts = split_statements("insert into t values ('a; b; c');")
    assert len(sts) == 1


def test_semicolon_in_line_comment_ignored():
    sql = "create table a (id int); -- drop; everything;\ncreate table b (id int);"
    sts = split_statements(sql)
    assert len(sts) == 2


def test_block_comment_ignored():
    sql = "create table a (id int); /* ; ; ; */ create table b (id int);"
    assert len(split_statements(sql)) == 2


def test_dollar_quoted_body_not_split():
    sql = (
        "create function f() returns trigger as $$ begin; perform 1; end; $$ language plpgsql;"
        " create table b (id int);"
    )
    sts = split_statements(sql)
    assert len(sts) == 2


def test_line_numbers_point_at_first_token():
    sql = "\n\n-- header\ncreate table a (id int);"
    sts = split_statements(sql)
    assert sts[0].line == 4
