import json

import pytest

from compliance.config import ConfigError
from compliance.queries import (
    EXAMPLE_QUERIES, ContentFilters, DashboardSettings, NoteRejected, QueryRejected, ViolationFilters,
    build_content_query, build_violations_query, clean_note, is_authorized, parse_connect_user,
    validate_readonly_sql,
)

# ----- SQL validation -----------------------------------------------------------


@pytest.mark.parametrize("query", [
    "SELECT 1",
    "select * from branch_violations;",
    "SELECT 1;;  ",
    "WITH x AS (SELECT 1) SELECT * FROM x",
    "TABLE branch_violations",
    "EXPLAIN SELECT * FROM branch_violations",
    "SELECT ';' AS semi, 'DROP TABLE x' AS text",
    "SELECT $$; DELETE FROM x$$",
    "SELECT $tag$ ; $tag$",
    "SELECT \"update\" FROM t",                       # quoted identifier is fine
    "-- comment; DROP\nSELECT 1",
    "/* ; DELETE */ SELECT 1",
    "SELECT locked, notified_at FROM branch_violations WHERE status = 'RESOLVED'",
    "SELECT E'it\\'s ok'",
    *EXAMPLE_QUERIES.values(),
])
def test_valid_read_only_queries(query):
    assert validate_readonly_sql(query)


@pytest.mark.parametrize("query,message", [
    ("", "Enter a query"),
    ("   ;", "Enter a query"),
    ("DELETE FROM branch_violations", "read-only"),
    ("UPDATE branch_violations SET locked = false", "read-only"),
    ("DROP TABLE branch_violations", "read-only"),
    ("SELECT 1; DELETE FROM branch_violations", "one statement"),
    ("SELECT 1; COMMIT", "one statement"),
    ("WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", "DELETE"),
    ("EXPLAIN ANALYZE SELECT 1", "ANALYZE"),
    ("SELECT set_config('x', 'y', false); SET ROLE postgres", "one statement"),
    ("SELECT 'unterminated", "Unterminated"),
    ("SELECT 1 /* open", "Unterminated"),
    ("SELECT E'\\''; DELETE FROM t; SELECT ''", "one statement"),
    ("SELECT 1; -- trailing comment\nDELETE FROM t", "one statement"),
    ("SELECT * INTO new_table FROM t; TRUNCATE t", "one statement"),
    ("COPY t TO PROGRAM 'x'", "read-only"),
])
def test_rejected_queries(query, message):
    with pytest.raises(QueryRejected, match=message):
        validate_readonly_sql(query)


def test_trailing_semicolon_removed_and_text_preserved():
    assert validate_readonly_sql("SELECT ';' ;  ") == "SELECT ';'"


def test_query_length_limit():
    with pytest.raises(QueryRejected, match="longer"):
        validate_readonly_sql("SELECT " + "1," * 20_000 + "1")


# ----- filters -------------------------------------------------------------------


def render(f: ViolationFilters):
    query, params = build_violations_query("posit_compliance", f, 500)
    return query.as_string(None), params


def test_default_filter_is_open_only():
    text, params = render(ViolationFilters())
    assert '"posit_compliance"."branch_violations"' in text
    assert "WHERE status = %s" in text and params == ["NON_COMPLIANT", 500]


def test_all_filters_are_parameterised():
    f = ViolationFilters(status="all", locked="locked", search="50%_x", branch="feat", detected_within_days=7)
    text, params = render(f)
    assert "50%" not in text and "feat" not in text          # values never inlined
    assert params[0] == "%50\\%\\_x%"                          # LIKE wildcards escaped
    assert params.count(params[0]) == 5
    assert params[-3:] == ["%feat%", 7, 500]
    assert "locked" in text and "make_interval" in text


def test_instance_filter():
    text, params = render(ViolationFilters(instance="prod-internal", status="all"))
    assert "instance = %s" in text and params == ["prod-internal", 500]


def test_content_query():
    query, params = build_content_query("posit_compliance", ContentFilters(
        instance="qa-external", status="UNKNOWN", search="atlas"), 100)
    text = query.as_string(None)
    assert '"posit_compliance"."content_compliance"' in text
    assert params == ["qa-external", "UNKNOWN", "%atlas%", "%atlas%", "%atlas%", 100]


def test_no_filters():
    text, params = render(ViolationFilters(status="all"))
    assert "WHERE" not in text and params == [500]


# ----- identity / authorization -------------------------------------------------


def test_parse_connect_user():
    u = parse_connect_user(json.dumps({"user": "jdoe", "groups": ["posit-admins"]}))
    assert u.username == "jdoe" and u.groups == ("posit-admins",)
    assert parse_connect_user(None) is None
    assert parse_connect_user("not json") is None
    assert parse_connect_user(json.dumps({"user": ""})) is None


def test_authorization():
    user = parse_connect_user(json.dumps({"user": "JDoe", "groups": ["Posit-Admins"]}))
    assert is_authorized(user, DashboardSettings())                       # Connect access only
    assert is_authorized(None, DashboardSettings())
    assert is_authorized(user, DashboardSettings(allowed_users=("jdoe",)))
    assert is_authorized(user, DashboardSettings(allowed_groups=("posit-admins",)))
    assert not is_authorized(user, DashboardSettings(allowed_users=("someone",)))
    assert not is_authorized(None, DashboardSettings(allowed_groups=("posit-admins",)))


# ----- settings / notes ----------------------------------------------------------


def test_dashboard_prefers_its_own_database_url():
    s = DashboardSettings.from_env({"DATABASE_URL": "postgresql://job", "DASHBOARD_DATABASE_URL": "postgresql://dash"})
    assert s.database_url == "postgresql://dash"
    assert "postgresql" not in repr(s)
    k = DashboardSettings.from_env({"CONNECT_SERVER": "https://c", "COMPLIANCE_CONNECT_API_KEY": "SECRETKEY"})
    assert k.connect_api_key == "SECRETKEY" and "SECRETKEY" not in repr(k)


def test_dashboard_settings_validation():
    with pytest.raises(ConfigError):
        DashboardSettings.from_env({"DB_SCHEMA": "x; drop"})
    with pytest.raises(ConfigError):
        DashboardSettings.from_env({"SQL_MAX_ROWS": "0"})


def test_clean_note():
    assert clean_note("  hello  ") == "hello"
    with pytest.raises(NoteRejected):
        clean_note("   ")
    with pytest.raises(NoteRejected):
        clean_note("x" * 4001)
