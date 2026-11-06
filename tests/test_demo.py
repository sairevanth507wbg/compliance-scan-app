import pytest

from compliance.demo import DEMO_SQL_EXAMPLES, INSTANCES, DemoDB
from compliance.queries import ContentFilters, NoteRejected, QueryRejected, ViolationFilters


@pytest.fixture
def db():
    return DemoDB()


def test_filters_and_summary(db):
    cols, rows = db.fetch_violations(ViolationFilters())
    assert len(rows) == 7 and "instance" in cols
    assert len(db.fetch_violations(ViolationFilters(status="all"))[1]) == 10
    assert len(db.fetch_violations(ViolationFilters(status="all", locked="locked"))[1]) == 1
    assert len(db.fetch_violations(ViolationFilters(status="all", search="jdoe"))[1]) == 2
    s = db.summary()
    assert {k: s[k] for k in ("open", "locked", "pending_lock", "resolved_7d")} == \
        {"open": 7, "locked": 1, "pending_lock": 2, "resolved_7d": 2}


def test_instances_runs_content_events(db):
    assert db.list_instances() == list(INSTANCES) == ["prod-internal"]
    cols, runs = db.fetch_runs()
    assert len(runs) == 12 and sum(r[cols.index("status")] == "FAILED" for r in runs) == 1
    _, apps = db.fetch_content(ContentFilters(instance="prod-internal", status="COMPLIANT"))
    assert len(apps) == 13
    _, excluded = db.fetch_content(ContentFilters(instance="prod-internal", status="EXCLUDED"))
    assert len(excluded) == 1
    events = [e[1] for e in db.list_events(5)]
    assert events[0] == "DETECTED" and "ADMIN_UNLOCKED" in events


def test_admin_lock_scope_and_history(db):
    from compliance.admin import change_scope_list, set_app_lock
    from compliance.models import SCOPE_EXCLUDED

    cols, rows = db.fetch_violations(ViolationFilters(instance="prod-internal"))
    v = dict(zip(cols, rows[0]))
    connect = db.demo_connect()
    r = set_app_lock(connect, db, instance=v["instance"], guid=v["content_guid"], lock=True, actor="tester")
    assert r.ok
    kinds = [e[1] for e in db.list_events(v["id"], v["instance"], v["content_guid"])]
    assert kinds[-1] == "MANUAL_LOCK"
    _, actions = db.list_admin_actions("prod-internal")
    assert actions[0][3] == "MANUAL_LOCK" and actions[0][2] == "tester"

    _, scope_before = db.list_scope("prod-internal")
    r = change_scope_list(db, instance="prod-internal", text=v["content_guid"], list_type=SCOPE_EXCLUDED,
                          add=True, actor="tester")
    assert r.ok
    _, scope_after = db.list_scope("prod-internal")
    assert len(scope_after) == len(scope_before) + 1


def test_notes(db):
    assert len(db.list_notes(3)) == 1
    db.add_note(1, "tester", "  looks fixable  ")
    assert db.list_notes(1)[0][1:] == ("tester", "looks fixable")
    with pytest.raises(NoteRejected):
        db.add_note(1, "tester", " ")


def test_sql_tab_is_read_only(db):
    for query in DEMO_SQL_EXAMPLES.values():
        db.run_readonly_sql(query, user="t")
    with pytest.raises(QueryRejected):
        db.run_readonly_sql("DELETE FROM branch_violations", user="t")
    assert db.summary()["open"] == 7
