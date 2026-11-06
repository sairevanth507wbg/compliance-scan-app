"""End-to-end job behaviour with a fake Connect API, fake email and in-memory store."""

from datetime import datetime, timedelta, timezone

import pytest

from compliance.config import Settings
from compliance.connect_client import ConnectAPIError, ConnectAuthError, ConnectNotFoundError
from compliance.job import ComplianceJob
from compliance.models import RESOLUTION_COMPLIANT, RESOLUTION_DELETED, STATUS_RESOLVED
from compliance.store import InMemoryStore

T0 = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)


class FakeConnect:
    def __init__(self):
        self.content: dict[str, dict] = {}
        self.repos: dict[str, dict] = {}
        self.users = {"u1": {"username": "jdoe", "email": "jdoe@example.com", "first_name": "J"}}
        self.lock_calls: list[tuple[str, bool]] = []
        self.hidden_when_locked = False
        self.repo_errors: set[str] = set()

    def add(self, guid, branch="main", repo="https://github.com/example-org/app", git=True):
        self.content[guid] = {"guid": guid, "title": f"App-{guid}", "owner_guid": "u1", "locked": False,
                              "content_url": f"https://connect/content/{guid}/",
                              "dashboard_url": f"https://connect/connect/#/apps/{guid}"}
        if git:
            self.repos[guid] = {"repository": repo, "branch": branch, "directory": "."}

    def list_content(self):
        return [dict(c) for c in self.content.values() if not (self.hidden_when_locked and c["locked"])]

    def get_content(self, guid):
        if guid not in self.content:
            raise ConnectNotFoundError("404", 404)
        return dict(self.content[guid])

    def get_repository(self, guid):
        if guid in self.repo_errors:
            raise ConnectAPIError("boom", 500)
        return self.repos.get(guid)

    def get_user(self, guid):
        return self.users[guid]

    def set_locked(self, guid, locked, message=None):
        self.lock_calls.append((guid, locked))
        self.content[guid]["locked"] = locked
        return dict(self.content[guid])


class FakeNotifier:
    def __init__(self, ok=True):
        self.sent: list[tuple[list, list, str]] = []
        self.contents: list = []
        self.ok = ok

    def send(self, to, cc, content):
        if self.ok:
            self.sent.append((to, cc, content.subject))
            self.contents.append(content)
        return self.ok


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


def settings(**kw):
    base = dict(scan_enabled=True, connect_server="https://connect", connect_api_key="k",
                allowed_git_orgs=("example-org", "example-labs"),
                database_url="postgresql://test", smtp_host="smtp", smtp_sender="noreply@x",
                admin_emails=("admin@example.com",))
    base.update(kw)
    return Settings(**base)


@pytest.fixture
def env():
    connect, store, notifier, clock = FakeConnect(), InMemoryStore(), FakeNotifier(), Clock()

    def run(**kw):
        job = ComplianceJob(settings(**kw), connect, store, notifier, now_fn=clock)
        return job.run()

    return connect, store, notifier, clock, run


def subjects(notifier):
    return [s for _, _, s in notifier.sent]


def test_idempotent_first_notice(env):
    connect, store, notifier, clock, run = env
    connect.add("a", branch="feature/test")
    for minutes in (0, 15, 30):
        clock.now = T0 + timedelta(minutes=minutes)
        summary = run()
        assert summary.non_compliant == 1
    assert len(notifier.sent) == 1
    assert notifier.sent[0][0] == ["jdoe@example.com"]
    [v] = store.list_open_violations()
    assert v.first_detected_at == T0
    assert v.last_checked_at == T0 + timedelta(minutes=30)
    assert v.notified_at == T0
    assert v.detected_branch == "feature/test" and v.app_url == "https://connect/content/a/"


def test_compliant_app_creates_no_violation(env):
    connect, store, notifier, _, run = env
    connect.add("a")
    connect.add("b", git=False)
    summary = run()
    assert (summary.compliant, summary.not_git_backed) == (1, 1)
    assert store.all() == [] and notifier.sent == []


def test_resolution_when_redeployed_from_main(env):
    connect, store, _, clock, run = env
    connect.add("a", branch="dev")
    run()
    connect.repos["a"]["branch"] = "main"
    clock.now = T0 + timedelta(hours=2)
    summary = run()
    assert summary.resolved == 1
    [v] = store.all()
    assert v.status == STATUS_RESOLVED and v.resolution == RESOLUTION_COMPLIANT
    assert v.resolved_at == clock.now


def test_blocking_disabled_never_locks(env):
    connect, store, notifier, clock, run = env
    connect.add("a", branch="dev")
    for days in (0, 1, 5, 30):
        clock.now = T0 + timedelta(days=days)
        run(grace_period=timedelta(days=3), blocking_enabled=False)
    assert connect.lock_calls == []
    assert len(notifier.sent) == 1  # first notice only, no final warning
    assert store.list_open_violations()[0].locked is False


def test_no_grace_period_never_locks(env):
    connect, _, _, clock, run = env
    connect.add("a", branch="dev")
    for days in (0, 30):
        clock.now = T0 + timedelta(days=days)
        run(grace_period=None, blocking_enabled=True)
    assert connect.lock_calls == []


def test_full_lock_cycle(env):
    connect, store, notifier, clock, run = env
    connect.add("a", branch="dev")
    cfg = dict(grace_period=timedelta(days=3), blocking_enabled=True)

    run(**cfg)                                         # day 0: first notice
    clock.now = T0 + timedelta(days=1); run(**cfg)     # day 1: nothing
    clock.now = T0 + timedelta(days=2); run(**cfg)     # day 2: final warning
    clock.now = T0 + timedelta(days=2, hours=1); run(**cfg)
    assert connect.lock_calls == []
    clock.now = T0 + timedelta(days=3); summary = run(**cfg)  # day 3: lock
    assert summary.locked == 1
    assert connect.lock_calls == [("a", True)]
    clock.now = T0 + timedelta(days=3, minutes=15); run(**cfg)  # no double lock
    assert connect.lock_calls == [("a", True)]

    s = subjects(notifier)
    assert len(s) == 3
    assert s[0].startswith("[test] [Action required]")
    assert s[1].startswith("[test] [FINAL WARNING]")
    assert s[2].startswith("[test] [Locked]")
    # Final warning and lock notice go to owner + admins.
    assert notifier.sent[1][1] == ["admin@example.com"]
    assert notifier.sent[2][1] == ["admin@example.com"]
    v = store.list_open_violations()[0]
    assert v.locked and v.locked_at == T0 + timedelta(days=3)


def test_no_lock_when_final_warning_cannot_be_sent(env):
    connect, _, notifier, clock, run = env
    notifier.ok = False
    connect.add("a", branch="dev")
    for days in (0, 2, 3, 10):
        clock.now = T0 + timedelta(days=days)
        run(grace_period=timedelta(days=3), blocking_enabled=True)
    assert connect.lock_calls == []


def test_admin_unlock_then_relock_after_fix_window(env):
    connect, store, notifier, clock, run = env
    connect.add("a", branch="dev")
    cfg = dict(grace_period=timedelta(days=3), blocking_enabled=True, relock_window=timedelta(hours=4))
    for days in (0, 2, 3):
        clock.now = T0 + timedelta(days=days)
        run(**cfg)
    assert connect.content["a"]["locked"] is True

    connect.content["a"]["locked"] = False  # admin unlocks in Connect
    clock.now = T0 + timedelta(days=4)
    run(**cfg)
    v = store.list_open_violations()[0]
    assert v.locked is False and v.admin_unlocked_at == clock.now
    assert subjects(notifier)[-1].startswith("[test] [Fix window]")

    clock.now = T0 + timedelta(days=4, hours=3); run(**cfg)
    assert connect.content["a"]["locked"] is False
    clock.now = T0 + timedelta(days=4, hours=4); run(**cfg)
    assert connect.content["a"]["locked"] is True
    assert connect.lock_calls == [("a", True), ("a", True)]


def test_fixed_during_fix_window_resolves_and_stays_unlocked(env):
    connect, store, _, clock, run = env
    connect.add("a", branch="dev")
    cfg = dict(grace_period=timedelta(days=3), blocking_enabled=True)
    for days in (0, 2, 3):
        clock.now = T0 + timedelta(days=days)
        run(**cfg)
    connect.content["a"]["locked"] = False
    clock.now = T0 + timedelta(days=4); run(**cfg)
    connect.repos["a"]["branch"] = "main"
    clock.now = T0 + timedelta(days=4, hours=1); run(**cfg)
    assert store.all()[0].status == STATUS_RESOLVED
    assert connect.content["a"]["locked"] is False


def test_locked_app_hidden_from_listing_is_still_tracked(env):
    connect, store, _, clock, run = env
    connect.hidden_when_locked = True
    connect.add("a", branch="dev")
    cfg = dict(grace_period=timedelta(days=3), blocking_enabled=True)
    for days in (0, 2, 3):
        clock.now = T0 + timedelta(days=days)
        run(**cfg)
    clock.now = T0 + timedelta(days=3, hours=1)
    run(**cfg)
    assert store.list_open_violations()[0].last_checked_at == clock.now


def test_deleted_app_resolves(env):
    connect, store, _, clock, run = env
    connect.add("a", branch="dev")
    run()
    del connect.content["a"]
    clock.now = T0 + timedelta(hours=1)
    run()
    v = store.all()[0]
    assert v.status == STATUS_RESOLVED and v.resolution == RESOLUTION_DELETED


def test_unknown_branch_is_not_a_violation(env):
    connect, store, notifier, _, run = env
    connect.add("a", branch=None)
    summary = run(grace_period=timedelta(days=3), blocking_enabled=True)
    assert summary.unknown == 1 and store.all() == [] and notifier.sent == []


def test_one_failing_app_does_not_stop_the_scan(env):
    connect, store, _, _, run = env
    connect.add("a", branch="dev")
    connect.add("b", branch="dev")
    connect.users["broken"] = None  # get_user returns None -> AttributeError
    connect.content["a"]["owner_guid"] = "broken"
    summary = run()
    assert summary.errors == 1
    assert [v.content_guid for v in store.list_open_violations()] == ["b"]


def test_repository_api_error_is_unknown(env):
    connect, store, _, _, run = env
    connect.add("a", branch="dev")
    connect.repo_errors.add("a")
    summary = run()
    assert summary.unknown == 1 and store.all() == []


def test_auth_failure_aborts_scan(env):
    connect, _, _, _, run = env

    def denied():
        raise ConnectAuthError("401", 401)

    connect.list_content = denied
    with pytest.raises(ConnectAuthError):
        run()


def test_enforce_only_guids_limits_emails_and_locks(env):
    connect, _, notifier, clock, run = env
    connect.add("a", branch="dev")
    connect.add("b", branch="dev")
    cfg = dict(grace_period=timedelta(days=3), blocking_enabled=True, enforce_only_guids=frozenset({"b"}))
    for days in (0, 2, 3):
        clock.now = T0 + timedelta(days=days)
        run(**cfg)
    assert connect.lock_calls == [("b", True)]
    assert all("App-b" in s for s in subjects(notifier))


def test_app_locked_outside_job_is_left_alone(env):
    connect, _, _, clock, run = env
    connect.add("a", branch="dev")
    connect.content["a"]["locked"] = True
    for days in (0, 2, 5):
        clock.now = T0 + timedelta(days=days)
        run(grace_period=timedelta(days=3), blocking_enabled=True)
    assert connect.lock_calls == []


def test_unsupported_lock_response_is_not_recorded_as_locked(env):
    connect, store, _, clock, run = env
    connect.add("a", branch="dev")
    connect.set_locked = lambda guid, locked, message=None: {"guid": guid}  # no 'locked' field
    for days in (0, 2, 3):
        clock.now = T0 + timedelta(days=days)
        run(grace_period=timedelta(days=3), blocking_enabled=True)
    assert store.list_open_violations()[0].locked is False


def test_event_history_for_full_cycle(env):
    connect, store, _, clock, run = env
    connect.add("a", branch="dev")
    cfg = dict(grace_period=timedelta(days=3), blocking_enabled=True)
    for days in (0, 1, 2, 3):
        clock.now = T0 + timedelta(days=days)
        run(**cfg)
    connect.repos["a"]["branch"] = "feature/x"          # details change while locked
    connect.content["a"]["locked"] = False              # admin unlocks
    clock.now = T0 + timedelta(days=4); run(**cfg)
    connect.repos["a"]["branch"] = "main"                # owner fixes it
    clock.now = T0 + timedelta(days=4, hours=1); run(**cfg)
    assert store.events_for("a") == [
        "DETECTED", "FIRST_NOTICE_SENT", "FINAL_WARNING_SENT", "LOCKED", "LOCK_NOTICE_SENT",
        "DETAILS_CHANGED", "ADMIN_UNLOCKED", "FIX_WINDOW_NOTICE_SENT", "RESOLVED",
    ]
    changed = next(e for e in store.events if e["event_type"] == "DETAILS_CHANGED")
    assert changed["details"]["before"]["branch"] == "dev" and changed["details"]["after"]["branch"] == "feature/x"


def test_no_duplicate_events_on_repeat_runs(env):
    connect, store, _, clock, run = env
    connect.add("a", branch="dev")
    for minutes in (0, 15, 30, 45):
        clock.now = T0 + timedelta(minutes=minutes)
        run()
    assert store.events_for("a") == ["DETECTED", "FIRST_NOTICE_SENT"]


def test_content_inventory_tracks_every_app(env):
    connect, store, _, clock, run = env
    connect.add("ok")
    connect.add("bad", branch="dev")
    connect.add("plain", git=False)
    connect.add("unknown", branch=None)
    run()
    assert {g: r["status"] for g, r in store.content.items()} == {
        "ok": "COMPLIANT", "bad": "NON_COMPLIANT", "plain": "NOT_GIT_BACKED", "unknown": "UNKNOWN"}
    del connect.content["plain"]
    clock.now = T0 + timedelta(minutes=15)
    run()
    assert "plain" not in store.content


def test_failed_app_recorded_as_error_in_inventory(env):
    connect, store, _, _, run = env
    connect.add("a", branch="dev")
    connect.users["broken"] = None
    connect.content["a"]["owner_guid"] = "broken"
    run()
    assert store.content["a"]["status"] == "ERROR"


def test_instances_do_not_see_each_other():
    connect, notifier = FakeConnect(), FakeNotifier()
    connect.add("a", branch="dev")
    shared_rows = InMemoryStore("prod-internal")
    ComplianceJob(settings(), connect, shared_rows, notifier, now_fn=Clock()).run()
    # Same GUID scanned from another instance using the same storage object.
    shared_rows.instance = "qa-internal"
    ComplianceJob(settings(), connect, shared_rows, notifier, now_fn=Clock()).run()
    assert sorted(v.instance for v in shared_rows.all()) == ["prod-internal", "qa-internal"]
    assert len(notifier.sent) == 2


def test_excluded_app_is_skipped_and_violation_closed(env):
    connect, store, notifier, clock, run = env
    connect.add("a", branch="dev")
    connect.add("b", branch="dev")
    run()
    store.scope.add(("a", "EXCLUDED"))
    clock.now = T0 + timedelta(days=5)
    summary = run(grace_period=timedelta(days=3), blocking_enabled=True)
    assert summary.excluded == 1
    a = next(v for v in store.all() if v.content_guid == "a")
    assert a.status == STATUS_RESOLVED and a.resolution == "EXCLUDED_BY_ADMIN"
    assert store.content["a"]["status"] == "EXCLUDED"
    assert ("a", True) not in connect.lock_calls
    assert all("App-a" not in s for s in subjects(notifier)[2:])


def test_enforce_only_list_from_database(env):
    connect, store, notifier, clock, run = env
    connect.add("a", branch="dev")
    connect.add("b", branch="dev")
    store.scope.add(("b", "ENFORCE_ONLY"))
    for days in (0, 2, 3):
        clock.now = T0 + timedelta(days=days)
        run(grace_period=timedelta(days=3), blocking_enabled=True)
    assert connect.lock_calls == [("b", True)]
    assert all("App-b" in s for s in subjects(notifier))
    assert {v.content_guid for v in store.list_open_violations()} == {"a", "b"}  # both still tracked


def test_dry_run_sends_nothing_and_never_locks():
    connect, notifier = FakeConnect(), FakeNotifier()
    connect.add("a", branch="dev")
    s = settings(database_url="", blocking_enabled=True, grace_period=timedelta(days=3))
    assert s.dry_run and not s.blocking_effective
    clock = Clock()
    clock.now = T0 + timedelta(days=30)
    ComplianceJob(s, connect, InMemoryStore(), notifier, now_fn=clock).run()
    assert connect.lock_calls == []
