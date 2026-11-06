import pytest

from compliance.admin import (
    DEFAULT_MANUAL_LOCK_MESSAGE, change_scope_list, parse_guids, set_app_lock,
)
from compliance.connect_client import ConnectAPIError, ConnectNotFoundError
from compliance.models import SCOPE_ENFORCE_ONLY, SCOPE_EXCLUDED

G1 = "1a2b3c4d-1111-2222-3333-444455556666"
G2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class FakeClient:
    def __init__(self):
        self.apps = {G1: {"guid": G1, "title": "Poverty Dashboard", "content_url": "https://c/x/", "locked": False}}
        self.calls = []
        self.fail = False
        self.no_locked_field = False

    def get_content(self, guid):
        if guid not in self.apps:
            raise ConnectNotFoundError("404", 404)
        return dict(self.apps[guid])

    def set_locked(self, guid, locked, message=None):
        self.calls.append((guid, locked, message))
        if self.fail:
            raise ConnectAPIError("PATCH failed", 500)
        self.apps[guid]["locked"] = locked
        out = dict(self.apps[guid])
        if self.no_locked_field:
            out.pop("locked")
        return out


class FakeDB:
    def __init__(self):
        self.actions = []
        self.scope = set()

    def record_admin_action(self, **kw):
        self.actions.append(kw)

    def change_scope(self, *, instance, guids, list_type, add, actor, reason):
        before = len(self.scope)
        for g in guids:
            (self.scope.add if add else self.scope.discard)((instance, g, list_type))
        return abs(len(self.scope) - before)


@pytest.fixture
def env():
    return FakeClient(), FakeDB()


def test_parse_guids():
    valid, invalid = parse_guids(f" {G1.upper()}, {G2}\n{G1} ; not-a-guid ")
    assert valid == [G1, G2] and invalid == ["not-a-guid"]
    assert parse_guids("") == ([], [])


def test_lock_and_unlock_are_recorded(env):
    client, db = env
    r = set_app_lock(client, db, instance="prod-internal", guid=G1, lock=True, actor="admin1", message="")
    assert r.ok and client.calls == [(G1, True, DEFAULT_MANUAL_LOCK_MESSAGE)]
    assert db.actions[-1]["action"] == "MANUAL_LOCK" and db.actions[-1]["success"] is True
    assert db.actions[-1]["actor"] == "admin1" and db.actions[-1]["app_name"] == "Poverty Dashboard"

    r = set_app_lock(client, db, instance="prod-internal", guid=G1, lock=False, actor="admin1")
    assert r.ok and client.calls[-1] == (G1, False, None)
    assert db.actions[-1]["action"] == "MANUAL_UNLOCK"


def test_custom_lock_message(env):
    client, db = env
    set_app_lock(client, db, instance="i", guid=G1, lock=True, actor="a", message="  Back soon  ")
    assert client.calls[0][2] == "Back soon"


def test_already_locked_is_a_no_op(env):
    client, db = env
    client.apps[G1]["locked"] = True
    r = set_app_lock(client, db, instance="i", guid=G1, lock=True, actor="a")
    assert r.ok and "already locked" in r.message and client.calls == []
    assert db.actions[-1]["details"] == {"already": True}


@pytest.mark.parametrize("guid,actor,expected", [
    ("not-a-guid", "a", "valid content GUID"),
    (G1, "", "could not be identified"),
])
def test_input_validation(env, guid, actor, expected):
    client, db = env
    r = set_app_lock(client, db, instance="i", guid=guid, lock=True, actor=actor)
    assert not r.ok and expected in r.message and client.calls == [] and db.actions == []


def test_unknown_app_recorded_as_failure(env):
    client, db = env
    r = set_app_lock(client, db, instance="i", guid=G2, lock=True, actor="a")
    assert not r.ok and "No content" in r.message
    assert db.actions[-1]["success"] is False


def test_api_failure_recorded(env):
    client, db = env
    client.fail = True
    r = set_app_lock(client, db, instance="i", guid=G1, lock=True, actor="a")
    assert not r.ok and db.actions[-1]["success"] is False and "PATCH failed" in db.actions[-1]["error_message"]


def test_unsupported_lock_response(env):
    client, db = env
    client.no_locked_field = True
    r = set_app_lock(client, db, instance="i", guid=G1, lock=True, actor="a")
    assert not r.ok and "unsupported" in r.message and db.actions[-1]["success"] is False


def test_scope_add_remove_and_audit(env):
    _, db = env
    r = change_scope_list(db, instance="prod-internal", text=f"{G1}\n{G2}", list_type=SCOPE_EXCLUDED, add=True,
                          actor="admin1", reason="vendor app")
    assert r.ok and "2 of 2" in r.message
    assert db.actions[-1]["action"] == "EXCLUDE_ADD" and db.actions[-1]["details"]["guids"] == [G1, G2]
    r = change_scope_list(db, instance="prod-internal", text=G1, list_type=SCOPE_EXCLUDED, add=False, actor="admin1")
    assert r.ok and db.actions[-1]["action"] == "EXCLUDE_REMOVE"
    assert db.scope == {("prod-internal", G2, SCOPE_EXCLUDED)}
    change_scope_list(db, instance="prod-internal", text=G1, list_type=SCOPE_ENFORCE_ONLY, add=True, actor="a")
    assert db.actions[-1]["action"] == "ENFORCE_ONLY_ADD"


@pytest.mark.parametrize("kw,expected", [
    (dict(text="nope"), "Not valid content GUIDs"),
    (dict(text=""), "Enter one or more"),
    (dict(text=G1, instance=""), "Choose an instance"),
    (dict(text=G1, actor=""), "could not be identified"),
])
def test_scope_validation_changes_nothing(env, kw, expected):
    _, db = env
    args = dict(instance="i", text=G1, list_type=SCOPE_EXCLUDED, add=True, actor="a")
    args.update(kw)
    r = change_scope_list(db, **args)
    assert not r.ok and expected in r.message and db.scope == set() and db.actions == []
