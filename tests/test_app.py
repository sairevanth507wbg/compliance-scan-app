"""Smoke tests for the Shiny dashboard UI (no database needed)."""

import json

import pytest

pytest.importorskip("shiny")
from starlette.testclient import TestClient  # noqa: E402

import app as dashboard  # noqa: E402
from compliance.queries import DashboardSettings  # noqa: E402

ADMIN = {"RStudio-Connect-Credentials": json.dumps({"user": "admin1", "groups": ["posit-admins"]})}


class FakeDB:
    pass


def get(monkeypatch, headers=None, settings=DashboardSettings(), db=FakeDB(), problem=None):
    monkeypatch.setattr(dashboard, "SETTINGS", settings)
    monkeypatch.setattr(dashboard, "DB", db)
    monkeypatch.setattr(dashboard, "STARTUP_PROBLEM", problem)
    return TestClient(dashboard.app).get("/", headers=headers or {})


def test_dashboard_renders_for_admin(monkeypatch):
    resp = get(monkeypatch, ADMIN)
    assert resp.status_code == 200
    for text in ("Violations", "All apps", "Scan runs", "Admin", "Lock application", "Exclude from scan",
                 "SQL query",
                 "Signed in as admin1", "sql_text", "Open violations", "Git apps compliant"):
        assert text in resp.text


def test_no_instance_dropdown(monkeypatch):
    resp = get(monkeypatch, ADMIN)
    assert 'id="instance"' not in resp.text and "All instances" not in resp.text


def test_allow_list_blocks_other_users(monkeypatch):
    resp = get(monkeypatch, ADMIN, settings=DashboardSettings(allowed_groups=("other-group",)))
    assert "Access denied" in resp.text and "SQL query" not in resp.text


def test_missing_database_shows_message(monkeypatch):
    resp = get(monkeypatch, ADMIN, db=None, problem="No database is configured.")
    assert "Dashboard not configured" in resp.text
