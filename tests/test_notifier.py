import smtplib
from datetime import datetime, timedelta, timezone

import pytest

from compliance.config import Settings
from compliance.models import Violation
from compliance.notifier import EmailNotifier, NoticeKind, build_message

T0 = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)


def violation(**kw):
    base = dict(content_guid="g-1", app_name="Poverty <Dashboard>", required_branch="main",
                reasons=["WRONG_BRANCH", "UNAPPROVED_REPOSITORY"], first_detected_at=T0, last_checked_at=T0,
                instance="prod-internal", connect_server="https://connect.example.com",
                app_url="https://connect.example.com/content/g-1/",
                dashboard_url="https://connect.example.com/connect/#/apps/g-1",
                owner_username="jdoe", owner_email="jdoe@example.com",
                repository="https://github.com/someone/app", detected_branch="feature/<x>")
    base.update(kw)
    return Violation(**base)


SETTINGS = Settings(admin_emails=("posit-admins@example.com",), database_url="postgresql://x",
                    blocking_enabled=True, grace_period=timedelta(days=3),
                    allowed_git_orgs=("example-org", "example-labs"), org_display_name="Example Org")


def test_org_name_comes_from_settings():
    c = build_message(NoticeKind.FIRST_NOTICE, violation(), SETTINGS)
    assert "approved Example Org GitHub organizations (github.com/example-org, github.com/example-labs)" in c.html
    generic = build_message(NoticeKind.FIRST_NOTICE, violation(), Settings(allowed_git_orgs=("acme",)))
    assert "approved GitHub organizations (github.com/acme)" in generic.text


@pytest.mark.parametrize("kind", list(NoticeKind))
def test_every_notice_has_html_and_text(kind):
    c = build_message(kind, violation(), SETTINGS, due=T0 + timedelta(days=3))
    assert c.subject.startswith("[prod-internal] ")
    assert c.html.startswith("<!DOCTYPE html>") and "</html>" in c.html
    for needle in ("https://connect.example.com/content/g-1/", "Open application", "github.com/example-org"):
        assert needle in c.html
    assert "https://connect.example.com/content/g-1/" in c.text
    assert "<" not in c.text.split("Hello")[0]  # text part is plain


def test_values_are_html_escaped():
    c = build_message(NoticeKind.FIRST_NOTICE, violation(), SETTINGS)
    assert "Poverty &lt;Dashboard&gt;" in c.html and "Poverty <Dashboard>" not in c.html
    assert "feature/&lt;x&gt;" in c.html


def test_unsafe_urls_are_not_linked():
    c = build_message(NoticeKind.FIRST_NOTICE, violation(app_url="javascript:alert(1)",
                                                           dashboard_url=None), SETTINGS)
    assert 'href="javascript' not in c.html
    assert "Open application" not in c.html


def test_first_notice_shows_deadline_when_blocking_on():
    c = build_message(NoticeKind.FIRST_NOTICE, violation(), SETTINGS)
    assert "Fix by 2026-11-04 10:00 UTC" in c.html


def test_final_warning_shows_lock_date():
    c = build_message(NoticeKind.FINAL_WARNING, violation(), SETTINGS, due=T0 + timedelta(days=3))
    assert "Locking on or after 2026-11-04 10:00 UTC" in c.html
    assert "will be locked on 2026-11-04 10:00 UTC" in c.subject


def test_smtp_message_is_multipart_alternative(monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def send_message(self, msg):
            sent.append(msg)

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    s = Settings(database_url="postgresql://x", smtp_host="smtp.example.com", smtp_sender="noreply@x")
    ok = EmailNotifier(s).send(["a@x"], ["b@x"], build_message(NoticeKind.LOCKED, violation(), s))
    assert ok
    msg = sent[0]
    assert msg.get_content_type() == "multipart/alternative"
    assert [p.get_content_type() for p in msg.iter_parts()] == ["text/plain", "text/html"]
    assert msg["Cc"] == "b@x"
    assert msg["From"] == "noreply@x"

    named = Settings(database_url="postgresql://x", smtp_host="smtp.example.com", smtp_sender="noreply@example.com",
                     smtp_sender_name="Posit Connect")
    EmailNotifier(named).send(["a@x"], [], build_message(NoticeKind.LOCKED, violation(), named))
    assert sent[1]["From"] == "Posit Connect <noreply@example.com>"
