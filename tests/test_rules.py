from datetime import datetime, timedelta, timezone

import pytest

from compliance.config import ConfigError, Settings, parse_grace_period
from compliance.models import ComplianceStatus, GitInfo, Violation, ViolationReason
from compliance.rules import (
    EnforcementAction, check_branch_compliance, decide_enforcement, grace_period_expired,
    lock_due_at, normalize_branch, parse_repository_url,
)

T0 = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
ORGS = ("example-org", "example-labs")
S = Settings(allowed_git_orgs=ORGS)


def violation(**kw) -> Violation:
    base = dict(content_guid="g1", app_name="MyApp", required_branch="main", reasons=["WRONG_BRANCH"],
                first_detected_at=T0, last_checked_at=T0)
    base.update(kw)
    return Violation(**base)


# ----- repository / branch parsing -----------------------------------------

@pytest.mark.parametrize("url,org", [
    ("https://github.com/example-org/my-app", "example-org"),
    ("https://github.com/example-org/my-app.git", "example-org"),
    ("https://github.com/Example-Org/my-app/", "example-org"),
    ("https://token@github.com/example-labs/x.git", "example-labs"),
    ("git@github.com:example-labs/x.git", "example-labs"),
])
def test_parse_repository_url(url, org):
    ref = parse_repository_url(url)
    assert ref is not None and ref.host == "github.com" and ref.org == org


def test_parse_repository_url_rejects_garbage():
    assert parse_repository_url("not a url") is None
    assert parse_repository_url("https://github.com/example-org/repo/tree/main") is None
    assert parse_repository_url(None) is None


def test_normalize_branch():
    assert normalize_branch(" refs/heads/main ") == "main"
    assert normalize_branch("") is None
    assert normalize_branch(None) is None


# ----- compliance classification -------------------------------------------

def git(repo="https://github.com/example-org/app", branch="main"):
    return GitInfo(is_git_backed=True, repository=repo, branch=branch)


def test_main_on_approved_org_is_compliant():
    assert check_branch_compliance(git(), S).status is ComplianceStatus.COMPLIANT
    assert check_branch_compliance(git("https://github.com/example-labs/a"), S).status is ComplianceStatus.COMPLIANT


def test_wrong_branch_is_non_compliant():
    r = check_branch_compliance(git(branch="feature/test"), S)
    assert r.status is ComplianceStatus.NON_COMPLIANT
    assert r.reasons == (ViolationReason.WRONG_BRANCH,)


def test_branch_comparison_is_exact():
    assert check_branch_compliance(git(branch="Main"), S).status is ComplianceStatus.NON_COMPLIANT
    assert check_branch_compliance(git(branch="main-old"), S).status is ComplianceStatus.NON_COMPLIANT


@pytest.mark.parametrize("repo", [
    "https://github.com/someone/app",
    "https://github.com/example-org-fork/app",
    "https://gitlab.com/example-org/app",
    "https://example.com/not/a/github/path",
])
def test_unapproved_repository(repo):
    r = check_branch_compliance(git(repo=repo), S)
    assert r.status is ComplianceStatus.NON_COMPLIANT
    assert r.reasons == (ViolationReason.UNAPPROVED_REPOSITORY,)


def test_both_reasons():
    r = check_branch_compliance(git("https://github.com/someone/app", "dev"), S)
    assert set(r.reasons) == {ViolationReason.WRONG_BRANCH, ViolationReason.UNAPPROVED_REPOSITORY}


def test_missing_branch_is_unknown_not_violation():
    assert check_branch_compliance(git(branch=None), S).status is ComplianceStatus.UNKNOWN


def test_missing_branch_with_bad_repo_is_repo_violation_only():
    r = check_branch_compliance(git("https://github.com/someone/app", None), S)
    assert r.status is ComplianceStatus.NON_COMPLIANT
    assert r.reasons == (ViolationReason.UNAPPROVED_REPOSITORY,)


def test_missing_repo_or_failed_lookup_is_unknown():
    assert check_branch_compliance(git(repo=None), S).status is ComplianceStatus.UNKNOWN
    assert check_branch_compliance(GitInfo(None, error="500"), S).status is ComplianceStatus.UNKNOWN


def test_not_git_backed():
    assert check_branch_compliance(GitInfo(False), S).status is ComplianceStatus.NOT_GIT_BACKED


def test_custom_required_branch():
    s = Settings(required_branch="release", allowed_git_orgs=ORGS)
    assert check_branch_compliance(git(branch="release"), s).status is ComplianceStatus.COMPLIANT


# ----- configuration ---------------------------------------------------------

def test_grace_period_parsing():
    assert parse_grace_period("", "days") == (None, None)
    assert parse_grace_period("3", "days")[0] == timedelta(days=3)
    assert parse_grace_period("72", "hours")[0] == timedelta(hours=72)
    assert parse_grace_period("1.5", "d")[0] == timedelta(days=1.5)


@pytest.mark.parametrize("value,unit", [("24", "hours"), ("1", "days"), ("12", "hours"), ("x", "days"), ("3", "weeks")])
def test_grace_period_invalid_values_disable_locking(value, unit):
    grace, problem = parse_grace_period(value, unit)
    assert grace is None and problem


def test_safe_defaults():
    s = Settings.from_env({})
    assert s.scan_enabled is False
    assert s.blocking_enabled is False
    assert s.required_branch == "main"
    assert s.allowed_git_orgs == ()          # no built-in organizations: must come from Vars
    with pytest.raises(ConfigError, match="ALLOWED_GIT_ORGS"):
        Settings.from_env({"CONNECT_SERVER": "https://connect.example.com", "CONNECT_API_KEY": "k"}).validate()
    assert Settings.from_env({"ALLOWED_GIT_ORGS": " Example-Org , example-labs "}).allowed_git_orgs == ORGS
    assert s.grace_period is None
    assert s.dry_run is True  # no DATABASE_URL
    assert s.blocking_effective is False


def test_blocking_needs_database_and_grace():
    env = {"BLOCKING_ENABLED": "true", "GRACE_PERIOD_VALUE": "3"}
    assert Settings.from_env(env).blocking_effective is False  # no database
    env["DATABASE_URL"] = "postgresql://x"
    assert Settings.from_env(env).blocking_effective is True
    env["GRACE_PERIOD_VALUE"] = ""
    assert Settings.from_env(env).blocking_effective is False


def test_secrets_not_in_repr():
    s = Settings.from_env({"CONNECT_API_KEY": "SECRET1", "DATABASE_URL": "postgresql://u:SECRET2@h/db",
                           "SMTP_PASSWORD": "SECRET3"})
    text = repr(s) + s.describe()
    assert "SECRET" not in text


def test_dedicated_key_preferred():
    s = Settings.from_env({"CONNECT_API_KEY": "injected", "COMPLIANCE_CONNECT_API_KEY": "admin"})
    assert s.connect_api_key == "admin"


def test_instance_required_with_database():
    base = {"CONNECT_SERVER": "https://connect.example.com", "CONNECT_API_KEY": "k", "ALLOWED_GIT_ORGS": "example-org"}
    Settings.from_env(base).validate()                                   # dry run: optional
    assert Settings.from_env(base).instance_label == "connect.example.com"
    with pytest.raises(ConfigError, match="COMPLIANCE_INSTANCE"):
        Settings.from_env({**base, "DATABASE_URL": "postgresql://x"}).validate()
    s = Settings.from_env({**base, "DATABASE_URL": "postgresql://x", "COMPLIANCE_INSTANCE": " Prod-Internal "})
    s.validate()
    assert s.instance == "prod-internal"
    with pytest.raises(ConfigError, match="COMPLIANCE_INSTANCE"):
        Settings.from_env({**base, "COMPLIANCE_INSTANCE": "prod internal!"}).validate()


def test_bad_boolean_raises():
    with pytest.raises(ConfigError):
        Settings.from_env({"BLOCKING_ENABLED": "maybe"})


# ----- grace period / enforcement decisions ---------------------------------

GRACE = timedelta(days=3)
RELOCK = timedelta(hours=4)


def decide(v, now, blocking=True, grace=GRACE):
    return decide_enforcement(v, grace=grace, blocking_enabled=blocking, relock_window=RELOCK, now=now)


def test_grace_period_expired():
    v = violation()
    assert not grace_period_expired(v, GRACE, T0 + GRACE - timedelta(seconds=1))
    assert grace_period_expired(v, GRACE, T0 + GRACE)
    assert not grace_period_expired(v, None, T0 + timedelta(days=999))


def test_no_grace_never_locks():
    assert decide(violation(), T0 + timedelta(days=999), grace=None) is EnforcementAction.NO_GRACE_PERIOD


def test_blocking_disabled_never_locks():
    v = violation()
    assert decide(v, T0 + timedelta(days=1), blocking=False) is EnforcementAction.WITHIN_GRACE_PERIOD
    assert decide(v, T0 + timedelta(days=30), blocking=False) is EnforcementAction.BLOCKING_DISABLED


def test_final_warning_24h_before_deadline():
    v = violation()
    assert decide(v, T0 + timedelta(days=1)) is EnforcementAction.WITHIN_GRACE_PERIOD
    assert decide(v, T0 + GRACE - timedelta(hours=24)) is EnforcementAction.SEND_FINAL_WARNING


def test_lock_after_deadline_when_warned_on_time():
    warned = T0 + GRACE - timedelta(hours=24)
    v = violation(final_warning_at=warned)
    assert decide(v, T0 + GRACE - timedelta(minutes=1)) is EnforcementAction.WITHIN_GRACE_PERIOD
    assert decide(v, T0 + GRACE) is EnforcementAction.LOCK


def test_late_warning_still_gives_24_hours():
    # Blocking turned on long after detection: warning goes out now, lock 24h later.
    warned = T0 + timedelta(days=10)
    v = violation(final_warning_at=warned)
    assert decide(v, warned + timedelta(hours=23)) is EnforcementAction.AWAITING_FINAL_WARNING_LEAD
    assert decide(v, warned + timedelta(hours=24)) is EnforcementAction.LOCK
    assert lock_due_at(v, GRACE, RELOCK) == warned + timedelta(hours=24)


def test_no_lock_without_final_warning():
    assert decide(violation(), T0 + timedelta(days=30)) is EnforcementAction.SEND_FINAL_WARNING


def test_already_locked():
    assert decide(violation(locked=True), T0 + timedelta(days=30)) is EnforcementAction.ALREADY_LOCKED


def test_relock_after_admin_unlock_fix_window():
    unlocked = T0 + timedelta(days=5)
    v = violation(final_warning_at=T0 + timedelta(days=2), admin_unlocked_at=unlocked)
    assert decide(v, unlocked + timedelta(hours=3)) is EnforcementAction.WITHIN_FIX_WINDOW
    assert decide(v, unlocked + RELOCK) is EnforcementAction.LOCK
