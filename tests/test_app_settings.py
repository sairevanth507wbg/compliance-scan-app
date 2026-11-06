from datetime import timedelta

import pytest

from compliance.app_settings import (
    GROUPS, SPECS, effective_values, merge_into_env, validate_settings,
)
from compliance.config import Settings


def test_every_setting_has_a_known_group_and_unique_key():
    assert len({s.key for s in SPECS}) == len(SPECS)
    assert {s.group for s in SPECS} <= set(GROUPS)
    assert GROUPS[0] == "Enforcement"              # most important first
    assert GROUPS[-1].startswith("Advanced")       # set-once/rare items last


def test_normalization():
    values, errors = validate_settings({
        "ALLOWED_GIT_ORGS": " Example-Org ; example-labs, example-org ",
        "ADMIN_EMAILS": "a@example.com b@example.com",
        "SMTP_PORT": "25", "SMTP_STARTTLS": False, "BLOCKING_ENABLED": "off",
        "GRACE_PERIOD_VALUE": "3", "GRACE_PERIOD_UNIT": "Days", "RELOCK_WINDOW_HOURS": "4.0",
    })
    assert errors == {}
    assert values["ALLOWED_GIT_ORGS"] == "example-org,example-labs"
    assert values["ADMIN_EMAILS"] == "a@example.com,b@example.com"
    assert values["SMTP_STARTTLS"] == "false" and values["BLOCKING_ENABLED"] == "false"
    assert values["GRACE_PERIOD_UNIT"] == "days" and values["RELOCK_WINDOW_HOURS"] == "4"


@pytest.mark.parametrize("values,key", [
    ({"ALLOWED_GIT_ORGS": ""}, "ALLOWED_GIT_ORGS"),
    ({"ALLOWED_GIT_ORGS": "https://github.com/x"}, "ALLOWED_GIT_ORGS"),
    ({"ADMIN_EMAILS": "not-an-email"}, "ADMIN_EMAILS"),
    ({"SMTP_PORT": "99999"}, "SMTP_PORT"),
    ({"SMTP_HOST": "https://smtp.example.com"}, "SMTP_HOST"),
    ({"GRACE_PERIOD_VALUE": "24", "GRACE_PERIOD_UNIT": "hours"}, "GRACE_PERIOD_VALUE"),
    ({"BLOCKING_ENABLED": "true", "GRACE_PERIOD_VALUE": ""}, "GRACE_PERIOD_VALUE"),
    ({"BLOCKING_ENABLED": "true", "GRACE_PERIOD_VALUE": "3", "EMAIL_ENABLED": "false"}, "EMAIL_ENABLED"),
])
def test_invalid_values_are_rejected(values, key):
    _, errors = validate_settings(values)
    assert key in errors


def test_database_settings_override_environment():
    env = {"CONNECT_SERVER": "https://connect.example.com", "CONNECT_API_KEY": "k", "DATABASE_URL": "postgresql://x",
           "ALLOWED_GIT_ORGS": "env-org", "SMTP_HOST": "env-smtp"}
    stored = {"ALLOWED_GIT_ORGS": "db-org", "GRACE_PERIOD_VALUE": "3", "BLOCKING_ENABLED": "true",
              "DATABASE_URL": "ignored-not-a-ui-setting"}
    s = Settings.from_env(merge_into_env(env, stored))
    assert s.allowed_git_orgs == ("db-org",)
    assert s.smtp_host == "env-smtp"                         # falls back to the environment
    assert s.grace_period == timedelta(days=3) and s.blocking_effective
    assert s.database_url == "postgresql://x"                # secrets never come from the table


def test_effective_values_precedence():
    eff = effective_values({"REQUIRED_BRANCH": "release"}, {"REQUIRED_BRANCH": "env", "SMTP_PORT": "2525"})
    assert eff["REQUIRED_BRANCH"] == "release"
    assert eff["SMTP_PORT"] == "2525"
    assert eff["GRACE_PERIOD_UNIT"] == "days"                # default


def test_instance_defaults_to_connect_host():
    s = Settings.from_env({"CONNECT_SERVER": "https://connect.example.com/", "CONNECT_API_KEY": "k",
                           "DATABASE_URL": "postgresql://x", "ALLOWED_GIT_ORGS": "example-org"})
    s.validate()                                             # no COMPLIANCE_INSTANCE needed
    assert s.instance_label == "connect.example.com"
    assert s.scan_enabled is True                            # on/off is the Connect schedule
