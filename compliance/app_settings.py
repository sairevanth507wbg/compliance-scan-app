"""Settings that admins edit in the dashboard (Settings tab).

Values are stored in the app_settings table, keyed by the same names as the
environment variables (e.g. GRACE_PERIOD_VALUE). At the start of every run the
job merges them over the environment: database value > environment > default.
Only secrets and connection details stay in Connect "Vars":
DATABASE_URL / DASHBOARD_DATABASE_URL and COMPLIANCE_CONNECT_API_KEY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping

from .config import parse_grace_period

_EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")
_ORG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")


@dataclass(frozen=True)
class SettingSpec:
    key: str                  # also the environment variable name
    label: str
    group: str
    kind: str                 # bool | text | int | number | choice | list | emails | textarea
    default: str = ""
    help: str = ""
    choices: tuple[str, ...] = ()
    required: bool = False
    min_value: float | None = None
    max_value: float | None = None


GROUP_ENFORCEMENT = "Enforcement"
GROUP_POLICY = "Policy"
GROUP_NOTIFICATIONS = "Notifications"
GROUP_SMTP = "Email server (set once)"
GROUP_ADVANCED = "Advanced (rarely changed)"

# Order = order on screen: most important first, set-once items last.
GROUPS = (GROUP_ENFORCEMENT, GROUP_POLICY, GROUP_NOTIFICATIONS, GROUP_SMTP, GROUP_ADVANCED)

SPECS: tuple[SettingSpec, ...] = (
    SettingSpec("BLOCKING_ENABLED", "Lock non-compliant apps after the grace period", GROUP_ENFORCEMENT, "bool",
                "false", "Off = detect, record and email only; nothing is ever locked."),
    SettingSpec("GRACE_PERIOD_VALUE", "Grace period", GROUP_ENFORCEMENT, "number", "",
                "Must be more than 24 hours in total. Leave empty = never lock.", min_value=0),
    SettingSpec("GRACE_PERIOD_UNIT", "Grace period unit", GROUP_ENFORCEMENT, "choice", "days",
                choices=("days", "hours")),
    SettingSpec("RELOCK_WINDOW_HOURS", "Fix window after an admin unlocks (hours)", GROUP_ENFORCEMENT, "number", "4",
                "Time the owner gets to redeploy before the app is locked again.", min_value=0, max_value=720),
    SettingSpec("EMAIL_ENABLED", "Send emails", GROUP_ENFORCEMENT, "bool", "true",
                "Off = no emails (and therefore no locking, which requires the final warning)."),

    SettingSpec("ALLOWED_GIT_ORGS", "Approved GitHub organizations", GROUP_POLICY, "list", "",
                "Comma-separated, e.g. my-org, my-org-labs. Required.", required=True),
    SettingSpec("REQUIRED_BRANCH", "Required branch", GROUP_POLICY, "text", "main"),
    SettingSpec("ORG_DISPLAY_NAME", "Organization name (used in emails)", GROUP_POLICY, "text", "",
                "Optional, e.g. Example Org."),

    SettingSpec("ADMIN_EMAILS", "Admin email addresses", GROUP_NOTIFICATIONS, "emails", "",
                "Comma-separated. Copied on final warnings, lock and fix-window emails, and shown in the footer."),

    SettingSpec("SMTP_HOST", "SMTP host", GROUP_SMTP, "text", "", "Use the same relay as your Connect server."),
    SettingSpec("SMTP_PORT", "SMTP port", GROUP_SMTP, "int", "25", min_value=1, max_value=65535),
    SettingSpec("SMTP_STARTTLS", "Use STARTTLS", GROUP_SMTP, "bool", "false"),
    SettingSpec("SMTP_SENDER", "Sender address", GROUP_SMTP, "emails", "", "e.g. the no-reply address Connect uses."),
    SettingSpec("SMTP_SENDER_NAME", "Sender display name", GROUP_SMTP, "text", "", "e.g. Posit Connect"),
    SettingSpec("SMTP_USERNAME", "SMTP username", GROUP_SMTP, "text", "",
                "Only if your relay needs a login. The password stays in Connect Vars (SMTP_PASSWORD)."),

    SettingSpec("ALLOWED_GIT_HOST", "Git host", GROUP_ADVANCED, "text", "github.com"),
    SettingSpec("SCAN_INTERVAL_MINUTES", "Scan interval shown in emails (minutes)", GROUP_ADVANCED, "int", "15",
                "Wording only; the real schedule is set on the job in Connect.", min_value=1, max_value=1440),
    SettingSpec("LOCK_MESSAGE", "Message shown on locked apps (Markdown)", GROUP_ADVANCED, "textarea", "",
                "Leave empty for the built-in message."),
)

SPEC_BY_KEY = {s.key: s for s in SPECS}
BOOL_TRUE = "true"
BOOL_FALSE = "false"


def _normalize(spec: SettingSpec, raw) -> tuple[str, str | None]:
    """Return (stored value, error). Empty string means 'use the default'."""
    if spec.kind == "bool":
        if isinstance(raw, bool):
            return (BOOL_TRUE if raw else BOOL_FALSE), None
        value = str(raw or "").strip().lower()
        if value in ("true", "1", "yes", "on"):
            return BOOL_TRUE, None
        if value in ("false", "0", "no", "off", ""):
            return BOOL_FALSE, None
        return "", f"{spec.label}: must be on or off"

    value = "" if raw is None else str(raw).strip()
    if not value:
        return "", (f"{spec.label}: required" if spec.required else None)

    if spec.kind in ("int", "number"):
        try:
            number = int(value) if spec.kind == "int" else float(value)
        except ValueError:
            return "", f"{spec.label}: must be a {'whole ' if spec.kind == 'int' else ''}number"
        if spec.min_value is not None and number < spec.min_value:
            return "", f"{spec.label}: must be at least {spec.min_value:g}"
        if spec.max_value is not None and number > spec.max_value:
            return "", f"{spec.label}: must be at most {spec.max_value:g}"
        return (str(number) if spec.kind == "int" else f"{number:g}"), None
    if spec.kind == "choice":
        value = value.lower()
        return (value, None) if value in spec.choices else ("", f"{spec.label}: choose one of {', '.join(spec.choices)}")
    if spec.kind in ("list", "emails"):
        items = [i.strip() for i in re.split(r"[,;\s]+", value) if i.strip()]
        if spec.kind == "emails":
            bad = [i for i in items if not _EMAIL_RE.match(i)]
            if bad:
                return "", f"{spec.label}: not valid email addresses: {', '.join(bad)}"
        elif spec.key == "ALLOWED_GIT_ORGS":
            bad = [i for i in items if not _ORG_RE.match(i)]
            if bad:
                return "", f"{spec.label}: not valid GitHub organization names: {', '.join(bad)}"
            items = [i.lower() for i in items]
        return ",".join(dict.fromkeys(items)), None
    if spec.key in ("SMTP_HOST", "ALLOWED_GIT_HOST") and not _HOST_RE.match(value):
        return "", f"{spec.label}: host name only (no https:// or path)"
    if spec.kind == "textarea" and len(value) > 4000:
        return "", f"{spec.label}: at most 4000 characters"
    if spec.kind == "text" and len(value) > 200:
        return "", f"{spec.label}: at most 200 characters"
    return value, None


def validate_settings(values: Mapping[str, object]) -> tuple[dict[str, str], dict[str, str]]:
    """Normalize every known setting. Returns (normalized, errors keyed by setting)."""
    normalized: dict[str, str] = {}
    errors: dict[str, str] = {}
    for spec in SPECS:
        if spec.key not in values:
            continue
        value, error = _normalize(spec, values[spec.key])
        if error:
            errors[spec.key] = error
        else:
            normalized[spec.key] = value

    # Cross-field rules
    if "GRACE_PERIOD_VALUE" not in errors and normalized.get("GRACE_PERIOD_VALUE"):
        _, problem = parse_grace_period(normalized["GRACE_PERIOD_VALUE"], normalized.get("GRACE_PERIOD_UNIT", "days"))
        if problem:
            errors["GRACE_PERIOD_VALUE"] = "Grace period must be more than 24 hours in total"
    if normalized.get("BLOCKING_ENABLED") == BOOL_TRUE and not normalized.get("GRACE_PERIOD_VALUE"):
        errors.setdefault("GRACE_PERIOD_VALUE", "Set a grace period before turning on locking")
    if normalized.get("BLOCKING_ENABLED") == BOOL_TRUE and normalized.get("EMAIL_ENABLED") == BOOL_FALSE:
        errors.setdefault("EMAIL_ENABLED", "Locking needs emails on: owners must get the final warning first")
    return normalized, errors


def effective_values(stored: Mapping[str, str], env: Mapping[str, str]) -> dict[str, str]:
    """What the job will use for each UI setting: database > environment > default."""
    out = {}
    for spec in SPECS:
        if stored.get(spec.key, "") != "":
            out[spec.key] = stored[spec.key]
        elif env.get(spec.key, "") != "":
            out[spec.key] = str(env[spec.key])
        else:
            out[spec.key] = spec.default
    return out


def merge_into_env(env: Mapping[str, str], stored: Mapping[str, str]) -> dict[str, str]:
    """Environment mapping with database settings layered on top (for Settings.from_env)."""
    merged = dict(env)
    for key, value in stored.items():
        if key in SPEC_BY_KEY and value != "":
            merged[key] = value
    return merged
