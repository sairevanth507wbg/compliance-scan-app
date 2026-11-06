"""Settings read from environment variables.

On Posit Connect, set these in the job's "Vars" panel. Secrets
(CONNECT_API_KEY / COMPLIANCE_CONNECT_API_KEY, DATABASE_URL, SMTP_PASSWORD)
are never logged or included in repr().
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Mapping

# The final warning is sent this long before an application is locked.
FINAL_WARNING_LEAD = timedelta(hours=24)

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off", ""}
_SCHEMA_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
_INSTANCE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,49}$")


class ConfigError(ValueError):
    """Raised when required configuration is missing or invalid."""


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


def _int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from exc


def _float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc


def _list(env: Mapping[str, str], name: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    raw = env.get(name)
    if raw is None:
        return default
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def parse_grace_period(value: str | None, unit: str | None) -> tuple[timedelta | None, str | None]:
    """Turn GRACE_PERIOD_VALUE / GRACE_PERIOD_UNIT into a timedelta.

    Returns (grace, problem). grace is None when no grace period is set or
    the value is invalid; in both cases the job never locks anything.
    The grace period must be longer than 24 hours so the final warning can
    always be sent 24 hours before locking.
    """
    value = (value or "").strip()
    unit = (unit or "days").strip().lower()
    if not value:
        return None, None
    try:
        amount = float(value)
    except ValueError:
        return None, f"GRACE_PERIOD_VALUE must be a number, got {value!r}"
    if unit in ("hour", "hours", "h"):
        grace = timedelta(hours=amount)
    elif unit in ("day", "days", "d"):
        grace = timedelta(days=amount)
    else:
        return None, f"GRACE_PERIOD_UNIT must be 'hours' or 'days', got {unit!r}"
    if grace <= FINAL_WARNING_LEAD:
        return None, (
            f"Grace period {value} {unit} is not longer than 24 hours; it must be, "
            "so owners get the final warning 24 hours before locking"
        )
    return grace, None


DEFAULT_LOCK_MESSAGE = (
    "**This application has been locked by the Posit Connect administrators.**\n\n"
    "Git-backed applications must be deployed from the `{required_branch}` branch of a "
    "repository in an approved {org_name}GitHub organization ({allowed_orgs}). "
    "This application did not meet that requirement within the remediation period.\n\n"
    "The application owner has been notified by email. "
    "Please contact the application owner or the Posit Connect administrators."
)


@dataclass(frozen=True)
class Settings:
    # Runs whenever Connect runs the job; use the Connect schedule to turn it
    # on/off. COMPLIANCE_SCAN_ENABLED=false is still honoured as an emergency stop.
    scan_enabled: bool = True

    # Label of the Connect instance; defaults to the host name of CONNECT_SERVER
    # (set automatically by Connect). Stored on every row and shown in emails.
    instance: str = ""

    connect_server: str = ""
    connect_api_key: str = field(default="", repr=False)
    verify_ssl: bool = True
    request_timeout_seconds: float = 30.0

    required_branch: str = "main"
    allowed_git_host: str = "github.com"
    # Required (no default): comma-separated GitHub organizations, set in Vars.
    allowed_git_orgs: tuple[str, ...] = ()
    # Optional organization name used in email/lock-message wording.
    org_display_name: str = ""

    # Informational: the real schedule is set in Posit Connect.
    scan_interval_minutes: int = 15

    grace_period: timedelta | None = None
    grace_period_problem: str | None = None
    relock_window: timedelta = timedelta(hours=4)

    email_enabled: bool = True
    blocking_enabled: bool = False
    dry_run_requested: bool = False
    # Filled at run time from the dashboard's "Enforce only" list (scan_scope
    # table). If set, emails and locking only apply to these content GUIDs;
    # everything else is still scanned and recorded.
    enforce_only_guids: frozenset[str] | None = None

    smtp_host: str = ""
    smtp_port: int = 25
    smtp_sender: str = ""
    smtp_sender_name: str = ""          # display name, e.g. "Posit Connect"
    smtp_starttls: bool = False
    smtp_username: str = ""
    smtp_password: str = field(default="", repr=False)
    admin_emails: tuple[str, ...] = ()

    database_url: str = field(default="", repr=False)
    db_schema: str = "posit_compliance"

    lock_message: str = DEFAULT_LOCK_MESSAGE

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env
        grace, problem = parse_grace_period(env.get("GRACE_PERIOD_VALUE"), env.get("GRACE_PERIOD_UNIT"))
        relock_hours = _float(env, "RELOCK_WINDOW_HOURS", 4.0)
        if relock_hours < 0:
            raise ConfigError("RELOCK_WINDOW_HOURS cannot be negative")
        return cls(
            scan_enabled=_bool(env, "COMPLIANCE_SCAN_ENABLED", True),
            instance=(env.get("COMPLIANCE_INSTANCE") or "").strip().lower(),
            connect_server=(env.get("CONNECT_SERVER") or "").strip(),
            # A dedicated admin key can be stored as COMPLIANCE_CONNECT_API_KEY
            # so it is not confused with the key Connect injects automatically.
            connect_api_key=(env.get("COMPLIANCE_CONNECT_API_KEY") or env.get("CONNECT_API_KEY") or "").strip(),
            verify_ssl=_bool(env, "CONNECT_VERIFY_SSL", True),
            request_timeout_seconds=_float(env, "CONNECT_TIMEOUT_SECONDS", 30.0),
            required_branch=(env.get("REQUIRED_BRANCH") or "main").strip(),
            allowed_git_host=(env.get("ALLOWED_GIT_HOST") or "github.com").strip().lower(),
            allowed_git_orgs=tuple(o.lower() for o in _list(env, "ALLOWED_GIT_ORGS")),
            org_display_name=(env.get("ORG_DISPLAY_NAME") or "").strip(),
            scan_interval_minutes=_int(env, "SCAN_INTERVAL_MINUTES", 15),
            grace_period=grace,
            grace_period_problem=problem,
            relock_window=timedelta(hours=relock_hours),
            email_enabled=_bool(env, "EMAIL_ENABLED", True),
            blocking_enabled=_bool(env, "BLOCKING_ENABLED", False),
            dry_run_requested=_bool(env, "DRY_RUN", False),
            smtp_host=(env.get("SMTP_HOST") or "").strip(),
            smtp_port=_int(env, "SMTP_PORT", 25),
            smtp_sender=(env.get("SMTP_SENDER") or "").strip(),
            smtp_sender_name=(env.get("SMTP_SENDER_NAME") or "").strip(),
            smtp_starttls=_bool(env, "SMTP_STARTTLS", False),
            smtp_username=(env.get("SMTP_USERNAME") or "").strip(),
            smtp_password=env.get("SMTP_PASSWORD") or "",
            admin_emails=_list(env, "ADMIN_EMAILS"),
            database_url=(env.get("DATABASE_URL") or "").strip(),
            db_schema=(env.get("DB_SCHEMA") or "posit_compliance").strip(),
            lock_message=env.get("LOCK_MESSAGE") or DEFAULT_LOCK_MESSAGE,
        )

    # ----- derived switches ---------------------------------------------

    @property
    def dry_run(self) -> bool:
        """Without a database the job cannot avoid duplicate emails or track
        grace periods, so it only detects and logs."""
        return self.dry_run_requested or not self.database_url

    @property
    def email_effective(self) -> bool:
        return self.email_enabled and not self.dry_run and bool(self.smtp_host and self.smtp_sender)

    @property
    def blocking_effective(self) -> bool:
        return self.blocking_enabled and not self.dry_run and self.grace_period is not None

    @property
    def instance_label(self) -> str:
        """COMPLIANCE_INSTANCE, or (dry runs only) the server host name."""
        if self.instance:
            return self.instance
        host = re.sub(r"^https?://", "", self.connect_server).split("/")[0].split(":")[0]
        return host.lower() or "unknown"

    def in_enforcement_scope(self, guid: str) -> bool:
        return self.enforce_only_guids is None or guid in self.enforce_only_guids

    def rendered_lock_message(self) -> str:
        orgs = ", ".join(f"{self.allowed_git_host}/{o}" for o in self.allowed_git_orgs)
        org_name = f"{self.org_display_name} " if self.org_display_name else ""
        try:
            return self.lock_message.format(required_branch=self.required_branch, allowed_orgs=orgs,
                                            org_name=org_name)
        except (KeyError, IndexError, ValueError):
            return self.lock_message

    def validate(self) -> None:
        problems = []
        if not self.connect_server:
            problems.append("CONNECT_SERVER is not set")
        if not self.connect_api_key:
            problems.append("COMPLIANCE_CONNECT_API_KEY (or CONNECT_API_KEY) is not set")
        if not self.required_branch:
            problems.append("REQUIRED_BRANCH is empty")
        if not self.allowed_git_orgs:
            problems.append("Allowed GitHub organizations are not set - fill them in on the dashboard's "
                            "Settings tab (ALLOWED_GIT_ORGS)")
        if not _SCHEMA_RE.match(self.db_schema):
            problems.append("DB_SCHEMA must be a simple identifier (letters, digits, underscore)")
        if self.instance and not _INSTANCE_RE.match(self.instance):
            problems.append("COMPLIANCE_INSTANCE must be lowercase letters, digits, '-' or '_' "
                            "(max 50), e.g. prod-internal")
        if problems:
            raise ConfigError("; ".join(problems))

    def describe(self) -> str:
        """One-line summary safe to log (no secrets)."""
        grace = "not set" if self.grace_period is None else str(self.grace_period)
        return (
            f"instance={self.instance_label} server={self.connect_server} required_branch={self.required_branch} "
            f"allowed={self.allowed_git_host}/{{{','.join(self.allowed_git_orgs)}}} "
            f"grace_period={grace} relock_window={self.relock_window} "
            f"email={'on' if self.email_effective else 'off'} "
            f"blocking={'on' if self.blocking_effective else 'off'} "
            f"dry_run={self.dry_run} "
            f"enforce_only={len(self.enforce_only_guids) if self.enforce_only_guids else 'all'}"
        )
