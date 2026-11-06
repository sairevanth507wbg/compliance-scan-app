"""Plain data types shared by the job modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ComplianceStatus(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    # Git-backed (or possibly Git-backed) but repository/branch could not be
    # determined. Never treated as a violation.
    UNKNOWN = "UNKNOWN"
    NOT_GIT_BACKED = "NOT_GIT_BACKED"


class ViolationReason(str, Enum):
    WRONG_BRANCH = "WRONG_BRANCH"
    UNAPPROVED_REPOSITORY = "UNAPPROVED_REPOSITORY"


class EventType(str, Enum):
    """Rows in violation_events (append-only history of each violation)."""

    DETECTED = "DETECTED"
    DETAILS_CHANGED = "DETAILS_CHANGED"
    FIRST_NOTICE_SENT = "FIRST_NOTICE_SENT"
    FINAL_WARNING_SENT = "FINAL_WARNING_SENT"
    LOCKED = "LOCKED"
    LOCK_FAILED = "LOCK_FAILED"
    LOCK_NOTICE_SENT = "LOCK_NOTICE_SENT"
    ADMIN_UNLOCKED = "ADMIN_UNLOCKED"
    FIX_WINDOW_NOTICE_SENT = "FIX_WINDOW_NOTICE_SENT"
    RESOLVED = "RESOLVED"


# content_compliance.status also allows ERROR (processing the app failed) and
# EXCLUDED (an admin excluded the app from the scan).
CONTENT_STATUS_ERROR = "ERROR"
CONTENT_STATUS_EXCLUDED = "EXCLUDED"

# scan_scope.list_type: lists maintained by admins in the dashboard.
SCOPE_EXCLUDED = "EXCLUDED"          # never scanned, emailed or locked
SCOPE_ENFORCE_ONLY = "ENFORCE_ONLY"  # if any exist, emails/locks only for these


@dataclass(frozen=True)
class ScanScope:
    excluded: frozenset[str] = frozenset()
    enforce_only: frozenset[str] = frozenset()

# Values stored in scan_runs.status
RUN_RUNNING = "RUNNING"
RUN_SUCCEEDED = "SUCCEEDED"
RUN_FAILED = "FAILED"

# Values stored in branch_violations.status
STATUS_OPEN = "NON_COMPLIANT"
STATUS_RESOLVED = "RESOLVED"

# Values stored in branch_violations.resolution
RESOLUTION_COMPLIANT = "NOW_COMPLIANT"
RESOLUTION_NOT_GIT = "NO_LONGER_GIT_BACKED"
RESOLUTION_DELETED = "CONTENT_DELETED"
RESOLUTION_EXCLUDED = "EXCLUDED_BY_ADMIN"


@dataclass(frozen=True)
class GitInfo:
    """What Connect reports about an item's Git source.

    is_git_backed is None when the lookup itself failed (status UNKNOWN).
    """

    is_git_backed: bool | None
    repository: str | None = None
    branch: str | None = None
    directory: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class ComplianceResult:
    status: ComplianceStatus
    reasons: tuple[ViolationReason, ...] = ()
    detail: str = ""


@dataclass(frozen=True)
class Owner:
    guid: str | None
    username: str | None = None
    email: str | None = None
    display_name: str | None = None


@dataclass
class Violation:
    """One row of branch_violations. One open row per content item."""

    content_guid: str
    app_name: str
    required_branch: str
    reasons: list[str]
    first_detected_at: datetime
    last_checked_at: datetime
    instance: str = ""
    connect_server: str | None = None
    app_url: str | None = None
    dashboard_url: str | None = None
    owner_guid: str | None = None
    owner_username: str | None = None
    owner_email: str | None = None
    repository: str | None = None
    detected_branch: str | None = None
    status: str = STATUS_OPEN
    notified_at: datetime | None = None
    final_warning_at: datetime | None = None
    locked: bool = False
    locked_at: datetime | None = None
    lock_notified_at: datetime | None = None
    admin_unlocked_at: datetime | None = None
    unlock_notified_at: datetime | None = None
    resolved_at: datetime | None = None
    resolution: str | None = None
    id: int | None = field(default=None, compare=False)
