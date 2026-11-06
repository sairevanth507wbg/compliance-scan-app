"""Pure decision logic (no I/O). Everything here is unit-tested."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from .config import FINAL_WARNING_LEAD, Settings
from .models import ComplianceResult, ComplianceStatus, GitInfo, Violation, ViolationReason

# https://github.com/org/repo(.git), https://user@github.com/org/repo,
# git@github.com:org/repo.git, ssh://git@github.com/org/repo.git
_REPO_RE = re.compile(
    r"^(?:(?:https?|ssh|git)://)?(?:[^@/]+@)?(?P<host>[^/:]+)(?::\d+)?[/:]"
    r"(?P<org>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RepoRef:
    host: str
    org: str
    name: str


def parse_repository_url(url: str | None) -> RepoRef | None:
    if not url:
        return None
    match = _REPO_RE.match(url.strip())
    if not match:
        return None
    return RepoRef(match["host"].lower(), match["org"].lower(), match["repo"])


def normalize_branch(branch: str | None) -> str | None:
    if branch is None:
        return None
    branch = branch.strip()
    if branch.startswith("refs/heads/"):
        branch = branch[len("refs/heads/"):]
    return branch or None


def check_branch_compliance(git: GitInfo, settings: Settings) -> ComplianceResult:
    """Classify one item against the branch + approved-repository rule.

    A missing branch never produces a WRONG_BRANCH violation (status UNKNOWN
    instead). A repository outside the approved organizations is a violation
    on its own, because the URL itself is the evidence.
    """
    if git.is_git_backed is None:
        return ComplianceResult(ComplianceStatus.UNKNOWN, detail=git.error or "Git metadata lookup failed")
    if not git.is_git_backed:
        return ComplianceResult(ComplianceStatus.NOT_GIT_BACKED, detail="not deployed from Git")
    if not git.repository:
        return ComplianceResult(ComplianceStatus.UNKNOWN, detail="Connect did not report a repository URL")

    reasons: list[ViolationReason] = []
    details: list[str] = []

    ref = parse_repository_url(git.repository)
    if ref is None or ref.host != settings.allowed_git_host or ref.org not in settings.allowed_git_orgs:
        reasons.append(ViolationReason.UNAPPROVED_REPOSITORY)
        details.append(f"repository={git.repository} is not under an approved organization")

    branch = normalize_branch(git.branch)
    if branch is None:
        if not reasons:
            return ComplianceResult(ComplianceStatus.UNKNOWN, detail="Connect did not report a branch")
        details.append("branch=unknown")
    elif branch != settings.required_branch:
        reasons.append(ViolationReason.WRONG_BRANCH)
        details.append(f"detected_branch={branch} required_branch={settings.required_branch}")

    if reasons:
        return ComplianceResult(ComplianceStatus.NON_COMPLIANT, tuple(reasons), " ".join(details))
    return ComplianceResult(ComplianceStatus.COMPLIANT, detail=f"branch={branch}")


# ----- grace period / enforcement ------------------------------------------


def grace_period_expired(violation: Violation, grace: timedelta | None, now: datetime) -> bool:
    if grace is None:
        return False
    return now >= violation.first_detected_at + grace


class EnforcementAction(str, Enum):
    ALREADY_LOCKED = "ALREADY_LOCKED"
    NO_GRACE_PERIOD = "NO_GRACE_PERIOD"
    WITHIN_GRACE_PERIOD = "WITHIN_GRACE_PERIOD"
    BLOCKING_DISABLED = "BLOCKING_DISABLED"
    SEND_FINAL_WARNING = "SEND_FINAL_WARNING"
    AWAITING_FINAL_WARNING_LEAD = "AWAITING_FINAL_WARNING_LEAD"
    WITHIN_FIX_WINDOW = "WITHIN_FIX_WINDOW"
    LOCK = "LOCK"


def lock_due_at(violation: Violation, grace: timedelta, relock_window: timedelta,
                warning_sent_at: datetime | None = None) -> datetime:
    """When the item becomes eligible for locking.

    Normally first_detected + grace, but never earlier than 24 hours after
    the final warning, and after an admin unlock it is unlock + relock_window.
    """
    if violation.admin_unlocked_at is not None:
        return violation.admin_unlocked_at + relock_window
    due = violation.first_detected_at + grace
    warned = warning_sent_at or violation.final_warning_at
    if warned is not None:
        due = max(due, warned + FINAL_WARNING_LEAD)
    return due


def decide_enforcement(violation: Violation, *, grace: timedelta | None, blocking_enabled: bool,
                       relock_window: timedelta, now: datetime) -> EnforcementAction:
    if violation.locked:
        return EnforcementAction.ALREADY_LOCKED
    if grace is None:
        return EnforcementAction.NO_GRACE_PERIOD
    if not blocking_enabled:
        if grace_period_expired(violation, grace, now):
            return EnforcementAction.BLOCKING_DISABLED
        return EnforcementAction.WITHIN_GRACE_PERIOD

    if violation.admin_unlocked_at is not None:
        if now >= violation.admin_unlocked_at + relock_window:
            return EnforcementAction.LOCK
        return EnforcementAction.WITHIN_FIX_WINDOW

    deadline = violation.first_detected_at + grace
    if violation.final_warning_at is None:
        if now >= deadline - FINAL_WARNING_LEAD:
            return EnforcementAction.SEND_FINAL_WARNING
        return EnforcementAction.WITHIN_GRACE_PERIOD

    if now >= lock_due_at(violation, grace, relock_window):
        return EnforcementAction.LOCK
    if now >= deadline:
        return EnforcementAction.AWAITING_FINAL_WARNING_LEAD
    return EnforcementAction.WITHIN_GRACE_PERIOD
