"""Orchestration: scan -> classify -> record -> notify -> (optionally) lock."""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Callable

from .app_settings import merge_into_env
from .config import Settings
from .connect_client import ConnectAPIError, ConnectAuthError, ConnectClient, ConnectNotFoundError
from .models import (
    CONTENT_STATUS_ERROR, CONTENT_STATUS_EXCLUDED, RESOLUTION_COMPLIANT, RESOLUTION_DELETED, RESOLUTION_EXCLUDED,
    RESOLUTION_NOT_GIT, RUN_FAILED,
    RUN_SUCCEEDED, STATUS_RESOLVED, ComplianceResult, ComplianceStatus, EventType, GitInfo, Owner, Violation,
)
from .notifier import EmailNotifier, NoticeKind, build_message
from .rules import (
    EnforcementAction, check_branch_compliance, decide_enforcement, lock_due_at, normalize_branch,
)
from .rules import grace_period_expired as _grace_period_expired
from .store import InMemoryStore, PostgresStore, ViolationStore

log = logging.getLogger("branch_compliance")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class RunSummary:
    scanned: int = 0
    git_backed: int = 0
    compliant: int = 0
    non_compliant: int = 0
    unknown: int = 0
    not_git_backed: int = 0
    excluded: int = 0
    errors: int = 0
    notifications_sent: int = 0
    final_warnings_sent: int = 0
    locked: int = 0
    resolved: int = 0
    dry_run: bool = False
    skipped_reason: str | None = None


class ComplianceJob:
    def __init__(self, settings: Settings, client: ConnectClient, store: ViolationStore,
                 notifier: EmailNotifier, now_fn: Callable[[], datetime] = utcnow):
        self.settings = settings
        self.client = client
        self.store = store
        self.notifier = notifier
        self.now_fn = now_fn
        self.summary = RunSummary(dry_run=settings.dry_run)
        self._users: dict[str, Owner] = {}
        self.excluded: set[str] = set()

    # ----- 1. inventory ---------------------------------------------------

    def get_connect_apps(self) -> list[dict]:
        """All content visible to the admin key. Auth/API failures abort the run."""
        apps = self.client.list_content()
        log.info("Retrieved %d content items from Posit Connect.", len(apps))
        return apps

    # ----- 2. Git metadata ------------------------------------------------

    def get_git_information(self, app: dict) -> GitInfo:
        guid = app["guid"]
        try:
            repo = self.client.get_repository(guid)
        except ConnectAuthError:
            raise
        except ConnectAPIError as exc:
            return GitInfo(is_git_backed=None, error=f"repository lookup failed: {exc}")
        if not repo:
            return GitInfo(is_git_backed=False)
        return GitInfo(
            is_git_backed=True,
            repository=(repo.get("repository") or "").strip() or None,
            branch=normalize_branch(repo.get("branch")),
            directory=repo.get("directory"),
        )

    # ----- 3. rule ----------------------------------------------------------

    def check_branch_compliance(self, git: GitInfo) -> ComplianceResult:
        return check_branch_compliance(git, self.settings)

    def get_owner(self, app: dict) -> Owner:
        guid = app.get("owner_guid")
        if not guid:
            return Owner(guid=None)
        if guid not in self._users:
            try:
                user = self.client.get_user(guid)
                name = " ".join(p for p in (user.get("first_name"), user.get("last_name")) if p) or None
                self._users[guid] = Owner(guid, user.get("username"), user.get("email") or None, name)
            except ConnectAuthError:
                raise
            except ConnectAPIError as exc:
                log.warning("Could not look up owner %s: %s", guid, exc)
                self._users[guid] = Owner(guid=guid)
        return self._users[guid]

    # ----- 4. storage -------------------------------------------------------

    def record_violation(self, app: dict, owner: Owner, git: GitInfo, result: ComplianceResult,
                         now: datetime) -> Violation:
        guid = app["guid"]
        v = self.store.get_open_violation(guid)
        reasons = [r.value for r in result.reasons]
        is_new = v is None
        if v is None:
            v = Violation(content_guid=guid, app_name=_name(app), required_branch=self.settings.required_branch,
                          reasons=reasons, first_detected_at=now, last_checked_at=now)
            log.info("%s: new violation recorded (%s).", _name(app), ",".join(reasons))
        else:
            log.info("%s: still non-compliant since %s.", _name(app), v.first_detected_at.isoformat())
        before = (v.repository, v.detected_branch, ",".join(v.reasons))
        v.instance = self.store.instance  # single source of truth for the instance label
        v.connect_server = self.settings.connect_server
        v.app_name = _name(app)
        v.app_url = app.get("content_url") or v.app_url
        v.dashboard_url = app.get("dashboard_url") or v.dashboard_url
        v.owner_guid = owner.guid or v.owner_guid
        v.owner_username = owner.username or v.owner_username
        v.owner_email = owner.email or v.owner_email
        v.repository = git.repository
        v.detected_branch = git.branch
        v.required_branch = self.settings.required_branch
        v.reasons = reasons
        v.last_checked_at = now
        self.store.save(v)
        after = (v.repository, v.detected_branch, ",".join(v.reasons))
        if is_new:
            self._event(v, EventType.DETECTED, now, repository=v.repository, branch=v.detected_branch,
                        reasons=reasons)
        elif after != before:
            self._event(v, EventType.DETAILS_CHANGED, now,
                        before=dict(zip(("repository", "branch", "reasons"), before)),
                        after=dict(zip(("repository", "branch", "reasons"), after)))
        return v

    def _event(self, v: Violation, event: EventType, now: datetime, **details) -> None:
        self.store.record_event(v, event, now, details)

    def resolve_violation(self, v: Violation, now: datetime, resolution: str) -> None:
        v.status = STATUS_RESOLVED
        v.resolved_at = now
        v.resolution = resolution
        v.last_checked_at = now
        self.store.save(v)
        self._event(v, EventType.RESOLVED, now, resolution=resolution, still_locked=v.locked)
        self.summary.resolved += 1
        log.info("%s: violation RESOLVED (%s).", v.app_name, resolution)
        if v.locked:
            log.warning("%s: was locked by this job and remains locked. Automatic unlock is not performed; "
                        "an administrator must unlock it.", v.app_name)

    # ----- 5. email ---------------------------------------------------------

    def send_non_compliance_email(self, v: Violation, kind: NoticeKind = NoticeKind.FIRST_NOTICE,
                                  due: datetime | None = None) -> bool:
        if not self.settings.in_enforcement_scope(v.content_guid):
            log.info("%s: outside ENFORCE_ONLY_GUIDS; %s not sent.", v.app_name, kind.value)
            return False
        to = [v.owner_email] if v.owner_email else []
        if not to:
            log.warning("%s: owner has no email address; sending %s to admins only.", v.app_name, kind.value)
        cc = [] if kind is NoticeKind.FIRST_NOTICE and to else list(self.settings.admin_emails)
        sent = self.notifier.send(to, cc, build_message(kind, v, self.settings, due))
        if sent:
            log.info("%s: notification sent to application owner (%s).", v.app_name, kind.value)
        return sent

    # ----- 6. grace period --------------------------------------------------

    def grace_period_expired(self, v: Violation, now: datetime) -> bool:
        return _grace_period_expired(v, self.settings.grace_period, now)

    # ----- 7. lock ----------------------------------------------------------

    def block_connect_app(self, app: dict, v: Violation) -> bool:
        """Lock the content item. Every safety switch is re-checked here."""
        name, guid = _name(app), app["guid"]
        if not self.settings.blocking_effective:
            log.warning("Application %s remains non-compliant after the configured grace period. "
                        "Blocking is disabled; no enforcement action taken.", name)
            return False
        if not self.settings.in_enforcement_scope(guid):
            log.info("%s: outside ENFORCE_ONLY_GUIDS; not locking.", name)
            return False

        log.warning("%s exceeded grace period. Blocking application. guid=%s", name, guid)
        try:
            updated = self.client.set_locked(guid, True, self.settings.rendered_lock_message())
        except ConnectAuthError:
            raise
        except ConnectAPIError as exc:
            log.error("%s: lock request failed (%s). Will retry next run.", name, exc)
            return False
        if not isinstance(updated, dict) or "locked" not in updated:
            log.error("%s: Connect did not return a 'locked' field; content locking may be unsupported "
                      "on this Connect version. Not marking as locked.", name)
            return False
        if updated["locked"] is not True:
            log.error("%s: Connect reports locked=%s after the lock request.", name, updated["locked"])
            return False
        log.warning("%s: application LOCKED.", name)
        return True

    # ----- per-item processing ---------------------------------------------

    def process_app(self, app: dict) -> None:
        now = self.now_fn()
        name, guid = _name(app), app["guid"]
        self.summary.scanned += 1

        git = self.get_git_information(app)
        result = self.check_branch_compliance(git)
        open_v = self.store.get_open_violation(guid)
        self.store.upsert_content_status(
            content_guid=guid, app_name=name, app_url=app.get("content_url"), owner_guid=app.get("owner_guid"),
            repository=git.repository, branch=git.branch, status=result.status.value, detail=result.detail,
            checked_at=now)

        if result.status is ComplianceStatus.NOT_GIT_BACKED:
            self.summary.not_git_backed += 1
            log.debug("%s: not Git-backed; skipped.", name)
            if open_v:
                self.resolve_violation(open_v, now, RESOLUTION_NOT_GIT)
            return

        if result.status is ComplianceStatus.UNKNOWN:
            self.summary.unknown += 1
            log.warning("%s: compliance UNKNOWN (%s). Not treated as a violation; no action taken.",
                        name, result.detail)
            if open_v:
                open_v.last_checked_at = now
                self.store.save(open_v)
            return

        self.summary.git_backed += 1
        if result.status is ComplianceStatus.COMPLIANT:
            self.summary.compliant += 1
            log.info("%s is compliant. %s", name, result.detail)
            if open_v:
                self.resolve_violation(open_v, now, RESOLUTION_COMPLIANT)
            return

        # NON_COMPLIANT
        self.summary.non_compliant += 1
        log.warning("%s is non-compliant. %s", name, result.detail)
        v = self.record_violation(app, self.get_owner(app), git, result, now)

        # Lock state: detect an admin unlock, or a lock applied outside this job.
        if "locked" in app:
            app_locked = bool(app["locked"])
            if v.locked and not app_locked:
                v.locked = False
                v.admin_unlocked_at = now
                v.unlock_notified_at = None
                self.store.save(v)
                self._event(v, EventType.ADMIN_UNLOCKED, now,
                            fix_window_hours=self.settings.relock_window.total_seconds() / 3600)
                log.warning("%s: unlocked by an administrator. Fix window of %s started.",
                            name, self.settings.relock_window)
            elif app_locked and not v.locked:
                log.info("%s: already locked outside this job; no enforcement action.", name)
                return

        if v.notified_at is None and self.send_non_compliance_email(v, NoticeKind.FIRST_NOTICE):
            v.notified_at = now
            self.store.save(v)
            self._event(v, EventType.FIRST_NOTICE_SENT, now, to=v.owner_email)
            self.summary.notifications_sent += 1

        if v.admin_unlocked_at is not None and v.unlock_notified_at is None and not v.locked \
                and self.settings.blocking_effective:
            due = v.admin_unlocked_at + self.settings.relock_window
            if self.send_non_compliance_email(v, NoticeKind.UNLOCKED_FIX_WINDOW, due):
                v.unlock_notified_at = now
                self.store.save(v)
                self._event(v, EventType.FIX_WINDOW_NOTICE_SENT, now, relock_at=due.isoformat())
                self.summary.notifications_sent += 1

        self._enforce(app, v, now)

        if v.locked and v.lock_notified_at is None and self.send_non_compliance_email(v, NoticeKind.LOCKED):
            v.lock_notified_at = now
            self.store.save(v)
            self._event(v, EventType.LOCK_NOTICE_SENT, now)
            self.summary.notifications_sent += 1

    def _enforce(self, app: dict, v: Violation, now: datetime) -> None:
        s, name = self.settings, v.app_name
        action = decide_enforcement(v, grace=s.grace_period, blocking_enabled=s.blocking_effective,
                                    relock_window=s.relock_window, now=now)

        if action is EnforcementAction.ALREADY_LOCKED:
            log.info("%s: locked by this job since %s; waiting for an administrator.", name, v.locked_at)
        elif action is EnforcementAction.NO_GRACE_PERIOD:
            log.info("%s: no grace period configured (GRACE_PERIOD_VALUE empty or invalid); "
                     "no enforcement action taken.", name)
        elif action is EnforcementAction.WITHIN_GRACE_PERIOD:
            log.info("%s is still within the allowed remediation period (until %s).",
                     name, (v.first_detected_at + s.grace_period).isoformat())
        elif action is EnforcementAction.BLOCKING_DISABLED:
            log.warning("%s exceeded grace period, but enforcement is disabled. Application %s remains "
                        "non-compliant after the configured grace period. Blocking is disabled; "
                        "no enforcement action taken.", name, name)
        elif action is EnforcementAction.WITHIN_FIX_WINDOW:
            log.info("%s: within the post-unlock fix window (until %s).",
                     name, (v.admin_unlocked_at + s.relock_window).isoformat())
        elif action is EnforcementAction.AWAITING_FINAL_WARNING_LEAD:
            log.info("%s: grace period expired; final warning sent %s; lock at %s.", name,
                     v.final_warning_at.isoformat(), lock_due_at(v, s.grace_period, s.relock_window).isoformat())
        elif action is EnforcementAction.SEND_FINAL_WARNING:
            due = lock_due_at(v, s.grace_period, s.relock_window, warning_sent_at=now)
            if self.send_non_compliance_email(v, NoticeKind.FINAL_WARNING, due):
                v.final_warning_at = now
                self.store.save(v)
                self._event(v, EventType.FINAL_WARNING_SENT, now, lock_due_at=due.isoformat())
                self.summary.final_warnings_sent += 1
                log.warning("%s: final warning sent; lock scheduled for %s.", name, due.isoformat())
            else:
                log.warning("%s: final warning could not be sent, so locking is postponed "
                            "(owners must be warned before any lock).", name)
        elif action is EnforcementAction.LOCK:
            if self.block_connect_app(app, v):
                v.locked = True
                v.locked_at = now
                v.lock_notified_at = None
                v.admin_unlocked_at = None
                v.unlock_notified_at = None
                self.store.save(v)
                self._event(v, EventType.LOCKED, now)
                self.summary.locked += 1
            elif s.blocking_effective and s.in_enforcement_scope(v.content_guid):
                self._event(v, EventType.LOCK_FAILED, now)

    # ----- run --------------------------------------------------------------

    def _safe_process(self, app: dict) -> None:
        try:
            self.process_app(app)
        except ConnectAuthError:
            raise  # every following call would fail too
        except Exception as exc:
            self.summary.errors += 1
            log.exception("Failed to process %s (%s); continuing with the next application.",
                          _name(app), app.get("guid"))
            try:
                self.store.upsert_content_status(
                    content_guid=app["guid"], app_name=_name(app), app_url=app.get("content_url"),
                    owner_guid=app.get("owner_guid"), repository=None, branch=None,
                    status=CONTENT_STATUS_ERROR, detail=f"{type(exc).__name__}: {exc}"[:500],
                    checked_at=self.now_fn())
            except Exception:
                log.warning("Could not record ERROR status for %s.", app.get("guid"))

    def _apply_scope(self) -> None:
        """Load the admin-maintained lists (dashboard Admin tab)."""
        scope = self.store.load_scope()
        self.excluded = set(scope.excluded)
        if scope.enforce_only:
            self.settings = replace(self.settings, enforce_only_guids=frozenset(scope.enforce_only))
        if self.excluded or scope.enforce_only:
            log.info("Admin scan scope: %d excluded app(s); enforce-only list has %d app(s)%s.",
                     len(self.excluded), len(scope.enforce_only),
                     "" if scope.enforce_only else " (empty = enforce on all apps)")

    def _handle_excluded(self, app: dict) -> None:
        """Excluded apps are not checked, emailed or locked."""
        now, guid, name = self.now_fn(), app["guid"], _name(app)
        self.summary.excluded += 1
        log.info("%s: excluded from the scan by an administrator; skipped.", name)
        try:
            self.store.upsert_content_status(
                content_guid=guid, app_name=name, app_url=app.get("content_url"), owner_guid=app.get("owner_guid"),
                repository=None, branch=None, status=CONTENT_STATUS_EXCLUDED, detail="excluded by an administrator",
                checked_at=now)
            open_v = self.store.get_open_violation(guid)
            if open_v:
                self.resolve_violation(open_v, now, RESOLUTION_EXCLUDED)
        except Exception:
            self.summary.errors += 1
            log.exception("Failed to record exclusion for %s (%s).", name, guid)

    def run(self) -> RunSummary:
        self._apply_scope()
        seen: set[str] = set()
        for app in self.get_connect_apps():
            if app.get("guid"):
                seen.add(app["guid"])
                if app["guid"] in self.excluded:
                    self._handle_excluded(app)
                else:
                    self._safe_process(app)

        # Items with open violations that were not in the listing: locked
        # content may be hidden from listings, or the item may be deleted.
        for v in self.store.list_open_violations():
            if v.content_guid in seen:
                continue
            if v.content_guid in self.excluded:
                seen.add(v.content_guid)
                self.resolve_violation(v, self.now_fn(), RESOLUTION_EXCLUDED)
                continue
            try:
                app = self.client.get_content(v.content_guid)
            except ConnectNotFoundError:
                self.resolve_violation(v, self.now_fn(), RESOLUTION_DELETED)
                continue
            except ConnectAuthError:
                raise
            except Exception:
                self.summary.errors += 1
                seen.add(v.content_guid)  # keep its inventory row; we just could not check it
                log.exception("Could not re-check tracked item %s (%s).", v.app_name, v.content_guid)
                continue
            seen.add(v.content_guid)
            self._safe_process(app)

        # Inventory rows for content that no longer exists on this instance.
        removed = self.store.prune_content_status(seen)
        if removed:
            log.info("Removed %d deleted content items from the inventory.", removed)
        return self.summary


def _name(app: dict) -> str:
    return app.get("title") or app.get("name") or app.get("guid") or "<unnamed>"


def configure_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=level, stream=sys.stdout,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    root.setLevel(level)


def open_store(settings: Settings) -> ViolationStore:
    if settings.dry_run:
        return InMemoryStore(settings.instance_label)
    return PostgresStore(settings.database_url, settings.db_schema, settings.instance_label)


def compliance_job(settings: Settings | None = None) -> RunSummary:
    """Entry point used by the CLI and the scheduled Quarto document."""
    configure_logging()
    from_dashboard = settings is None
    settings = settings or Settings.from_env()

    if not settings.scan_enabled:
        log.info("COMPLIANCE_SCAN_ENABLED=false (emergency stop); scan skipped.")
        return RunSummary(skipped_reason="scan disabled")

    store = open_store(settings)   # creates the tables on first run
    try:
        if from_dashboard and not settings.dry_run:
            # Settings saved in the dashboard (Settings tab) override the environment.
            stored = store.load_settings()
            settings = Settings.from_env(merge_into_env(os.environ, stored))
            log.info("Loaded %d setting(s) from the dashboard.", len(stored))

        settings.validate()
        if settings.grace_period_problem:
            log.error("Grace period ignored: %s. No application will be locked.", settings.grace_period_problem)
        if settings.dry_run:
            log.warning("DRY RUN (no DATABASE_URL or DRY_RUN=true): detect and log only; no emails, no locking.")
        if settings.blocking_enabled and not settings.blocking_effective:
            log.warning("Locking is turned on but inactive (dry run or no valid grace period).")
        if not settings.email_effective and settings.email_enabled and not settings.dry_run:
            log.warning("Emails are on but the email server is not configured (Settings tab); no emails will be sent.")
        log.info("Starting branch compliance scan: %s", settings.describe())

        client = ConnectClient(settings.connect_server, settings.connect_api_key,
                               timeout=settings.request_timeout_seconds, verify_ssl=settings.verify_ssl)
        if not store.try_acquire_run_lock():
            log.warning("Another compliance run is in progress; this run exits without changes.")
            return RunSummary(dry_run=settings.dry_run, skipped_reason="another run in progress")
        store.start_run(settings.connect_server, settings.describe(), utcnow())
        job = ComplianceJob(settings, client, store, EmailNotifier(settings))
        try:
            summary = job.run()
        except Exception as exc:
            try:
                store.finish_run(RUN_FAILED, utcnow(), job.summary, f"{type(exc).__name__}: {exc}")
            except Exception:
                log.warning("Could not record the failed run in scan_runs.")
            raise
        store.finish_run(RUN_SUCCEEDED, utcnow(), summary)
    finally:
        store.close()

    log.info("Scan finished: %s", asdict(summary))
    return summary
