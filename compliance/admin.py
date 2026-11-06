"""Admin actions taken from the dashboard (Admin tab).

  * Lock / unlock one content item through the documented Connect API
    (PATCH /__api__/v1/content/{guid} with "locked" / "locked_message").
  * Maintain the scan-scope lists (Excluded / Enforce only).

Every action - successful or not - is written to the append-only
admin_actions table with the Connect user who performed it.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Protocol

from .connect_client import ConnectAPIError, ConnectNotFoundError
from .models import SCOPE_ENFORCE_ONLY, SCOPE_EXCLUDED

log = logging.getLogger("branch_compliance.admin")

GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
MAX_GUIDS_PER_REQUEST = 200
MAX_MESSAGE_LENGTH = 2000

DEFAULT_MANUAL_LOCK_MESSAGE = (
    "**This application has been locked by the Posit Connect administrators.**\n\n"
    "Please contact the application owner or the Posit Connect administrators."
)

ACTION_LOCK = "MANUAL_LOCK"
ACTION_UNLOCK = "MANUAL_UNLOCK"
SCOPE_ACTIONS = {
    (SCOPE_EXCLUDED, True): "EXCLUDE_ADD",
    (SCOPE_EXCLUDED, False): "EXCLUDE_REMOVE",
    (SCOPE_ENFORCE_ONLY, True): "ENFORCE_ONLY_ADD",
    (SCOPE_ENFORCE_ONLY, False): "ENFORCE_ONLY_REMOVE",
}


class AdminDB(Protocol):
    def record_admin_action(self, *, instance: str, actor: str, action: str, content_guid: str | None,
                            app_name: str | None, details: dict, success: bool,
                            error_message: str | None = None) -> None: ...
    def change_scope(self, *, instance: str, guids: list[str], list_type: str, add: bool,
                     actor: str, reason: str | None) -> int: ...


class ContentClient(Protocol):
    def get_content(self, guid: str) -> dict: ...
    def set_locked(self, guid: str, locked: bool, message: str | None = None) -> dict: ...


@dataclass(frozen=True)
class AdminResult:
    ok: bool
    message: str
    app_name: str | None = None


def parse_guids(text: str | None) -> tuple[list[str], list[str]]:
    """Split on commas/whitespace/semicolons. Returns (valid, invalid), deduplicated, lowercase."""
    valid, invalid = [], []
    for token in re.split(r"[\s,;]+", (text or "").strip()):
        if not token:
            continue
        guid = token.lower()
        target = valid if GUID_RE.match(guid) else invalid
        if guid not in target:
            target.append(guid)
    return valid, invalid


def describe_app(client: ContentClient, guid: str) -> dict:
    """Small summary of a content item for the confirmation dialog. Raises on errors."""
    app = client.get_content(guid)
    return {
        "guid": guid,
        "name": app.get("title") or app.get("name") or guid,
        "url": app.get("content_url"),
        "locked": app.get("locked"),
        "owner_guid": app.get("owner_guid"),
    }


def set_app_lock(client: ContentClient, db: AdminDB, *, instance: str, guid: str, lock: bool, actor: str,
                 message: str | None = None) -> AdminResult:
    """Lock or unlock one app and record the action. Never raises for API errors."""
    action = ACTION_LOCK if lock else ACTION_UNLOCK
    verb = "lock" if lock else "unlock"
    if not actor:
        return AdminResult(False, "Your Posit Connect user could not be identified, so the action is not allowed.")
    guid = (guid or "").strip().lower()
    if not GUID_RE.match(guid):
        return AdminResult(False, "Enter a valid content GUID (e.g. 1a2b3c4d-1111-2222-3333-444455556666).")
    message = (message or "").strip() or DEFAULT_MANUAL_LOCK_MESSAGE
    if len(message) > MAX_MESSAGE_LENGTH:
        return AdminResult(False, f"The lock message is limited to {MAX_MESSAGE_LENGTH} characters.")

    def record(success: bool, name: str | None, error: str | None = None, **details: Any) -> None:
        db.record_admin_action(instance=instance, actor=actor, action=action, content_guid=guid, app_name=name,
                               details=details, success=success, error_message=error)

    try:
        info = describe_app(client, guid)
    except ConnectNotFoundError:
        record(False, None, "content not found")
        return AdminResult(False, f"No content with GUID {guid} exists on this Connect server.")
    except ConnectAPIError as exc:
        record(False, None, str(exc)[:500])
        return AdminResult(False, f"Could not read the application from Connect: {exc}")

    name = info["name"]
    if info["locked"] is lock:
        record(True, name, None, already=True)
        return AdminResult(True, f"'{name}' is already {'locked' if lock else 'unlocked'}; nothing changed.", name)

    log.warning("Admin %s requested %s of %s (%s) on %s.", actor, verb, name, guid, instance)
    try:
        updated = client.set_locked(guid, lock, message if lock else None)
    except ConnectAPIError as exc:
        record(False, name, str(exc)[:500])
        return AdminResult(False, f"Connect rejected the {verb} request: {exc}", name)

    if not isinstance(updated, dict) or "locked" not in updated:
        record(False, name, "response had no 'locked' field")
        return AdminResult(False, "Connect did not confirm the change; content locking may be unsupported "
                                  "on this Connect version.", name)
    if updated["locked"] is not lock:
        record(False, name, f"Connect reports locked={updated['locked']}")
        return AdminResult(False, f"Connect reports locked={updated['locked']} after the request.", name)

    record(True, name, None, **({"locked_message": message} if lock else {}))
    note = "" if lock else (" If it is still non-compliant, the compliance job treats this as an admin unlock "
                            "and starts the fix window before locking it again.")
    return AdminResult(True, f"'{name}' was {'locked' if lock else 'unlocked'}.{note}", name)


def change_scope_list(db: AdminDB, *, instance: str, text: str, list_type: str, add: bool, actor: str,
                      reason: str | None = None) -> AdminResult:
    """Add or remove GUIDs from the Excluded / Enforce-only list and record the action."""
    if list_type not in (SCOPE_EXCLUDED, SCOPE_ENFORCE_ONLY):
        return AdminResult(False, "Unknown list.")
    if not actor:
        return AdminResult(False, "Your Posit Connect user could not be identified, so the change is not allowed.")
    if not instance:
        return AdminResult(False, "Choose an instance in the top bar first.")
    valid, invalid = parse_guids(text)
    if invalid:
        shown = ", ".join(invalid[:5]) + (" ..." if len(invalid) > 5 else "")
        return AdminResult(False, f"Not valid content GUIDs: {shown}. Nothing was changed.")
    if not valid:
        return AdminResult(False, "Enter one or more content GUIDs.")
    if len(valid) > MAX_GUIDS_PER_REQUEST:
        return AdminResult(False, f"At most {MAX_GUIDS_PER_REQUEST} GUIDs per change.")
    reason = (reason or "").strip()[:500] or None

    changed = db.change_scope(instance=instance, guids=valid, list_type=list_type, add=add, actor=actor, reason=reason)
    db.record_admin_action(instance=instance, actor=actor, action=SCOPE_ACTIONS[(list_type, add)], content_guid=None,
                           app_name=None, details={"guids": valid, "reason": reason, "changed": changed},
                           success=True)
    label = "Excluded" if list_type == SCOPE_EXCLUDED else "Enforce only"
    verb = "added to" if add else "removed from"
    log.info("Admin %s: %d GUID(s) %s the %s list on %s.", actor, changed, verb, label, instance)
    return AdminResult(True, f"{changed} of {len(valid)} app(s) {verb} the '{label}' list. "
                             "The change applies from the next scheduled run.")
