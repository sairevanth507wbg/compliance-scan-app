"""Demo backend for previewing the dashboard locally without PostgreSQL.

Enabled with DASHBOARD_DEMO=true. Data lives in an in-memory SQLite database
filled with sample data for several Connect instances; nothing is written to
disk. The SQL tab runs against SQLite (with the same read-only validation), so
PostgreSQL-only functions (split_part, make_interval, DISTINCT ON, FILTER on
some versions) are not available here.
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from .models import STATUS_OPEN, STATUS_RESOLVED
from .queries import (
    ACTION_COLUMNS, CONTENT_COLUMNS, RUN_COLUMNS, SCOPE_COLUMNS, VIOLATION_COLUMNS, ContentFilters, DashboardSettings, NoteRejected,
    QueryFailed, QueryResult, ViolationFilters, clean_note, validate_readonly_sql,
)

_URI = "file:compliance_demo?mode=memory&cache=shared"
# One dashboard per Connect instance, so the demo shows a single instance.
DEMO_INSTANCE = "prod-internal"
INSTANCES = (DEMO_INSTANCE,)
DEMO_ORGS = ("example-org", "example-labs")  # placeholder GitHub organizations

DEMO_SQL_EXAMPLES: dict[str, str] = {
    "Open violations (newest first)": (
        "SELECT id, instance, app_name, owner_username, repository, detected_branch, reasons,\n"
        "       first_detected_at, notified_at, final_warning_at, locked\n"
        "FROM branch_violations\n"
        "WHERE status = 'NON_COMPLIANT'\n"
        "ORDER BY first_detected_at DESC;"
    ),
    "Compliance by instance": (
        "SELECT instance, count(*) AS apps,\n"
        "       sum(status = 'COMPLIANT') AS compliant,\n"
        "       sum(status = 'NON_COMPLIANT') AS non_compliant,\n"
        "       sum(status = 'UNKNOWN') AS unknown,\n"
        "       sum(status = 'NOT_GIT_BACKED') AS not_git_backed\n"
        "FROM content_compliance\n"
        "GROUP BY instance ORDER BY instance;"
    ),
    "Open violations per owner": (
        "SELECT instance, owner_username, owner_email, count(*) AS open_violations, sum(locked) AS locked\n"
        "FROM branch_violations\n"
        "WHERE status = 'NON_COMPLIANT'\n"
        "GROUP BY instance, owner_username, owner_email\n"
        "ORDER BY open_violations DESC;"
    ),
    "Recent enforcement events": (
        "SELECT e.occurred_at, e.instance, v.app_name, e.event_type, e.details\n"
        "FROM violation_events e JOIN branch_violations v ON v.id = e.violation_id\n"
        "WHERE e.event_type IN ('FINAL_WARNING_SENT', 'LOCKED', 'LOCK_FAILED', 'ADMIN_UNLOCKED')\n"
        "ORDER BY e.occurred_at DESC;"
    ),
    "Failed runs": (
        "SELECT instance, started_at, error_message FROM scan_runs\n"
        "WHERE status = 'FAILED' ORDER BY started_at DESC;"
    ),
    "Notes with application": (
        "SELECT n.created_at, n.author, v.instance, v.app_name, n.note\n"
        "FROM branch_violation_notes n JOIN branch_violations v ON v.id = n.violation_id\n"
        "ORDER BY n.created_at DESC;"
    ),
    "Admin actions": (
        "SELECT occurred_at, instance, actor, action, app_name, content_guid, success, error_message\n"
        "FROM admin_actions ORDER BY occurred_at DESC;"
    ),
    "Excluded and enforce-only apps": (
        "SELECT s.instance, s.list_type, s.content_guid, c.app_name, s.reason, s.added_by, s.added_at\n"
        "FROM scan_scope s\n"
        "LEFT JOIN content_compliance c ON c.instance = s.instance AND c.content_guid = s.content_guid\n"
        "ORDER BY s.list_type, s.added_at DESC;"
    ),
}


def demo_guid(n: int) -> str:
    """Valid UUID-shaped GUID for sample apps."""
    return f"{n:08x}-0000-4000-8000-{n:012x}"


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _ts(value):
    return datetime.fromisoformat(value) if isinstance(value, str) and value else value


def _sample_violations(now: datetime) -> list[dict]:
    h = lambda n: now - timedelta(hours=n)  # noqa: E731
    d = lambda n: now - timedelta(days=n)   # noqa: E731
    # Placeholder hosts (RFC 2606 example.com); demo data never uses real servers.
    servers = {"prod-internal": "https://connect.example.com",
               "prod-external": "https://connect-ext.example.com",
               "qa-internal": "https://connect-qa.example.com",
               "dev-internal": "https://connect-dev.example.com"}
    org, labs = DEMO_ORGS

    def row(i, _env, name, owner, repo, branch, reasons, first, status=STATUS_OPEN, **extra):
        instance = DEMO_INSTANCE
        guid = f"{i:08x}-0000-4c1e-9a7b-{i:012x}"
        base = servers[instance]
        r = dict(
            instance=instance, connect_server=base, content_guid=guid, app_name=name,
            app_url=f"{base}/content/{guid}/", dashboard_url=f"{base}/connect/#/apps/{guid}",
            owner_guid=f"user-{owner}", owner_username=owner, owner_email=f"{owner}@example.com",
            repository=repo, detected_branch=branch, required_branch="main", reasons=reasons, status=status,
            first_detected_at=first, last_checked_at=h(0.1), notified_at=first, final_warning_at=None,
            locked=0, locked_at=None, lock_notified_at=None, admin_unlocked_at=None,
            unlock_notified_at=None, resolved_at=None, resolution=None,
        )
        r.update(extra)
        return r

    return [
        row(1, "prod-internal", "Poverty Dashboard", "asmith", f"https://github.com/{org}/poverty-dashboard",
            "feature/new-maps", "WRONG_BRANCH", h(2)),
        row(2, "prod-internal", "Climate Risk Explorer", "jdoe", f"https://github.com/{labs}/climate-risk",
            "dev", "WRONG_BRANCH", d(1)),
        row(3, "prod-external", "Debt Statistics API", "mkhan", "https://github.com/mkhan/debt-stats-api",
            "main", "UNAPPROVED_REPOSITORY", d(2), final_warning_at=d(0.5)),
        row(4, "prod-external", "Health Indicators", "lchen", "https://github.com/someorg/health-indicators",
            "test", "UNAPPROVED_REPOSITORY,WRONG_BRANCH", d(4), final_warning_at=d(2),
            locked=1, locked_at=d(1), lock_notified_at=d(1)),
        row(5, "prod-internal", "Education Atlas", "jdoe", f"https://github.com/{org}/education-atlas",
            "hotfix/2026-10", "WRONG_BRANCH", d(5), final_warning_at=d(3),
            admin_unlocked_at=h(1), unlock_notified_at=h(1)),
        row(6, "qa-internal", "Procurement Monitor", "rgarcia", f"https://github.com/{org}/procurement-monitor",
            "release-candidate", "WRONG_BRANCH", h(20)),
        row(7, "prod-internal", "Energy Access Tracker", "asmith", f"https://github.com/{labs}/energy-access",
            "feature/test", "WRONG_BRANCH", d(10), status=STATUS_RESOLVED, resolved_at=d(8),
            resolution="NOW_COMPLIANT"),
        row(8, "dev-internal", "Old Survey App", "pnair", "https://github.com/pnair/old-survey",
            "master", "UNAPPROVED_REPOSITORY,WRONG_BRANCH", d(20), status=STATUS_RESOLVED,
            resolved_at=d(3), resolution="CONTENT_DELETED"),
        row(9, "qa-internal", "Trade Flows", "mkhan", f"https://github.com/{org}/trade-flows",
            "develop", "WRONG_BRANCH", d(6), status=STATUS_RESOLVED, resolved_at=d(5), resolution="NOW_COMPLIANT"),
        row(10, "dev-internal", "Gender Data Portal", "lchen", f"https://github.com/{labs}/gender-portal",
            "feature/charts", "WRONG_BRANCH", h(0.3), notified_at=None, owner_email=None),
    ]


def _events_for(v: dict) -> list[tuple[datetime, str, dict]]:
    """Plausible history derived from the violation's timestamps."""
    ev = [(v["first_detected_at"], "DETECTED",
           {"repository": v["repository"], "branch": v["detected_branch"], "reasons": v["reasons"].split(",")})]
    if v["notified_at"]:
        ev.append((v["notified_at"] + timedelta(seconds=2), "FIRST_NOTICE_SENT", {"to": v["owner_email"]}))
    if v["final_warning_at"]:
        ev.append((v["final_warning_at"], "FINAL_WARNING_SENT", {}))
    if v["locked_at"] or v["admin_unlocked_at"]:
        locked_at = v["locked_at"] or v["admin_unlocked_at"] - timedelta(hours=20)
        ev.append((locked_at, "LOCKED", {}))
        ev.append((locked_at + timedelta(seconds=3), "LOCK_NOTICE_SENT", {}))
    if v["admin_unlocked_at"]:
        ev.append((v["admin_unlocked_at"], "ADMIN_UNLOCKED", {"fix_window_hours": 4}))
        ev.append((v["admin_unlocked_at"] + timedelta(seconds=2), "FIX_WINDOW_NOTICE_SENT", {}))
    if v["resolved_at"]:
        ev.append((v["resolved_at"], "RESOLVED", {"resolution": v["resolution"]}))
    return ev


class DemoDB:
    """Same interface as compliance.queries.DashboardDB."""

    def __init__(self, settings: DashboardSettings | None = None):
        self.s = settings or DashboardSettings()
        # Keep one connection open so the shared in-memory database survives.
        self._conn = sqlite3.connect(_URI, uri=True, check_same_thread=False)
        self._seed()

    # ----- seed data ------------------------------------------------------------

    def _seed(self) -> None:
        c = self._conn
        c.executescript("""
            DROP TABLE IF EXISTS branch_violation_notes;
            DROP TABLE IF EXISTS scan_scope;
            DROP TABLE IF EXISTS admin_actions;
            DROP TABLE IF EXISTS violation_events;
            DROP TABLE IF EXISTS content_compliance;
            DROP TABLE IF EXISTS scan_runs;
            DROP TABLE IF EXISTS branch_violations;
            CREATE TABLE branch_violations (
                id INTEGER PRIMARY KEY, instance TEXT, connect_server TEXT, content_guid TEXT, app_name TEXT,
                app_url TEXT, dashboard_url TEXT, owner_guid TEXT, owner_username TEXT, owner_email TEXT,
                repository TEXT, detected_branch TEXT, required_branch TEXT, reasons TEXT, status TEXT,
                first_detected_at TEXT, last_checked_at TEXT, notified_at TEXT, final_warning_at TEXT,
                locked INTEGER, locked_at TEXT, lock_notified_at TEXT, admin_unlocked_at TEXT,
                unlock_notified_at TEXT, resolved_at TEXT, resolution TEXT);
            CREATE TABLE violation_events (
                id INTEGER PRIMARY KEY, violation_id INTEGER, run_id INTEGER, instance TEXT, content_guid TEXT,
                event_type TEXT, occurred_at TEXT, details TEXT);
            CREATE TABLE scan_runs (
                id INTEGER PRIMARY KEY, instance TEXT, connect_server TEXT, started_at TEXT, finished_at TEXT,
                status TEXT, scanned INTEGER, git_backed INTEGER, compliant INTEGER, non_compliant INTEGER,
                unknown INTEGER, not_git_backed INTEGER, excluded INTEGER, errors INTEGER, notifications_sent INTEGER,
                final_warnings_sent INTEGER, locked INTEGER, resolved INTEGER, settings TEXT, error_message TEXT);
            CREATE TABLE content_compliance (
                instance TEXT, content_guid TEXT, app_name TEXT, app_url TEXT, owner_guid TEXT, repository TEXT,
                branch TEXT, status TEXT, detail TEXT, last_checked_at TEXT, last_run_id INTEGER,
                PRIMARY KEY (instance, content_guid));
            CREATE TABLE branch_violation_notes (
                id INTEGER PRIMARY KEY, violation_id INTEGER, content_guid TEXT, author TEXT, note TEXT,
                created_at TEXT);
            CREATE TABLE scan_scope (
                instance TEXT, content_guid TEXT, list_type TEXT, reason TEXT, added_by TEXT, added_at TEXT,
                PRIMARY KEY (instance, content_guid, list_type));
            CREATE TABLE admin_actions (
                id INTEGER PRIMARY KEY, instance TEXT, actor TEXT, action TEXT, content_guid TEXT, app_name TEXT,
                details TEXT, success INTEGER, error_message TEXT, occurred_at TEXT);
        """)
        now = datetime.now(timezone.utc)
        violations = _sample_violations(now)
        for vid, v in enumerate(violations, start=1):
            self._insert("branch_violations", {"id": vid, **v})
            for when, kind, details in _events_for(v):
                self._insert("violation_events", dict(violation_id=vid, instance=v["instance"],
                                                      content_guid=v["content_guid"], event_type=kind,
                                                      occurred_at=when, details=json.dumps(details)))

        # Inventory: open violations + a set of compliant / other apps per instance.
        extra = {DEMO_INSTANCE: (14, 2, 30)}
        for v in violations:
            if v["status"] == STATUS_OPEN:
                self._insert("content_compliance", dict(
                    instance=v["instance"], content_guid=v["content_guid"], app_name=v["app_name"],
                    app_url=v["app_url"], owner_guid=v["owner_guid"], repository=v["repository"],
                    branch=v["detected_branch"], status="NON_COMPLIANT", detail=v["reasons"], last_checked_at=now))
        n = 100
        for instance, (compliant, unknown, plain) in extra.items():
            for status, count in (("COMPLIANT", compliant), ("UNKNOWN", unknown), ("NOT_GIT_BACKED", plain)):
                for _ in range(count):
                    n += 1
                    git = status != "NOT_GIT_BACKED"
                    self._insert("content_compliance", dict(
                        instance=instance, content_guid=demo_guid(n), app_name=f"App {n}",
                        app_url=f"https://connect.example.com/content/{n}/", owner_guid=f"user-{n % 7}",
                        repository=f"https://github.com/{DEMO_ORGS[0]}/app-{n}" if git else None,
                        branch=("main" if status == "COMPLIANT" else None) if git else None, status=status,
                        detail={"COMPLIANT": "branch=main", "UNKNOWN": "Connect did not report a branch",
                                "NOT_GIT_BACKED": "not deployed from Git"}[status],
                        last_checked_at=now))

        # One app excluded by an admin on prod-internal, with its audit record.
        excluded_guid = demo_guid(101)
        c.execute("UPDATE content_compliance SET status = 'EXCLUDED', detail = 'excluded by an administrator' "
                  "WHERE content_guid = ?", (excluded_guid,))
        self._insert("scan_scope", dict(instance="prod-internal", content_guid=excluded_guid, list_type="EXCLUDED",
                                        reason="Vendor-managed app, tracked separately", added_by="posit-admin",
                                        added_at=now - timedelta(days=2)))
        self._insert("admin_actions", dict(instance="prod-internal", actor="posit-admin", action="EXCLUDE_ADD",
                                           content_guid=None, app_name=None, success=1, occurred_at=now - timedelta(days=2),
                                           details=json.dumps({"guids": [excluded_guid],
                                                               "reason": "Vendor-managed app, tracked separately"})))

        # Runs: last 3 hours every 15 minutes per instance; one failure on QA.
        for instance in INSTANCES:
            apps = c.execute("SELECT status, count(*) FROM content_compliance WHERE instance = ? GROUP BY status",
                             (instance,)).fetchall()
            counts = dict(apps)
            for k in range(12):
                started = now - timedelta(minutes=15 * k + 3)
                failed = k == 4
                self._insert("scan_runs", dict(
                    instance=instance, started_at=started, finished_at=started + timedelta(seconds=40),
                    status="FAILED" if failed else "SUCCEEDED",
                    scanned=0 if failed else sum(counts.values()),
                    git_backed=0 if failed else sum(counts.get(s, 0) for s in ("COMPLIANT", "NON_COMPLIANT", "UNKNOWN")),
                    compliant=0 if failed else counts.get("COMPLIANT", 0),
                    non_compliant=0 if failed else counts.get("NON_COMPLIANT", 0),
                    unknown=0 if failed else counts.get("UNKNOWN", 0),
                    not_git_backed=0 if failed else counts.get("NOT_GIT_BACKED", 0),
                    excluded=0 if failed else counts.get("EXCLUDED", 0), errors=0, notifications_sent=0, final_warnings_sent=0, locked=0, resolved=0,
                    error_message="ConnectAPIError: GET /v1/content failed: ConnectTimeout" if failed else None))

        c.execute("INSERT INTO branch_violation_notes (violation_id, content_guid, author, note, created_at) "
                  "SELECT id, content_guid, 'posit-admin', 'Owner contacted on Teams; they are moving the app "
                  "to an approved organization this week.', ? FROM branch_violations WHERE id = 3",
                  (_iso(now - timedelta(hours=5)),))
        c.commit()

    def _insert(self, table: str, row: dict) -> None:
        row = {k: (_iso(v) if isinstance(v, datetime) else v) for k, v in row.items()}
        self._conn.execute(f"INSERT INTO {table} ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                           list(row.values()))

    def _select(self, table: str, columns, where: str = "", params=()) -> list[dict]:
        cur = self._conn.execute(f"SELECT {', '.join(columns)} FROM {table} {where}", params)
        out = []
        for raw in cur.fetchall():
            rec = dict(zip(columns, raw))
            for k, val in rec.items():
                if k.endswith("_at"):
                    rec[k] = _ts(val)
            out.append(rec)
        return out

    # ----- DashboardDB interface -------------------------------------------------

    def fetch_violations(self, f: ViolationFilters, limit: int | None = None):
        now = datetime.now(timezone.utc)
        needle = f.search.strip().lower()
        out = []
        for r in self._select("branch_violations", VIOLATION_COLUMNS):
            r["locked"] = bool(r["locked"])
            if f.instance and r["instance"] != f.instance:
                continue
            if f.status == "open" and r["status"] != STATUS_OPEN:
                continue
            if f.status == "resolved" and r["status"] != STATUS_RESOLVED:
                continue
            if f.locked == "locked" and not r["locked"]:
                continue
            if f.locked == "unlocked" and r["locked"]:
                continue
            if needle and not any(needle in (r[c] or "").lower() for c in
                                  ("app_name", "content_guid", "owner_username", "owner_email", "repository")):
                continue
            if f.branch.strip() and f.branch.strip().lower() not in (r["detected_branch"] or "").lower():
                continue
            if f.detected_within_days and r["first_detected_at"] < now - timedelta(days=f.detected_within_days):
                continue
            out.append(r)
        out.sort(key=lambda r: r["first_detected_at"], reverse=True)
        out = out[: limit or self.s.sql_max_rows]
        return list(VIOLATION_COLUMNS), [tuple(r[c] for c in VIOLATION_COLUMNS) for r in out]

    def summary(self, instance: str = "") -> dict[str, int]:
        where, params = ("WHERE instance = ?", (instance,)) if instance else ("", ())
        rows = self._select("branch_violations", ("status", "locked", "final_warning_at", "resolved_at"), where, params)
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        open_rows = [r for r in rows if r["status"] == STATUS_OPEN]
        inventory = self._select("content_compliance", ("status",), where, params)
        return {
            "open": len(open_rows),
            "locked": sum(bool(r["locked"]) for r in open_rows),
            "pending_lock": sum(1 for r in open_rows if not r["locked"] and r["final_warning_at"]),
            "resolved_7d": sum(1 for r in rows if r["status"] == STATUS_RESOLVED and r["resolved_at"] >= week_ago),
            "apps": len(inventory),
            "compliant": sum(r["status"] == "COMPLIANT" for r in inventory),
            "git_backed": sum(r["status"] in ("COMPLIANT", "NON_COMPLIANT", "UNKNOWN") for r in inventory),
        }

    def list_instances(self) -> list[str]:
        cur = self._conn.execute("SELECT instance FROM scan_runs UNION SELECT instance FROM branch_violations ORDER BY 1")
        return [r[0] for r in cur.fetchall()]

    def list_events(self, violation_id: int, instance: str = "", content_guid: str = "") -> list[tuple]:
        rows = self._select("violation_events", ("occurred_at", "event_type", "details"),
                            "WHERE violation_id = ?", (violation_id,))
        events = [(r["occurred_at"], r["event_type"], json.loads(r["details"] or "{}")) for r in rows]
        actions = self._select("admin_actions", ("occurred_at", "action", "details", "actor", "success"),
                               "WHERE instance = ? AND content_guid = ?", (instance, content_guid))
        events += [(a["occurred_at"], a["action"],
                    {**json.loads(a["details"] or "{}"), "by": a["actor"], "success": bool(a["success"])})
                   for a in actions]
        return sorted(events, key=lambda e: e[0])

    # ----- admin tab -------------------------------------------------------------

    def list_scope(self, instance: str = ""):
        where, params = ("WHERE s.instance = ?", (instance,)) if instance else ("", ())
        cur = self._conn.execute(
            "SELECT s.instance, s.list_type, s.content_guid, c.app_name, s.reason, s.added_by, s.added_at "
            "FROM scan_scope s LEFT JOIN content_compliance c "
            f"ON c.instance = s.instance AND c.content_guid = s.content_guid {where} "
            "ORDER BY s.list_type, s.added_at DESC", params)
        rows = [tuple(_ts(v) if i == 6 else v for i, v in enumerate(r)) for r in cur.fetchall()]
        return list(SCOPE_COLUMNS), rows

    def change_scope(self, *, instance, guids, list_type, add, actor, reason) -> int:
        changed = 0
        for g in guids:
            if add:
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO scan_scope (instance, content_guid, list_type, reason, added_by, added_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)", (instance, g, list_type, reason, actor, _iso(datetime.now(timezone.utc))))
            else:
                cur = self._conn.execute("DELETE FROM scan_scope WHERE instance = ? AND list_type = ? AND content_guid = ?",
                                         (instance, list_type, g))
            changed += cur.rowcount
        self._conn.commit()
        return changed

    def record_admin_action(self, *, instance, actor, action, content_guid, app_name, details, success,
                            error_message=None) -> None:
        self._insert("admin_actions", dict(instance=instance, actor=actor, action=action, content_guid=content_guid,
                                           app_name=app_name, details=json.dumps(details or {}), success=int(success),
                                           error_message=error_message, occurred_at=datetime.now(timezone.utc)))
        self._conn.commit()

    def list_admin_actions(self, instance: str = "", limit: int = 200):
        where, params = ("WHERE instance = ?", (instance,)) if instance else ("", ())
        rows = self._select("admin_actions", ACTION_COLUMNS, f"{where} ORDER BY occurred_at DESC LIMIT {int(limit)}",
                            params)
        for r in rows:
            r["success"] = bool(r["success"])
        return list(ACTION_COLUMNS), [tuple(r[c] for c in ACTION_COLUMNS) for r in rows]

    def demo_connect(self) -> "DemoConnect":
        return DemoConnect(self)

    def fetch_runs(self, instance: str = "", limit: int = 200):
        where, params = ("WHERE instance = ?", (instance,)) if instance else ("", ())
        rows = self._select("scan_runs", RUN_COLUMNS, f"{where} ORDER BY started_at DESC LIMIT {int(limit)}", params)
        return list(RUN_COLUMNS), [tuple(r[c] for c in RUN_COLUMNS) for r in rows]

    def fetch_content(self, f: ContentFilters, limit: int | None = None):
        clauses, params = [], []
        if f.instance:
            clauses.append("instance = ?")
            params.append(f.instance)
        if f.status:
            clauses.append("status = ?")
            params.append(f.status)
        if f.search.strip():
            clauses.append("(lower(app_name) LIKE ? OR lower(content_guid) LIKE ? OR lower(coalesce(repository, '')) LIKE ?)")
            params.extend([f"%{f.search.strip().lower()}%"] * 3)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._select("content_compliance", CONTENT_COLUMNS,
                            f"{where} ORDER BY instance, status, app_name LIMIT {int(limit or self.s.sql_max_rows)}",
                            params)
        return list(CONTENT_COLUMNS), [tuple(r[c] for c in CONTENT_COLUMNS) for r in rows]

    def list_notes(self, violation_id: int) -> list[tuple]:
        rows = self._select("branch_violation_notes", ("created_at", "author", "note"),
                            "WHERE violation_id = ? ORDER BY created_at DESC", (violation_id,))
        return [(r["created_at"], r["author"], r["note"]) for r in rows]

    def add_note(self, violation_id: int, author: str, text: str) -> int:
        note = clean_note(text)
        if not author:
            raise NoteRejected("Your Posit Connect user could not be identified, so the note cannot be attributed.")
        cur = self._conn.execute(
            "INSERT INTO branch_violation_notes (violation_id, content_guid, author, note, created_at) "
            "SELECT id, content_guid, ?, ?, ? FROM branch_violations WHERE id = ?",
            (author, note, _iso(datetime.now(timezone.utc)), violation_id))
        self._conn.commit()
        if cur.rowcount != 1:
            raise NoteRejected("That violation no longer exists.")
        return cur.lastrowid

    def run_readonly_sql(self, text: str, user: str) -> QueryResult:
        query = validate_readonly_sql(text)
        started = time.monotonic()
        ro = sqlite3.connect(_URI, uri=True, check_same_thread=False)
        try:
            ro.execute("PRAGMA query_only = ON")
            cur = ro.execute(query)
            columns = [d[0] for d in cur.description] if cur.description else []
            rows = cur.fetchmany(self.s.sql_max_rows + 1) if columns else []
        except sqlite3.Error as exc:
            raise QueryFailed(f"Database error (demo/SQLite): {exc}") from exc
        finally:
            ro.close()
        truncated = len(rows) > self.s.sql_max_rows
        return QueryResult(columns, rows[: self.s.sql_max_rows], truncated, time.monotonic() - started)


class DemoConnect:
    """Stands in for ConnectClient in demo mode: lock state kept in memory."""

    def __init__(self, db: DemoDB):
        self._db = db
        self._locked: dict[str, bool] = {}
        for r in db._select("branch_violations", ("content_guid", "locked")):
            self._locked[r["content_guid"]] = bool(r["locked"])

    def get_content(self, guid: str) -> dict:
        from .connect_client import ConnectNotFoundError

        rows = self._db._select("content_compliance", ("content_guid", "app_name", "app_url", "owner_guid"),
                                "WHERE content_guid = ?", (guid,))
        if not rows:
            rows = self._db._select("branch_violations", ("content_guid", "app_name", "app_url", "owner_guid"),
                                    "WHERE content_guid = ?", (guid,))
        if not rows:
            raise ConnectNotFoundError("404", 404)
        r = rows[0]
        return {"guid": guid, "title": r["app_name"], "content_url": r["app_url"], "owner_guid": r["owner_guid"],
                "locked": self._locked.get(guid, False)}

    def set_locked(self, guid: str, locked: bool, message: str | None = None) -> dict:
        self.get_content(guid)
        self._locked[guid] = locked
        return {**self.get_content(guid), "locked_message": message}
