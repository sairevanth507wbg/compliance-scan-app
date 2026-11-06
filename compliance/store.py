"""Storage: Azure PostgreSQL in production, in-memory for dry runs/tests.

Each Connect instance (Dev/QA/Prod, internal/external) normally has its own
database. Every row still carries `instance` (COMPLIANCE_INSTANCE), and each
job only reads/writes its own instance, so a shared database also works.

Tables (created on first run, CREATE ... IF NOT EXISTS):
  scan_runs              one row per job run, with counts
  branch_violations      one row per violation (current state)
  violation_events       append-only history of each violation
  content_compliance     latest status of every content item
  branch_violation_notes append-only admin notes (written by the dashboard)
The job never touches Connect's own database.
"""

from __future__ import annotations

import copy
import logging
from dataclasses import asdict
from datetime import datetime
from typing import Any, Protocol

from .models import (
    RUN_RUNNING, SCOPE_ENFORCE_ONLY, SCOPE_EXCLUDED, STATUS_OPEN, EventType, ScanScope, Violation,
)

log = logging.getLogger("branch_compliance.store")

TABLE = "branch_violations"
NOTES_TABLE = "branch_violation_notes"
EVENTS_TABLE = "violation_events"
RUNS_TABLE = "scan_runs"
CONTENT_TABLE = "content_compliance"
SCOPE_TABLE = "scan_scope"
ACTIONS_TABLE = "admin_actions"

# branch_violations columns except id, in a fixed order.
FIELDS = (
    "instance", "connect_server",
    "content_guid", "app_name", "app_url", "dashboard_url",
    "owner_guid", "owner_username", "owner_email",
    "repository", "detected_branch", "required_branch", "reasons", "status",
    "first_detected_at", "last_checked_at", "notified_at", "final_warning_at",
    "locked", "locked_at", "lock_notified_at", "admin_unlocked_at", "unlock_notified_at",
    "resolved_at", "resolution",
)

RUN_COUNTERS = (
    "scanned", "git_backed", "compliant", "non_compliant", "unknown", "not_git_backed", "excluded", "errors",
    "notifications_sent", "final_warnings_sent", "locked", "resolved",
)

DDL = """
CREATE SCHEMA IF NOT EXISTS {schema};

CREATE TABLE IF NOT EXISTS {runs} (
    id                   BIGSERIAL PRIMARY KEY,
    instance             TEXT        NOT NULL,
    connect_server       TEXT,
    started_at           TIMESTAMPTZ NOT NULL,
    finished_at          TIMESTAMPTZ,
    status               TEXT        NOT NULL CHECK (status IN ('RUNNING', 'SUCCEEDED', 'FAILED')),
    scanned              INTEGER,
    git_backed           INTEGER,
    compliant            INTEGER,
    non_compliant        INTEGER,
    unknown              INTEGER,
    not_git_backed       INTEGER,
    excluded             INTEGER,
    errors               INTEGER,
    notifications_sent   INTEGER,
    final_warnings_sent  INTEGER,
    locked               INTEGER,
    resolved             INTEGER,
    settings             TEXT,
    error_message        TEXT
);
CREATE INDEX IF NOT EXISTS scan_runs_instance_started ON {runs} (instance, started_at DESC);

CREATE TABLE IF NOT EXISTS {table} (
    id                  BIGSERIAL PRIMARY KEY,
    instance            TEXT        NOT NULL,
    connect_server      TEXT,
    content_guid        TEXT        NOT NULL,
    app_name            TEXT        NOT NULL,
    app_url             TEXT,
    dashboard_url       TEXT,
    owner_guid          TEXT,
    owner_username      TEXT,
    owner_email         TEXT,
    repository          TEXT,
    detected_branch     TEXT,
    required_branch     TEXT        NOT NULL,
    reasons             TEXT        NOT NULL,
    status              TEXT        NOT NULL CHECK (status IN ('NON_COMPLIANT', 'RESOLVED')),
    first_detected_at   TIMESTAMPTZ NOT NULL,
    last_checked_at     TIMESTAMPTZ NOT NULL,
    notified_at         TIMESTAMPTZ,
    final_warning_at    TIMESTAMPTZ,
    locked              BOOLEAN     NOT NULL DEFAULT FALSE,
    locked_at           TIMESTAMPTZ,
    lock_notified_at    TIMESTAMPTZ,
    admin_unlocked_at   TIMESTAMPTZ,
    unlock_notified_at  TIMESTAMPTZ,
    resolved_at         TIMESTAMPTZ,
    resolution          TEXT
);
-- At most one open violation per content item per instance.
CREATE UNIQUE INDEX IF NOT EXISTS branch_violations_one_open
    ON {table} (instance, content_guid) WHERE status = 'NON_COMPLIANT';
CREATE INDEX IF NOT EXISTS branch_violations_instance_status ON {table} (instance, status);

CREATE TABLE IF NOT EXISTS {events} (
    id            BIGSERIAL PRIMARY KEY,
    violation_id  BIGINT      NOT NULL REFERENCES {table} (id),
    run_id        BIGINT      REFERENCES {runs} (id),
    instance      TEXT        NOT NULL,
    content_guid  TEXT        NOT NULL,
    event_type    TEXT        NOT NULL,
    occurred_at   TIMESTAMPTZ NOT NULL,
    details       JSONB       NOT NULL DEFAULT '{{}}'::jsonb
);
CREATE INDEX IF NOT EXISTS violation_events_violation ON {events} (violation_id, occurred_at);
CREATE INDEX IF NOT EXISTS violation_events_instance_time ON {events} (instance, occurred_at DESC);

CREATE TABLE IF NOT EXISTS {content} (
    instance         TEXT        NOT NULL,
    content_guid     TEXT        NOT NULL,
    app_name         TEXT,
    app_url          TEXT,
    owner_guid       TEXT,
    repository       TEXT,
    branch           TEXT,
    status           TEXT        NOT NULL CHECK (status IN
                         ('COMPLIANT', 'NON_COMPLIANT', 'UNKNOWN', 'NOT_GIT_BACKED', 'ERROR', 'EXCLUDED')),
    detail           TEXT,
    last_checked_at  TIMESTAMPTZ NOT NULL,
    last_run_id      BIGINT      REFERENCES {runs} (id),
    PRIMARY KEY (instance, content_guid)
);

-- Admin notes written from the dashboard. Append-only: the dashboard role is
-- granted INSERT/SELECT only, so notes cannot be edited or deleted.
CREATE TABLE IF NOT EXISTS {notes} (
    id            BIGSERIAL PRIMARY KEY,
    violation_id  BIGINT      NOT NULL REFERENCES {table} (id),
    content_guid  TEXT        NOT NULL,
    author        TEXT        NOT NULL,
    note          TEXT        NOT NULL CHECK (char_length(note) BETWEEN 1 AND 4000),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS branch_violation_notes_violation ON {notes} (violation_id);

-- Lists maintained by admins in the dashboard (Admin tab).
CREATE TABLE IF NOT EXISTS {scope} (
    instance      TEXT        NOT NULL,
    content_guid  TEXT        NOT NULL,
    list_type     TEXT        NOT NULL CHECK (list_type IN ('EXCLUDED', 'ENFORCE_ONLY')),
    reason        TEXT,
    added_by      TEXT        NOT NULL,
    added_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (instance, content_guid, list_type)
);

-- Append-only audit log of admin actions taken in the dashboard.
CREATE TABLE IF NOT EXISTS {actions} (
    id             BIGSERIAL PRIMARY KEY,
    instance       TEXT        NOT NULL,
    actor          TEXT        NOT NULL,
    action         TEXT        NOT NULL,
    content_guid   TEXT,
    app_name       TEXT,
    details        JSONB       NOT NULL DEFAULT '{{}}'::jsonb,
    success        BOOLEAN     NOT NULL,
    error_message  TEXT,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS admin_actions_instance_time ON {actions} (instance, occurred_at DESC);
CREATE INDEX IF NOT EXISTS admin_actions_content ON {actions} (instance, content_guid);
"""


class ViolationStore(Protocol):
    instance: str

    def get_open_violation(self, content_guid: str) -> Violation | None: ...
    def list_open_violations(self) -> list[Violation]: ...
    def save(self, violation: Violation) -> Violation: ...
    def record_event(self, violation: Violation, event: EventType, occurred_at: datetime,
                     details: dict | None = None) -> None: ...
    def upsert_content_status(self, *, content_guid: str, app_name: str, app_url: str | None,
                              owner_guid: str | None, repository: str | None, branch: str | None,
                              status: str, detail: str | None, checked_at: datetime) -> None: ...
    def prune_content_status(self, seen_guids: set[str]) -> int: ...
    def load_scope(self) -> ScanScope: ...
    def start_run(self, connect_server: str, settings_summary: str, started_at: datetime) -> int: ...
    def finish_run(self, status: str, finished_at: datetime, summary: Any, error: str | None = None) -> None: ...
    def try_acquire_run_lock(self) -> bool: ...
    def close(self) -> None: ...


def _counters(summary: Any) -> dict[str, int]:
    data = asdict(summary) if summary is not None else {}
    return {k: data.get(k) for k in RUN_COUNTERS}


class InMemoryStore:
    """Used for dry runs (no DATABASE_URL) and unit tests."""

    def __init__(self, instance: str = "test") -> None:
        self.instance = instance
        self._rows: dict[int, Violation] = {}
        self._next_id = 1
        self.events: list[dict] = []
        self.content: dict[str, dict] = {}
        self.runs: list[dict] = []
        self.run_id: int | None = None
        self.scope: set[tuple[str, str]] = set()   # (content_guid, list_type)

    def load_scope(self) -> ScanScope:
        return ScanScope(
            excluded=frozenset(g for g, t in self.scope if t == SCOPE_EXCLUDED),
            enforce_only=frozenset(g for g, t in self.scope if t == SCOPE_ENFORCE_ONLY),
        )

    def get_open_violation(self, content_guid: str) -> Violation | None:
        for row in self._rows.values():
            if row.content_guid == content_guid and row.status == STATUS_OPEN and row.instance == self.instance:
                return copy.deepcopy(row)
        return None

    def list_open_violations(self) -> list[Violation]:
        return [copy.deepcopy(r) for r in self._rows.values()
                if r.status == STATUS_OPEN and r.instance == self.instance]

    def all(self) -> list[Violation]:
        return [copy.deepcopy(r) for r in self._rows.values()]

    def save(self, violation: Violation) -> Violation:
        violation.instance = violation.instance or self.instance
        if violation.id is None:
            violation.id = self._next_id
            self._next_id += 1
        self._rows[violation.id] = copy.deepcopy(violation)
        return violation

    def record_event(self, violation, event, occurred_at, details=None):
        self.events.append(dict(violation_id=violation.id, run_id=self.run_id, instance=self.instance,
                                content_guid=violation.content_guid, event_type=EventType(event).value,
                                occurred_at=occurred_at, details=dict(details or {})))

    def events_for(self, content_guid: str) -> list[str]:
        return [e["event_type"] for e in self.events if e["content_guid"] == content_guid]

    def upsert_content_status(self, *, content_guid, app_name, app_url, owner_guid, repository, branch,
                              status, detail, checked_at):
        self.content[content_guid] = dict(instance=self.instance, content_guid=content_guid, app_name=app_name,
                                          app_url=app_url, owner_guid=owner_guid, repository=repository,
                                          branch=branch, status=status, detail=detail,
                                          last_checked_at=checked_at, last_run_id=self.run_id)

    def prune_content_status(self, seen_guids):
        gone = [g for g in self.content if g not in seen_guids]
        for g in gone:
            del self.content[g]
        return len(gone)

    def start_run(self, connect_server, settings_summary, started_at):
        self.run_id = len(self.runs) + 1
        self.runs.append(dict(id=self.run_id, instance=self.instance, connect_server=connect_server,
                              started_at=started_at, finished_at=None, status=RUN_RUNNING,
                              settings=settings_summary, error_message=None))
        return self.run_id

    def finish_run(self, status, finished_at, summary, error=None):
        if self.run_id is None:
            return
        self.runs[self.run_id - 1].update(status=status, finished_at=finished_at, error_message=error,
                                          **_counters(summary))

    def try_acquire_run_lock(self) -> bool:
        return True

    def close(self) -> None:
        pass


class PostgresStore:
    def __init__(self, database_url: str, schema: str, instance: str):
        import psycopg  # imported lazily so dry runs/tests need no driver
        from psycopg import sql
        from psycopg.rows import dict_row
        from psycopg.types.json import Jsonb

        self.instance = instance
        self._sql = sql
        self._jsonb = Jsonb
        self._t = {name: sql.Identifier(schema, name)
                   for name in (TABLE, NOTES_TABLE, EVENTS_TABLE, RUNS_TABLE, CONTENT_TABLE,
                                SCOPE_TABLE, ACTIONS_TABLE)}
        self._lock_key = f"posit_branch_compliance:{schema}:{instance}"
        self.run_id: int | None = None
        extra = {} if "sslmode=" in database_url else {"sslmode": "require"}  # Azure requires TLS
        self._conn = psycopg.connect(database_url, autocommit=True, row_factory=dict_row,
                                     connect_timeout=15, application_name=f"posit-branch-compliance:{instance}",
                                     **extra)
        self._run_locked = False
        self._ensure_schema(schema)

    def _ensure_schema(self, schema: str) -> None:
        sql = self._sql
        statement = sql.SQL(DDL).format(
            schema=sql.Identifier(schema), table=self._t[TABLE], notes=self._t[NOTES_TABLE],
            events=self._t[EVENTS_TABLE], runs=self._t[RUNS_TABLE], content=self._t[CONTENT_TABLE],
            scope=self._t[SCOPE_TABLE], actions=self._t[ACTIONS_TABLE])
        with self._conn.cursor() as cur:
            cur.execute(statement)

    def _execute(self, query, params=()) -> Any:
        cur = self._conn.cursor()
        cur.execute(query, params)
        return cur

    # ----- violations ------------------------------------------------------

    def _row_to_violation(self, row: dict) -> Violation:
        data = {k: row[k] for k in FIELDS}
        data["reasons"] = [r for r in (row["reasons"] or "").split(",") if r]
        return Violation(id=row["id"], **data)

    def get_open_violation(self, content_guid: str) -> Violation | None:
        q = self._sql.SQL("SELECT * FROM {t} WHERE instance = %s AND content_guid = %s AND status = %s"
                          ).format(t=self._t[TABLE])
        row = self._execute(q, (self.instance, content_guid, STATUS_OPEN)).fetchone()
        return self._row_to_violation(row) if row else None

    def list_open_violations(self) -> list[Violation]:
        q = self._sql.SQL("SELECT * FROM {t} WHERE instance = %s AND status = %s ORDER BY id").format(t=self._t[TABLE])
        return [self._row_to_violation(r) for r in self._execute(q, (self.instance, STATUS_OPEN)).fetchall()]

    def save(self, violation: Violation) -> Violation:
        sql = self._sql
        violation.instance = violation.instance or self.instance
        values = [getattr(violation, f) for f in FIELDS]
        values[FIELDS.index("reasons")] = ",".join(violation.reasons)
        if violation.id is None:
            q = sql.SQL("INSERT INTO {t} ({cols}) VALUES ({vals}) RETURNING id").format(
                t=self._t[TABLE], cols=sql.SQL(", ").join(map(sql.Identifier, FIELDS)),
                vals=sql.SQL(", ").join(sql.Placeholder() * len(FIELDS)))
            violation.id = self._execute(q, values).fetchone()["id"]
        else:
            q = sql.SQL("UPDATE {t} SET {sets} WHERE id = %s").format(
                t=self._t[TABLE],
                sets=sql.SQL(", ").join(sql.SQL("{} = %s").format(sql.Identifier(f)) for f in FIELDS))
            self._execute(q, values + [violation.id])
        return violation

    def record_event(self, violation, event, occurred_at, details=None):
        q = self._sql.SQL("INSERT INTO {t} (violation_id, run_id, instance, content_guid, event_type, "
                          "occurred_at, details) VALUES (%s, %s, %s, %s, %s, %s, %s)").format(t=self._t[EVENTS_TABLE])
        self._execute(q, (violation.id, self.run_id, self.instance, violation.content_guid,
                          EventType(event).value, occurred_at, self._jsonb(details or {})))

    # ----- content inventory -------------------------------------------------

    def upsert_content_status(self, *, content_guid, app_name, app_url, owner_guid, repository, branch,
                              status, detail, checked_at):
        q = self._sql.SQL(
            "INSERT INTO {t} (instance, content_guid, app_name, app_url, owner_guid, repository, branch, "
            "status, detail, last_checked_at, last_run_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (instance, content_guid) DO UPDATE SET app_name = EXCLUDED.app_name, "
            "app_url = EXCLUDED.app_url, owner_guid = EXCLUDED.owner_guid, repository = EXCLUDED.repository, "
            "branch = EXCLUDED.branch, status = EXCLUDED.status, detail = EXCLUDED.detail, "
            "last_checked_at = EXCLUDED.last_checked_at, last_run_id = EXCLUDED.last_run_id"
        ).format(t=self._t[CONTENT_TABLE])
        self._execute(q, (self.instance, content_guid, app_name, app_url, owner_guid, repository, branch,
                          status, (detail or "")[:1000], checked_at, self.run_id))

    def prune_content_status(self, seen_guids):
        q = self._sql.SQL("DELETE FROM {t} WHERE instance = %s AND NOT (content_guid = ANY(%s))"
                          ).format(t=self._t[CONTENT_TABLE])
        return self._execute(q, (self.instance, list(seen_guids))).rowcount

    # ----- admin-maintained scan scope ----------------------------------------------

    def load_scope(self) -> ScanScope:
        q = self._sql.SQL("SELECT content_guid, list_type FROM {t} WHERE instance = %s").format(t=self._t[SCOPE_TABLE])
        rows = self._execute(q, (self.instance,)).fetchall()
        return ScanScope(
            excluded=frozenset(r["content_guid"] for r in rows if r["list_type"] == SCOPE_EXCLUDED),
            enforce_only=frozenset(r["content_guid"] for r in rows if r["list_type"] == SCOPE_ENFORCE_ONLY),
        )

    # ----- runs ------------------------------------------------------------------

    def start_run(self, connect_server, settings_summary, started_at):
        q = self._sql.SQL("INSERT INTO {t} (instance, connect_server, started_at, status, settings) "
                          "VALUES (%s, %s, %s, %s, %s) RETURNING id").format(t=self._t[RUNS_TABLE])
        self.run_id = self._execute(q, (self.instance, connect_server, started_at, RUN_RUNNING,
                                        settings_summary)).fetchone()["id"]
        return self.run_id

    def finish_run(self, status, finished_at, summary, error=None):
        if self.run_id is None:
            return
        counters = _counters(summary)
        sql = self._sql
        q = sql.SQL("UPDATE {t} SET status = %s, finished_at = %s, error_message = %s, {sets} WHERE id = %s").format(
            t=self._t[RUNS_TABLE],
            sets=sql.SQL(", ").join(sql.SQL("{} = %s").format(sql.Identifier(k)) for k in counters))
        self._execute(q, [status, finished_at, (error or None) and error[:2000], *counters.values(), self.run_id])

    # ----- concurrency / lifecycle -----------------------------------------------

    def try_acquire_run_lock(self) -> bool:
        """Stop two overlapping runs for the same instance from acting twice."""
        row = self._execute("SELECT pg_try_advisory_lock(hashtext(%s)) AS ok", (self._lock_key,)).fetchone()
        self._run_locked = bool(row["ok"])
        return self._run_locked

    def close(self) -> None:
        try:
            if self._run_locked:
                self._execute("SELECT pg_advisory_unlock(hashtext(%s))", (self._lock_key,))
        finally:
            self._conn.close()
