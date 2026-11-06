"""Data access for the compliance dashboard.

Defense in depth for the SQL tab:
  1. validate_readonly_sql(): one statement only, must start with a read-only
     keyword, no write/DDL/transaction-control keywords.
  2. Every query runs inside BEGIN ... SET TRANSACTION READ ONLY, with
     statement_timeout and a row cap.
  3. The dashboard should use its own database role with SELECT on the
     compliance tables and INSERT on the notes table only (sql/roles.sql).
Every query is logged with the Connect user who ran it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Mapping

from .config import ConfigError, _float, _int, _list
from .models import STATUS_OPEN, STATUS_RESOLVED
from .store import (
    ACTIONS_TABLE, CONTENT_TABLE, EVENTS_TABLE, NOTES_TABLE, RUNS_TABLE, SCOPE_TABLE, SETTINGS_TABLE, TABLE,
)

log = logging.getLogger("branch_compliance.dashboard")

MAX_SQL_LENGTH = 20_000
MAX_NOTE_LENGTH = 4_000
_SCHEMA_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")

READ_ONLY_FIRST_WORDS = {"select", "with", "table", "values", "explain", "show"}
FORBIDDEN_WORDS = {
    "insert", "update", "delete", "merge", "upsert", "drop", "alter", "create", "truncate",
    "grant", "revoke", "copy", "call", "do", "set", "reset", "commit", "rollback", "begin",
    "start", "savepoint", "release", "vacuum", "analyze", "cluster", "reindex", "lock",
    "refresh", "listen", "notify", "unlisten", "prepare", "execute", "deallocate", "declare",
    "fetch", "move", "close", "discard", "load", "security", "comment", "import",
}

# Shown in the SQL tab's "Examples" list. Table names are unqualified because
# search_path is set to the compliance schema.
EXAMPLE_QUERIES: dict[str, str] = {
    "Open violations (newest first)": (
        "SELECT id, instance, app_name, owner_username, repository, detected_branch, reasons,\n"
        "       first_detected_at, notified_at, final_warning_at, locked\n"
        "FROM branch_violations\n"
        "WHERE status = 'NON_COMPLIANT'\n"
        "ORDER BY first_detected_at DESC;"
    ),
    "Compliance by instance": (
        "SELECT instance, count(*) AS apps,\n"
        "       count(*) FILTER (WHERE status = 'COMPLIANT') AS compliant,\n"
        "       count(*) FILTER (WHERE status = 'NON_COMPLIANT') AS non_compliant,\n"
        "       count(*) FILTER (WHERE status = 'UNKNOWN') AS unknown,\n"
        "       count(*) FILTER (WHERE status = 'NOT_GIT_BACKED') AS not_git_backed\n"
        "FROM content_compliance\n"
        "GROUP BY instance\n"
        "ORDER BY instance;"
    ),
    "Open violations per owner": (
        "SELECT instance, owner_username, owner_email, count(*) AS open_violations,\n"
        "       count(*) FILTER (WHERE locked) AS locked\n"
        "FROM branch_violations\n"
        "WHERE status = 'NON_COMPLIANT'\n"
        "GROUP BY instance, owner_username, owner_email\n"
        "ORDER BY open_violations DESC;"
    ),
    "Locked applications": (
        "SELECT instance, app_name, app_url, owner_email, locked_at, admin_unlocked_at\n"
        "FROM branch_violations\n"
        "WHERE locked\n"
        "ORDER BY locked_at DESC;"
    ),
    "Latest run per instance": (
        "SELECT DISTINCT ON (instance) instance, started_at, finished_at, status,\n"
        "       scanned, compliant, non_compliant, unknown, errors, locked, error_message\n"
        "FROM scan_runs\n"
        "ORDER BY instance, started_at DESC;"
    ),
    "Failed runs (last 7 days)": (
        "SELECT instance, started_at, error_message\n"
        "FROM scan_runs\n"
        "WHERE status = 'FAILED' AND started_at >= now() - interval '7 days'\n"
        "ORDER BY started_at DESC;"
    ),
    "Recent enforcement events": (
        "SELECT e.occurred_at, e.instance, v.app_name, e.event_type, e.details\n"
        "FROM violation_events e\n"
        "JOIN branch_violations v ON v.id = e.violation_id\n"
        "WHERE e.event_type IN ('FINAL_WARNING_SENT', 'LOCKED', 'LOCK_FAILED', 'ADMIN_UNLOCKED')\n"
        "ORDER BY e.occurred_at DESC\n"
        "LIMIT 200;"
    ),
    "Final warning sent, not yet locked": (
        "SELECT app_name, app_url, owner_email, final_warning_at\n"
        "FROM branch_violations\n"
        "WHERE status = 'NON_COMPLIANT' AND NOT locked AND final_warning_at IS NOT NULL\n"
        "ORDER BY final_warning_at;"
    ),
    "Violations by GitHub organization": (
        "SELECT lower(split_part(repository, '/', 4)) AS github_org, count(*) AS violations\n"
        "FROM branch_violations\n"
        "GROUP BY 1\n"
        "ORDER BY violations DESC;"
    ),
    "Resolved in the last 30 days": (
        "SELECT instance, app_name, resolution, first_detected_at, resolved_at,\n"
        "       resolved_at - first_detected_at AS time_to_fix\n"
        "FROM branch_violations\n"
        "WHERE status = 'RESOLVED' AND resolved_at >= now() - interval '30 days'\n"
        "ORDER BY resolved_at DESC;"
    ),
    "Admin actions (last 30 days)": (
        "SELECT occurred_at, instance, actor, action, app_name, content_guid, success, error_message\n"
        "FROM admin_actions\n"
        "WHERE occurred_at >= now() - interval '30 days'\n"
        "ORDER BY occurred_at DESC;"
    ),
    "Excluded and enforce-only apps": (
        "SELECT s.instance, s.list_type, s.content_guid, c.app_name, s.reason, s.added_by, s.added_at\n"
        "FROM scan_scope s\n"
        "LEFT JOIN content_compliance c ON c.instance = s.instance AND c.content_guid = s.content_guid\n"
        "ORDER BY s.list_type, s.added_at DESC;"
    ),
    "Notes with application": (
        "SELECT n.created_at, n.author, v.instance, v.app_name, n.note\n"
        "FROM branch_violation_notes n\n"
        "JOIN branch_violations v ON v.id = n.violation_id\n"
        "ORDER BY n.created_at DESC\n"
        "LIMIT 200;"
    ),
}


class QueryRejected(ValueError):
    """The query failed validation; message is safe to show to the user."""


class QueryFailed(RuntimeError):
    """The database rejected or could not run the query; message is safe to show."""


class NoteRejected(ValueError):
    pass


# ----- settings ---------------------------------------------------------------


@dataclass(frozen=True)
class DashboardSettings:
    database_url: str = ""
    db_schema: str = "posit_compliance"
    sql_timeout_seconds: float = 30.0
    sql_max_rows: int = 5000
    allowed_users: tuple[str, ...] = ()
    allowed_groups: tuple[str, ...] = ()
    local_user: str = ""
    # For lock/unlock from the Admin tab (same administrator key as the job).
    connect_server: str = ""
    connect_api_key: str = ""

    @property
    def instance(self) -> str:
        """Same label the job uses: COMPLIANCE_INSTANCE, else the host name of CONNECT_SERVER."""
        explicit = (os.environ.get("COMPLIANCE_INSTANCE") or "").strip().lower()
        if explicit:
            return explicit
        host = re.sub(r"^https?://", "", self.connect_server).split("/")[0].split(":")[0]
        return host.lower()

    def __repr__(self) -> str:  # never print the connection string or key
        return (f"DashboardSettings(schema={self.db_schema!r}, database_configured={bool(self.database_url)}, "
                f"connect_configured={bool(self.connect_server and self.connect_api_key)})")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "DashboardSettings":
        env = os.environ if env is None else env
        s = cls(
            # Prefer a dedicated least-privilege login for the dashboard.
            database_url=(env.get("DASHBOARD_DATABASE_URL") or env.get("DATABASE_URL") or "").strip(),
            db_schema=(env.get("DB_SCHEMA") or "posit_compliance").strip(),
            sql_timeout_seconds=_float(env, "SQL_TIMEOUT_SECONDS", 30.0),
            sql_max_rows=_int(env, "SQL_MAX_ROWS", 5000),
            allowed_users=tuple(u.lower() for u in _list(env, "DASHBOARD_ALLOWED_USERS")),
            allowed_groups=tuple(g.lower() for g in _list(env, "DASHBOARD_ALLOWED_GROUPS")),
            local_user=(env.get("DASHBOARD_LOCAL_USER") or "").strip(),
            connect_server=(env.get("CONNECT_SERVER") or "").strip(),
            connect_api_key=(env.get("COMPLIANCE_CONNECT_API_KEY") or env.get("CONNECT_API_KEY") or "").strip(),
        )
        if not _SCHEMA_RE.match(s.db_schema):
            raise ConfigError("DB_SCHEMA must be a simple identifier")
        if not (1 <= s.sql_timeout_seconds <= 300):
            raise ConfigError("SQL_TIMEOUT_SECONDS must be between 1 and 300")
        if not (1 <= s.sql_max_rows <= 100_000):
            raise ConfigError("SQL_MAX_ROWS must be between 1 and 100000")
        return s


# ----- who is viewing --------------------------------------------------------


@dataclass(frozen=True)
class ConnectUser:
    username: str
    groups: tuple[str, ...] = ()


def parse_connect_user(header_value: str | None) -> ConnectUser | None:
    """Posit Connect passes the logged-in viewer to Python apps in the
    'RStudio-Connect-Credentials' header as JSON: {"user": ..., "groups": [...]}."""
    if not header_value:
        return None
    try:
        data = json.loads(header_value)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("user"):
        return None
    groups = data.get("groups") or []
    return ConnectUser(str(data["user"]), tuple(str(g) for g in groups if g))


def is_authorized(user: ConnectUser | None, settings: DashboardSettings) -> bool:
    """Extra check on top of Connect's access list. With no allow-list
    configured, access is governed by Connect alone."""
    if not settings.allowed_users and not settings.allowed_groups:
        return True
    if user is None:
        return False
    if user.username.lower() in settings.allowed_users:
        return True
    return any(g.lower() in settings.allowed_groups for g in user.groups)


# ----- SQL validation ----------------------------------------------------------

_DOLLAR_TAG = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")


def _mask_literals_and_comments(text: str) -> str:
    """Replace comments with spaces and string literals / quoted identifiers /
    dollar-quoted strings with NUL characters (same length), so keywords and
    semicolons can be checked. NUL (not space) keeps literals from being
    trimmed away as trailing whitespace."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j == -1:
                raise QueryRejected("Unterminated /* comment.")
            j += 2
        elif c in ("'", '"'):
            # E'...' strings allow backslash escapes.
            escape = c == "'" and i > 0 and text[i - 1] in "eE" and (i < 2 or not (text[i - 2].isalnum() or text[i - 2] == "_"))
            j = i + 1
            while True:
                if j >= n:
                    raise QueryRejected("Unterminated quoted string.")
                if escape and text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    if j + 1 < n and text[j + 1] == c:
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
        elif c == "$" and (m := _DOLLAR_TAG.match(text, i)) and not (i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_")):
            tag = m.group(0)
            j = text.find(tag, m.end())
            if j == -1:
                raise QueryRejected("Unterminated dollar-quoted string.")
            j += len(tag)
        else:
            out.append(c)
            i += 1
            continue
        out.append((" " if c in "-/" else "\0") * (j - i))
        i = j
    return "".join(out)


def validate_readonly_sql(text: str) -> str:
    """Return the single read-only statement to run, or raise QueryRejected."""
    if not text or not text.strip():
        raise QueryRejected("Enter a query.")
    if len(text) > MAX_SQL_LENGTH:
        raise QueryRejected(f"Query is longer than {MAX_SQL_LENGTH} characters.")
    masked = _mask_literals_and_comments(text)

    end = len(masked.rstrip())
    while end > 0 and masked[end - 1] == ";":
        end = len(masked[: end - 1].rstrip())
    body = masked[:end]
    if ";" in body:
        raise QueryRejected("Only one statement can be run at a time.")
    words = re.findall(r"[A-Za-z_]+", body)
    if not words:
        raise QueryRejected("Enter a query.")
    if words[0].lower() not in READ_ONLY_FIRST_WORDS:
        raise QueryRejected("Only read-only queries are allowed (SELECT, WITH, TABLE, VALUES, EXPLAIN, SHOW).")
    bad = sorted({w.upper() for w in words if w.lower() in FORBIDDEN_WORDS})
    if bad:
        raise QueryRejected(f"Not allowed in the query tab: {', '.join(bad)}.")
    return text[:end].strip()


# ----- violation filters --------------------------------------------------------


@dataclass(frozen=True)
class ViolationFilters:
    instance: str = ""              # "" = all instances
    status: str = "open"            # open | resolved | all
    locked: str = "all"             # all | locked | unlocked
    search: str = ""                # app name, GUID, owner, email, repository
    branch: str = ""
    detected_within_days: int | None = None


VIOLATION_COLUMNS = (
    "id", "instance", "app_name", "status", "locked", "owner_username", "owner_email", "repository",
    "detected_branch", "required_branch", "reasons", "first_detected_at", "last_checked_at",
    "notified_at", "final_warning_at", "locked_at", "admin_unlocked_at", "resolved_at",
    "resolution", "app_url", "dashboard_url", "content_guid",
)


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def build_violations_query(schema: str, f: ViolationFilters, limit: int):
    """Parameterised query for the Violations tab. Returns (Composed, params)."""
    from psycopg import sql

    conditions: list[Any] = []
    params: list[Any] = []
    if f.instance:
        conditions.append(sql.SQL("instance = %s"))
        params.append(f.instance)
    if f.status == "open":
        conditions.append(sql.SQL("status = %s"))
        params.append(STATUS_OPEN)
    elif f.status == "resolved":
        conditions.append(sql.SQL("status = %s"))
        params.append(STATUS_RESOLVED)
    if f.locked == "locked":
        conditions.append(sql.SQL("locked"))
    elif f.locked == "unlocked":
        conditions.append(sql.SQL("NOT locked"))
    if f.search.strip():
        cols = ("app_name", "content_guid", "owner_username", "owner_email", "repository")
        conditions.append(sql.SQL("({})").format(
            sql.SQL(" OR ").join(sql.SQL("{} ILIKE %s").format(sql.Identifier(c)) for c in cols)))
        params.extend([_like(f.search.strip())] * len(cols))
    if f.branch.strip():
        conditions.append(sql.SQL("detected_branch ILIKE %s"))
        params.append(_like(f.branch.strip()))
    if f.detected_within_days:
        conditions.append(sql.SQL("first_detected_at >= now() - make_interval(days => %s)"))
        params.append(int(f.detected_within_days))

    where = sql.SQL(" WHERE ") + sql.SQL(" AND ").join(conditions) if conditions else sql.SQL("")
    query = sql.SQL("SELECT {cols} FROM {t}{where} ORDER BY first_detected_at DESC LIMIT %s").format(
        cols=sql.SQL(", ").join(map(sql.Identifier, VIOLATION_COLUMNS)),
        t=sql.Identifier(schema, TABLE),
        where=where,
    )
    params.append(limit)
    return query, params


SCOPE_COLUMNS = ("instance", "list_type", "content_guid", "app_name", "reason", "added_by", "added_at")
ACTION_COLUMNS = ("occurred_at", "instance", "actor", "action", "app_name", "content_guid", "success",
                  "error_message", "details")

RUN_COLUMNS = (
    "id", "instance", "started_at", "finished_at", "status", "scanned", "git_backed", "compliant",
    "non_compliant", "unknown", "not_git_backed", "excluded", "errors", "notifications_sent", "final_warnings_sent",
    "locked", "resolved", "error_message",
)

CONTENT_COLUMNS = (
    "instance", "app_name", "status", "repository", "branch", "detail", "last_checked_at",
    "app_url", "owner_guid", "content_guid",
)


@dataclass(frozen=True)
class ContentFilters:
    instance: str = ""
    status: str = ""                # "" = any; COMPLIANT | NON_COMPLIANT | UNKNOWN | NOT_GIT_BACKED | ERROR
    search: str = ""                # app name, GUID, repository


def build_content_query(schema: str, f: ContentFilters, limit: int):
    from psycopg import sql

    conditions: list[Any] = []
    params: list[Any] = []
    if f.instance:
        conditions.append(sql.SQL("instance = %s"))
        params.append(f.instance)
    if f.status:
        conditions.append(sql.SQL("status = %s"))
        params.append(f.status)
    if f.search.strip():
        cols = ("app_name", "content_guid", "repository")
        conditions.append(sql.SQL("({})").format(
            sql.SQL(" OR ").join(sql.SQL("{} ILIKE %s").format(sql.Identifier(c)) for c in cols)))
        params.extend([_like(f.search.strip())] * len(cols))
    where = sql.SQL(" WHERE ") + sql.SQL(" AND ").join(conditions) if conditions else sql.SQL("")
    query = sql.SQL("SELECT {cols} FROM {t}{where} ORDER BY instance, status, app_name LIMIT %s").format(
        cols=sql.SQL(", ").join(map(sql.Identifier, CONTENT_COLUMNS)),
        t=sql.Identifier(schema, CONTENT_TABLE), where=where)
    params.append(limit)
    return query, params


@dataclass(frozen=True)
class QueryResult:
    columns: list[str]
    rows: list[tuple]
    truncated: bool
    elapsed_seconds: float


# ----- database access -----------------------------------------------------------


class DashboardDB:
    def __init__(self, settings: DashboardSettings):
        if not settings.database_url:
            raise ConfigError("DASHBOARD_DATABASE_URL (or DATABASE_URL) is not set")
        self.s = settings

    @contextmanager
    def _transaction(self, *, read_only: bool) -> Iterator[Any]:
        import psycopg
        from psycopg import sql

        extra = {} if "sslmode=" in self.s.database_url else {"sslmode": "require"}
        try:
            conn = psycopg.connect(self.s.database_url, autocommit=True, connect_timeout=10,
                                   application_name="posit-compliance-dashboard", **extra)
        except psycopg.OperationalError as exc:
            log.error("Dashboard database connection failed: %s", type(exc).__name__)
            raise QueryFailed("The database is unavailable. Try again later.") from exc
        try:
            with conn.transaction(), conn.cursor() as cur:
                if read_only:
                    cur.execute("SET TRANSACTION READ ONLY")
                timeout_ms = int(self.s.sql_timeout_seconds * 1000)
                cur.execute(sql.SQL("SET LOCAL statement_timeout = {}").format(sql.Literal(timeout_ms)))
                cur.execute(sql.SQL("SET LOCAL search_path = {}, pg_catalog").format(sql.Identifier(self.s.db_schema)))
                yield cur
        except psycopg.errors.QueryCanceled as exc:
            raise QueryFailed(f"The query took longer than {self.s.sql_timeout_seconds:g} seconds and was cancelled.") from exc
        except psycopg.errors.UndefinedTable as exc:
            raise QueryFailed(f"{_db_message(exc)} (has the compliance job run at least once?)") from exc
        except psycopg.Error as exc:
            raise QueryFailed(_db_message(exc)) from exc
        finally:
            conn.close()

    def fetch_violations(self, f: ViolationFilters, limit: int | None = None) -> tuple[list[str], list[tuple]]:
        query, params = build_violations_query(self.s.db_schema, f, limit or self.s.sql_max_rows)
        with self._transaction(read_only=True) as cur:
            cur.execute(query, params)
            return [d.name for d in cur.description], cur.fetchall()

    def _t(self, name: str):
        from psycopg import sql

        return sql.Identifier(self.s.db_schema, name)

    @staticmethod
    def _instance_clause(instance: str, prefix: str = " WHERE "):
        from psycopg import sql

        if instance:
            return sql.SQL(prefix + "instance = %s"), [instance]
        return sql.SQL(""), []

    def summary(self, instance: str = "") -> dict[str, int]:
        from psycopg import sql

        where, params = self._instance_clause(instance)
        query = sql.SQL(
            "SELECT"
            " count(*) FILTER (WHERE status = %s) AS open,"
            " count(*) FILTER (WHERE status = %s AND locked) AS locked,"
            " count(*) FILTER (WHERE status = %s AND NOT locked AND final_warning_at IS NOT NULL) AS pending_lock,"
            " count(*) FILTER (WHERE status = %s AND resolved_at >= now() - interval '7 days') AS resolved_7d"
            " FROM {t}{where}"
        ).format(t=self._t(TABLE), where=where)
        inv_where, inv_params = self._instance_clause(instance)
        inventory = sql.SQL(
            "SELECT count(*) AS apps,"
            " count(*) FILTER (WHERE status = 'COMPLIANT') AS compliant,"
            " count(*) FILTER (WHERE status IN ('COMPLIANT', 'NON_COMPLIANT', 'UNKNOWN')) AS git_backed"
            " FROM {t}{where}"
        ).format(t=self._t(CONTENT_TABLE), where=inv_where)
        with self._transaction(read_only=True) as cur:
            cur.execute(query, (STATUS_OPEN, STATUS_OPEN, STATUS_OPEN, STATUS_RESOLVED, *params))
            result = dict(zip([d.name for d in cur.description], cur.fetchone()))
            cur.execute(inventory, inv_params)
            result.update(zip([d.name for d in cur.description], cur.fetchone()))
            return result

    def list_instances(self) -> list[str]:
        from psycopg import sql

        query = sql.SQL("SELECT instance FROM {r} UNION SELECT instance FROM {v} ORDER BY 1").format(
            r=self._t(RUNS_TABLE), v=self._t(TABLE))
        with self._transaction(read_only=True) as cur:
            cur.execute(query)
            return [r[0] for r in cur.fetchall()]

    def list_events(self, violation_id: int, instance: str = "", content_guid: str = "") -> list[tuple]:
        """Job events for the violation, merged with admin lock/unlock actions on the same app."""
        from psycopg import sql

        query = sql.SQL(
            "SELECT occurred_at, event_type, details FROM {e} WHERE violation_id = %s "
            "UNION ALL "
            "SELECT occurred_at, action, details || jsonb_build_object('by', actor, 'success', success) "
            "FROM {a} WHERE instance = %s AND content_guid = %s "
            "ORDER BY 1"
        ).format(e=self._t(EVENTS_TABLE), a=self._t(ACTIONS_TABLE))
        with self._transaction(read_only=True) as cur:
            cur.execute(query, (violation_id, instance, content_guid))
            return cur.fetchall()

    # ----- admin tab -----------------------------------------------------------------

    def list_scope(self, instance: str = "") -> tuple[list[str], list[tuple]]:
        from psycopg import sql

        where, params = self._instance_clause(instance, prefix=" WHERE s.")
        query = sql.SQL(
            "SELECT s.instance, s.list_type, s.content_guid, c.app_name, s.reason, s.added_by, s.added_at "
            "FROM {s} s LEFT JOIN {c} c ON c.instance = s.instance AND c.content_guid = s.content_guid"
            "{where} ORDER BY s.list_type, s.added_at DESC"
        ).format(s=self._t(SCOPE_TABLE), c=self._t(CONTENT_TABLE), where=where)
        with self._transaction(read_only=True) as cur:
            cur.execute(query, params)
            return list(SCOPE_COLUMNS), cur.fetchall()

    def change_scope(self, *, instance: str, guids: list[str], list_type: str, add: bool, actor: str,
                     reason: str | None) -> int:
        from psycopg import sql

        t = self._t(SCOPE_TABLE)
        if add:
            q = sql.SQL("INSERT INTO {t} (instance, content_guid, list_type, reason, added_by) "
                        "SELECT %s, g, %s, %s, %s FROM unnest(%s::text[]) AS g "
                        "ON CONFLICT DO NOTHING").format(t=t)
            params = (instance, list_type, reason, actor, guids)
        else:
            q = sql.SQL("DELETE FROM {t} WHERE instance = %s AND list_type = %s AND content_guid = ANY(%s)").format(t=t)
            params = (instance, list_type, guids)
        with self._transaction(read_only=False) as cur:
            cur.execute(q, params)
            return max(cur.rowcount, 0)   # rows actually added / removed

    def record_admin_action(self, *, instance: str, actor: str, action: str, content_guid: str | None,
                            app_name: str | None, details: dict, success: bool,
                            error_message: str | None = None) -> None:
        from psycopg import sql
        from psycopg.types.json import Jsonb

        q = sql.SQL("INSERT INTO {t} (instance, actor, action, content_guid, app_name, details, success, "
                    "error_message) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)").format(t=self._t(ACTIONS_TABLE))
        with self._transaction(read_only=False) as cur:
            cur.execute(q, (instance, actor, action, content_guid, app_name, Jsonb(details or {}), success,
                            error_message))

    def load_settings(self, instance: str) -> dict[str, str]:
        from psycopg import sql

        q = sql.SQL("SELECT key, value FROM {t} WHERE instance = %s").format(t=self._t(SETTINGS_TABLE))
        with self._transaction(read_only=True) as cur:
            cur.execute(q, (instance,))
            return {k: v for k, v in cur.fetchall()}

    def save_settings(self, instance: str, changes: dict[str, str], actor: str) -> None:
        """Upsert changed settings; an empty value deletes the row (= use the default)."""
        from psycopg import sql

        t = self._t(SETTINGS_TABLE)
        upsert = sql.SQL("INSERT INTO {t} (instance, key, value, updated_by, updated_at) "
                         "VALUES (%s, %s, %s, %s, now()) ON CONFLICT (instance, key) DO UPDATE SET "
                         "value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, "
                         "updated_at = EXCLUDED.updated_at").format(t=t)
        delete = sql.SQL("DELETE FROM {t} WHERE instance = %s AND key = %s").format(t=t)
        with self._transaction(read_only=False) as cur:
            for key, value in changes.items():
                if value == "":
                    cur.execute(delete, (instance, key))
                else:
                    cur.execute(upsert, (instance, key, value, actor))

    def list_admin_actions(self, instance: str = "", limit: int = 200) -> tuple[list[str], list[tuple]]:
        from psycopg import sql

        where, params = self._instance_clause(instance)
        query = sql.SQL("SELECT {cols} FROM {t}{where} ORDER BY occurred_at DESC LIMIT %s").format(
            cols=sql.SQL(", ").join(map(sql.Identifier, ACTION_COLUMNS)), t=self._t(ACTIONS_TABLE), where=where)
        with self._transaction(read_only=True) as cur:
            cur.execute(query, (*params, limit))
            return list(ACTION_COLUMNS), cur.fetchall()

    def fetch_runs(self, instance: str = "", limit: int = 200) -> tuple[list[str], list[tuple]]:
        from psycopg import sql

        where, params = self._instance_clause(instance)
        query = sql.SQL("SELECT {cols} FROM {t}{where} ORDER BY started_at DESC LIMIT %s").format(
            cols=sql.SQL(", ").join(map(sql.Identifier, RUN_COLUMNS)), t=self._t(RUNS_TABLE), where=where)
        with self._transaction(read_only=True) as cur:
            cur.execute(query, (*params, limit))
            return [d.name for d in cur.description], cur.fetchall()

    def fetch_content(self, f: "ContentFilters", limit: int | None = None) -> tuple[list[str], list[tuple]]:
        query, params = build_content_query(self.s.db_schema, f, limit or self.s.sql_max_rows)
        with self._transaction(read_only=True) as cur:
            cur.execute(query, params)
            return [d.name for d in cur.description], cur.fetchall()

    def list_notes(self, violation_id: int) -> list[tuple]:
        from psycopg import sql

        query = sql.SQL("SELECT created_at, author, note FROM {n} WHERE violation_id = %s "
                        "ORDER BY created_at DESC").format(n=sql.Identifier(self.s.db_schema, NOTES_TABLE))
        with self._transaction(read_only=True) as cur:
            cur.execute(query, (violation_id,))
            return cur.fetchall()

    def add_note(self, violation_id: int, author: str, text: str) -> int:
        from psycopg import sql

        note = clean_note(text)
        if not author:
            raise NoteRejected("Your Posit Connect user could not be identified, so the note cannot be attributed.")
        query = sql.SQL(
            "INSERT INTO {n} (violation_id, content_guid, author, note) "
            "SELECT id, content_guid, %s, %s FROM {t} WHERE id = %s RETURNING id"
        ).format(n=sql.Identifier(self.s.db_schema, NOTES_TABLE), t=sql.Identifier(self.s.db_schema, TABLE))
        with self._transaction(read_only=False) as cur:
            cur.execute(query, (author, note, violation_id))
            row = cur.fetchone()
        if not row:
            raise NoteRejected("That violation no longer exists.")
        log.info("Note %s added to violation %s by %s.", row[0], violation_id, author)
        return row[0]

    def run_readonly_sql(self, text: str, user: str) -> QueryResult:
        query = validate_readonly_sql(text)
        started = time.monotonic()
        try:
            with self._transaction(read_only=True) as cur:
                cur.execute(query)
                if cur.description is None:
                    columns, rows = [], []
                else:
                    columns = [d.name for d in cur.description]
                    rows = cur.fetchmany(self.s.sql_max_rows + 1)
        except QueryFailed as exc:
            log.warning("SQL tab query by %s failed: %s | %s", user, exc, _one_line(query))
            raise
        elapsed = time.monotonic() - started
        truncated = len(rows) > self.s.sql_max_rows
        log.info("SQL tab query by %s returned %d rows in %.2fs | %s",
                 user, min(len(rows), self.s.sql_max_rows), elapsed, _one_line(query))
        return QueryResult(columns, rows[: self.s.sql_max_rows], truncated, elapsed)


def clean_note(text: str | None) -> str:
    note = (text or "").strip()
    if not note:
        raise NoteRejected("The note is empty.")
    if len(note) > MAX_NOTE_LENGTH:
        raise NoteRejected(f"Notes are limited to {MAX_NOTE_LENGTH} characters.")
    return note


def _db_message(exc: Exception) -> str:
    diag = getattr(exc, "diag", None)
    message = getattr(diag, "message_primary", None) if diag else None
    return f"Database error: {message or type(exc).__name__}"


def _one_line(query: str, limit: int = 1000) -> str:
    flat = " ".join(query.split())
    return flat if len(flat) <= limit else flat[:limit] + "..."
