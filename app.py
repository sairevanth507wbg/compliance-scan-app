"""Branch Compliance Dashboard (Shiny for Python).

Published on Posit Connect as a separate content item next to the scheduled
job. Restrict access to Posit admins under Settings -> Access. Publish one
dashboard per Connect instance, pointing at that instance's database (the
instance selector also works if several instances ever share a database).

Tabs:
  Violations - summary cards, filters, table, details, history, admin notes
  All apps   - latest compliance status of every content item
  Scan runs  - one row per job run (counts and errors)
  SQL query  - read-only SQL against the compliance schema, CSV download
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import replace
from datetime import datetime
from decimal import Decimal

import pandas as pd
from shiny import App, reactive, render, ui

from compliance.admin import (
    DEFAULT_MANUAL_LOCK_MESSAGE, GUID_RE, change_scope_list, describe_app, set_app_lock,
)
from compliance.config import ConfigError
from compliance.connect_client import ConnectAPIError, ConnectClient, ConnectNotFoundError
from compliance.job import configure_logging
from compliance.models import SCOPE_ENFORCE_ONLY, SCOPE_EXCLUDED
from compliance.queries import (
    EXAMPLE_QUERIES, ContentFilters, DashboardDB, DashboardSettings, NoteRejected, QueryFailed,
    QueryRejected, QueryResult, ViolationFilters, is_authorized, parse_connect_user,
)

configure_logging()
log = logging.getLogger("branch_compliance.dashboard")

CREDENTIALS_HEADER = "RStudio-Connect-Credentials"
APP_TITLE = "Branch Compliance"
DEMO = os.environ.get("DASHBOARD_DEMO", "").strip().lower() in ("1", "true", "yes", "on")
EXAMPLES = EXAMPLE_QUERIES

EVENT_LABELS = {
    "DETECTED": "Violation detected",
    "DETAILS_CHANGED": "Repository / branch changed",
    "FIRST_NOTICE_SENT": "First notice emailed",
    "FINAL_WARNING_SENT": "Final warning emailed",
    "LOCKED": "Application locked",
    "LOCK_FAILED": "Lock attempt failed",
    "LOCK_NOTICE_SENT": "Lock notice emailed",
    "ADMIN_UNLOCKED": "Unlocked by an administrator",
    "FIX_WINDOW_NOTICE_SENT": "Fix-window email sent",
    "RESOLVED": "Resolved",
    "MANUAL_LOCK": "Locked manually from the dashboard",
    "MANUAL_UNLOCK": "Unlocked manually from the dashboard",
}

try:
    SETTINGS = DashboardSettings.from_env()
    if DEMO:
        # Local preview only: sample data in memory, no PostgreSQL needed.
        from compliance.demo import DEMO_SQL_EXAMPLES, DemoDB

        if not SETTINGS.local_user:
            SETTINGS = replace(SETTINGS, local_user="local-admin")
        DB = DemoDB(SETTINGS)
        CONNECT = DB.demo_connect()
        EXAMPLES = DEMO_SQL_EXAMPLES
        log.warning("DASHBOARD_DEMO=true: showing SAMPLE data, not the real database.")
    else:
        DB = DashboardDB(SETTINGS) if SETTINGS.database_url else None
        # Lock/unlock needs the administrator key; CONNECT_SERVER is set by Connect.
        CONNECT = (ConnectClient(SETTINGS.connect_server, SETTINGS.connect_api_key)
                   if SETTINGS.connect_server and SETTINGS.connect_api_key else None)
    STARTUP_PROBLEM = None if DB else "No database is configured. Set DASHBOARD_DATABASE_URL (or DATABASE_URL) in Vars."
except ConfigError as exc:
    SETTINGS, DB, CONNECT, STARTUP_PROBLEM = DashboardSettings(), None, None, f"Configuration error: {exc}"


# ----- helpers ------------------------------------------------------------------


def _current_user(headers):
    user = parse_connect_user(headers.get(CREDENTIALS_HEADER))
    name = user.username if user else SETTINGS.local_user
    return user, name


def _display_value(value):
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC") if value.tzinfo else value.strftime("%Y-%m-%d %H:%M")
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float, str)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


def _display_frame(columns: list[str], rows: list[tuple]) -> pd.DataFrame:
    """DataFrame with values the data grid can always render."""
    df = pd.DataFrame(rows, columns=columns)
    for col in df.columns:
        df[col] = df[col].map(_display_value)
    return df


COLUMN_LABELS = {
    "id": "ID", "app_name": "Application", "status": "Status", "locked": "Locked", "owner_username": "Owner",
    "repository": "Repository", "detected_branch": "Branch", "branch": "Branch", "reasons": "Reasons",
    "first_detected_at": "First detected", "notified_at": "Notified", "final_warning_at": "Final warning",
    "locked_at": "Locked at", "resolved_at": "Resolved at", "detail": "Detail", "last_checked_at": "Last checked",
    "app_url": "Standalone URL", "owner_guid": "Owner GUID", "content_guid": "GUID",
    "started_at": "Started", "finished_at": "Finished", "scanned": "Scanned", "git_backed": "Git apps",
    "compliant": "Compliant", "non_compliant": "Non-compliant", "unknown": "Unknown", "not_git_backed": "Not Git",
    "excluded": "Excluded", "errors": "Errors", "notifications_sent": "Emails", "final_warnings_sent": "Final warnings",
    "resolved": "Resolved", "error_message": "Error", "list_type": "List", "reason": "Reason",
    "added_by": "Added by", "added_at": "Added", "occurred_at": "When", "actor": "By", "action": "Action",
    "success": "OK", "details": "Details",
}

# Row tints for status values (Bootstrap palette, light).
ROW_TINTS = {
    "NON_COMPLIANT": "#fffbeb",   # very light amber
    "ERROR": "#fef2f2",           # very light red
    "FAILED": "#fef2f2",
    "UNKNOWN": "#f8fafc",         # very light grey
    "EXCLUDED": "#f8fafc",
}
LOCKED_TINT = "#fef2f2"


def _pretty(df: pd.DataFrame, columns: list[str] | None = None) -> pd.DataFrame:
    """Pick columns (in order) and give them readable headers, for on-screen tables only."""
    if columns:
        df = df[[c for c in columns if c in df.columns]]
    return df.rename(columns={c: COLUMN_LABELS.get(c, c) for c in df.columns})


def _row_styles(values, extra: dict | None = None) -> list[dict]:
    tints = {**ROW_TINTS, **(extra or {})}
    styles = []
    for value, colour in tints.items():
        rows = [i for i, v in enumerate(values) if v == value]
        if rows:
            styles.append({"rows": rows, "style": {"background-color": colour}})
    return styles


def _safe_link(url: str | None, label: str):
    if url and str(url).startswith(("https://", "http://")):
        return ui.a(label, href=url, target="_blank", rel="noopener noreferrer")
    return ui.span("-")


def lock_buttons(lock_id: str, unlock_id: str):
    """Lock / Unlock buttons for a selected app; each opens the confirmation dialog."""
    return ui.div(
        ui.input_action_button(lock_id, "Lock application", class_="btn-danger btn-sm", disabled=CONNECT is None),
        ui.input_action_button(unlock_id, "Unlock application", class_="btn-outline-secondary btn-sm",
                               disabled=CONNECT is None),
        ui.span("Set COMPLIANCE_CONNECT_API_KEY to enable." if CONNECT is None else "",
                class_="text-muted small align-self-center"),
        class_="d-flex gap-2",
    )


def _message_page(title: str, message: str):
    return ui.page_fillable(ui.card(ui.card_header(title), ui.p(message)), title=APP_TITLE)


def _details_text(details) -> str:
    if not details:
        return ""
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except ValueError:
            return details
    if not isinstance(details, dict):
        return str(details)
    parts = []
    for key, value in details.items():
        if isinstance(value, dict):
            value = ", ".join(f"{k}={v}" for k, v in value.items())
        elif isinstance(value, list):
            value = ", ".join(map(str, value))
        parts.append(f"{key}: {value}")
    return "; ".join(parts)


# ----- UI -------------------------------------------------------------------------


def violations_panel():
    return ui.nav_panel(
        "Violations",
        ui.layout_columns(
            ui.value_box("Open violations", ui.output_text("kpi_open"), class_="kpi kpi-amber"),
            ui.value_box("Locked apps", ui.output_text("kpi_locked"), class_="kpi kpi-red"),
            ui.value_box("Final warning sent", ui.output_text("kpi_pending"), class_="kpi kpi-slate"),
            ui.value_box("Resolved (last 7 days)", ui.output_text("kpi_resolved"), class_="kpi kpi-green"),
            ui.value_box("Git apps compliant", ui.output_text("kpi_compliance"), class_="kpi kpi-blue"),
            fill=False,
            class_="mb-3",
        ),
        ui.layout_sidebar(
            ui.sidebar(
                ui.input_select("f_status", "Status", {"open": "Open", "resolved": "Resolved", "all": "All"}),
                ui.input_select("f_locked", "Lock state", {"all": "All", "locked": "Locked", "unlocked": "Not locked"}),
                ui.input_text("f_search", "Search", placeholder="App, GUID, owner, repository"),
                ui.input_text("f_branch", "Branch", placeholder="e.g. feature"),
                ui.input_select("f_window", "First detected",
                                {"": "Any time", "1": "Last 24 hours", "7": "Last 7 days",
                                 "30": "Last 30 days", "90": "Last 90 days"}),
                ui.input_action_button("apply", "Apply / refresh", class_="btn-primary"),
                ui.download_button("download_violations", "Download CSV"),
                width=290,
            ),
            ui.card(
                ui.card_header("Violations - select a row to see details, history and notes"),
                ui.output_ui("violations_error"),
                ui.output_data_frame("violations_grid"),
                full_screen=True,
            ),
            ui.output_ui("detail_panel"),
        ),
    )


def apps_panel():
    return ui.nav_panel(
        "All apps",
        ui.layout_sidebar(
            ui.sidebar(
                ui.input_select("a_status", "Status", {
                    "": "Any", "COMPLIANT": "Compliant", "NON_COMPLIANT": "Non-compliant",
                    "UNKNOWN": "Unknown", "NOT_GIT_BACKED": "Not Git-backed", "ERROR": "Error"}),
                ui.input_text("a_search", "Search", placeholder="App, GUID, repository"),
                ui.input_action_button("a_apply", "Apply / refresh", class_="btn-primary"),
                ui.download_button("download_apps", "Download CSV"),
                width=290,
            ),
            ui.card(
                ui.card_header("Latest status of every content item - select a row to lock or unlock it"),
                ui.output_ui("apps_error"),
                ui.output_data_frame("apps_grid"),
                full_screen=True,
            ),
            ui.output_ui("apps_actions"),
        ),
    )


def runs_panel():
    return ui.nav_panel(
        "Scan runs",
        ui.card(
            ui.card_header(ui.div(
                ui.span("Most recent 200 scheduled runs"),
                ui.div(ui.input_action_button("r_apply", "Refresh", class_="btn-sm btn-primary"),
                       ui.download_button("download_runs", "Download CSV", class_="btn-sm"),
                       class_="d-flex gap-2"),
                class_="d-flex justify-content-between align-items-center")),
            ui.output_ui("runs_error"),
            ui.output_data_frame("runs_grid"),
            full_screen=True,
        ),
    )


def admin_panel():
    lock_disabled_note = None if CONNECT else ui.div(
        "Lock / unlock is disabled: set COMPLIANCE_CONNECT_API_KEY (administrator key) in this dashboard's Vars.",
        class_="alert alert-secondary py-2")
    return ui.nav_panel(
        "Admin",
        ui.layout_columns(
            ui.card(
                ui.card_header("Lock or unlock an application"),
                lock_disabled_note,
                ui.input_text("adm_guid", "Content GUID", placeholder="1a2b3c4d-1111-2222-3333-444455556666",
                              width="100%"),
                ui.input_text_area("adm_message", "Message shown to visitors while locked (optional, Markdown)",
                                   rows=3, width="100%", placeholder=DEFAULT_MANUAL_LOCK_MESSAGE.replace("**", "")),
                ui.div(
                    ui.input_action_button("adm_lock", "Lock application", class_="btn-danger",
                                           disabled=CONNECT is None),
                    ui.input_action_button("adm_unlock", "Unlock application", class_="btn-outline-secondary",
                                           disabled=CONNECT is None),
                    class_="d-flex gap-2"),
                ui.p("You will see the application's name and confirm before anything changes. Locking stops the "
                     "app immediately and ends active sessions. Unlocking a non-compliant app starts its fix "
                     "window; the job locks it again afterwards if it is still non-compliant.",
                     class_="text-muted small mt-2 mb-0"),
                ui.output_ui("adm_lock_result"),
            ),
            ui.card(
                ui.card_header("Scan scope"),
                ui.input_text_area("scope_guids", "Content GUIDs (one per line, or comma-separated)", rows=4,
                                   width="100%"),
                ui.input_text("scope_reason", "Reason (optional, recorded)", width="100%"),
                ui.div(
                    ui.input_action_button("scope_exclude_add", "Exclude from scan", class_="btn-primary btn-sm"),
                    ui.input_action_button("scope_exclude_remove", "Remove from excluded", class_="btn-outline-primary btn-sm"),
                    class_="d-flex gap-2 mb-2"),
                ui.div(
                    ui.input_action_button("scope_enforce_add", "Add to enforce only", class_="btn-primary btn-sm"),
                    ui.input_action_button("scope_enforce_remove", "Remove from enforce only", class_="btn-outline-primary btn-sm"),
                    class_="d-flex gap-2"),
                ui.markdown(
                    "- **Excluded**: never scanned, emailed or locked; any open violation is closed.\n"
                    "- **Enforce only**: when this list has apps, emails and locking apply **only** to them "
                    "(all apps are still scanned). Empty = enforce on all apps.\n"
                    "- Changes apply from the next scheduled run.",
                ),
                ui.output_ui("scope_result"),
            ),
            col_widths=(6, 6),
        ),
        ui.card(ui.card_header("Excluded and enforce-only apps"), ui.output_data_frame("scope_grid"), full_screen=True),
        ui.card(ui.card_header("Recent admin actions"), ui.output_data_frame("actions_grid"), full_screen=True),
    )


def sql_panel():
    schema = SETTINGS.db_schema
    return ui.nav_panel(
        "SQL query",
        ui.card(
            ui.card_header("Read-only SQL"),
            ui.markdown(
                f"Queries run in a **read-only transaction** against schema `{schema}`. Tables: "
                "`branch_violations`, `violation_events`, `content_compliance`, `scan_runs`, "
                "`branch_violation_notes` (each row has an `instance` column). One statement per run, "
                f"time limit {SETTINGS.sql_timeout_seconds:g}s, at most {SETTINGS.sql_max_rows:,} rows. "
                "Every query is logged with your user name."
            ),
            ui.input_select("sql_example", "Examples", {"": "Choose an example...", **{k: k for k in EXAMPLES}}),
            ui.input_text_area("sql_text", "SQL", value=next(iter(EXAMPLES.values())),
                               rows=9, width="100%", spellcheck="false"),
            ui.div(ui.input_action_button("sql_run", "Run query", class_="btn-primary"),
                   ui.download_button("sql_download", "Download CSV"), class_="d-flex gap-2"),
            ui.output_ui("sql_status"),
        ),
        ui.card(ui.output_data_frame("sql_grid"), full_screen=True),
    )


def app_ui(request):
    user, _ = _current_user(request.headers)
    if not is_authorized(user, SETTINGS):
        return _message_page("Access denied", "You are not on the allow-list for this dashboard.")
    if STARTUP_PROBLEM:
        return _message_page("Dashboard not configured", STARTUP_PROBLEM)
    signed_in = f"Signed in as {user.username}" if user else "Local session (not on Posit Connect)"
    status_strip = ui.div(
        ui.span(signed_in),
        ui.span("DEMO MODE - sample data only", class_="badge text-bg-warning") if DEMO else None,
        class_="status-strip d-flex justify-content-between align-items-center",
    )
    return ui.page_navbar(
        # Order = how often admins need each tab.
        violations_panel(),
        apps_panel(),
        admin_panel(),
        runs_panel(),
        sql_panel(),
        title=APP_TITLE,
        id="nav",
        window_title=APP_TITLE,
        header=ui.TagList(ui.tags.style(APP_CSS), status_strip),
    )


APP_CSS = """
body { background-color: #f8fafc; color: #1f2937; }

/* Navigation: white bar, blue underline on the active tab */
.navbar { background-color: #ffffff !important; border-bottom: 1px solid #e5e7eb;
          padding-top: .25rem; padding-bottom: 0; }
.navbar .navbar-brand { color: #111827 !important; font-weight: 600; margin-right: 2rem; }
.navbar .navbar-nav { flex-wrap: nowrap; }
.navbar .nav-link { color: #4b5563 !important; white-space: nowrap; padding: .75rem 1rem !important;
                    border-bottom: 2px solid transparent; }
.navbar .nav-link:hover { color: #111827 !important; }
.navbar .nav-link.active { color: #1d4ed8 !important; font-weight: 600; border-bottom-color: #1d4ed8; }

.status-strip { background: #ffffff; border-bottom: 1px solid #e5e7eb; padding: .3rem 1.25rem;
                font-size: .82rem; color: #6b7280; }

/* Cards */
.card { border: 1px solid #e5e7eb; box-shadow: none; }
.card-header { font-weight: 600; background-color: #ffffff; border-bottom: 1px solid #f1f5f9; color: #111827; }

/* Summary cards: white with a thin coloured top line and coloured number */
.kpi.bslib-value-box { background: #ffffff !important; color: #1f2937 !important;
                       border: 1px solid #e5e7eb; border-top-width: 3px; }
.kpi .value-box-title { font-size: .85rem; color: #6b7280; font-weight: 500; }
.kpi .value-box-value { font-size: 1.75rem; font-weight: 600; }
.kpi-amber { border-top-color: #d97706 !important; } .kpi-amber .value-box-value { color: #b45309; }
.kpi-red   { border-top-color: #dc2626 !important; } .kpi-red .value-box-value   { color: #b91c1c; }
.kpi-slate { border-top-color: #64748b !important; } .kpi-slate .value-box-value { color: #334155; }
.kpi-green { border-top-color: #16a34a !important; } .kpi-green .value-box-value { color: #15803d; }
.kpi-blue  { border-top-color: #2563eb !important; } .kpi-blue .value-box-value  { color: #1d4ed8; }

/* Buttons: one consistent blue */
.btn-primary { background-color: #1d4ed8; border-color: #1d4ed8; }
.btn-primary:hover { background-color: #1e40af; border-color: #1e40af; }

#sql_text { font-family: ui-monospace, Consolas, monospace; font-size: .9rem; }
.timeline-item { border-left: 2px solid #cbd5e1; padding-left: .6rem; margin-bottom: .5rem; }
"""


# ----- server -----------------------------------------------------------------------


def server(input, output, session):
    user, username = _current_user(session.http_conn.headers)
    # Defense in depth: never serve data to a session the UI would have refused.
    if DB is None or not is_authorized(user, SETTINGS):
        return

    refresh = reactive.value(0)          # reloads table + cards
    notes_version = reactive.value(0)    # reloads only the notes (keeps the row selected)
    violations_error_msg = reactive.value("")
    apps_error_msg = reactive.value("")
    runs_error_msg = reactive.value("")
    sql_result: reactive.Value[QueryResult | None] = reactive.value(None)
    sql_message = reactive.value(("", ""))  # (kind, text)


    # --- violations -------------------------------------------------------------

    def current_filters() -> ViolationFilters:
        window = input.f_window()
        return ViolationFilters(status=input.f_status(), locked=input.f_locked(),
                                search=input.f_search(), branch=input.f_branch(),
                                detected_within_days=int(window) if window else None)

    @reactive.calc
    @reactive.event(input.apply, input.f_status, input.f_locked, input.f_window, refresh, ignore_none=False)
    def violations_raw() -> tuple[list[str], list[tuple]]:
        try:
            result = DB.fetch_violations(current_filters())
            violations_error_msg.set("")
            return result
        except QueryFailed as exc:
            violations_error_msg.set(str(exc))
            return [], []

    @reactive.calc
    @reactive.event(input.apply, refresh, ignore_none=False)
    def kpis() -> dict:
        try:
            return DB.summary()
        except QueryFailed:
            return {}

    @render.text
    def kpi_open():
        return str(kpis().get("open", "-"))

    @render.text
    def kpi_locked():
        return str(kpis().get("locked", "-"))

    @render.text
    def kpi_pending():
        return str(kpis().get("pending_lock", "-"))

    @render.text
    def kpi_resolved():
        return str(kpis().get("resolved_7d", "-"))

    @render.text
    def kpi_compliance():
        k = kpis()
        total, ok = k.get("git_backed"), k.get("compliant")
        if not total:
            return "-"
        return f"{ok}/{total} ({100 * ok / total:.0f}%)"

    @render.ui
    def violations_error():
        msg = violations_error_msg.get()
        return ui.div(msg, class_="alert alert-danger") if msg else None

    @render.data_frame
    def violations_grid():
        columns, rows = violations_raw()
        df = _display_frame(columns, rows)
        locked = list(df["locked"]) if "locked" in df.columns else []
        df = _pretty(df, ["id", "app_name", "status", "locked", "owner_username", "repository",
                          "detected_branch", "reasons", "first_detected_at", "notified_at",
                          "final_warning_at", "locked_at", "resolved_at"])
        return render.DataGrid(df, selection_mode="row", filters=True, height="420px", width="100%",
                               styles=_row_styles(locked, {"yes": LOCKED_TINT}))

    @reactive.calc
    def selected_row() -> dict | None:
        selected = violations_grid.data_view(selected=True)
        if selected is None or selected.empty:
            return None
        violation_id = int(selected.iloc[0][COLUMN_LABELS["id"]])
        columns, rows = violations_raw()
        for row in rows:
            record = dict(zip(columns, row))
            if record["id"] == violation_id:
                return record
        return None

    @render.ui
    def detail_panel():
        v = selected_row()
        if v is None:
            return ui.card(ui.p("Select a violation in the table to see its details, history and notes.",
                                class_="text-muted"))
        notes_version()  # re-render after a note is added
        try:
            notes = DB.list_notes(v["id"])
            notes_ui = [ui.div(ui.strong(f"{_display_value(ts)} - {author}"), ui.p(note, style="white-space: pre-wrap;"),
                               class_="border-bottom pb-2 mb-2") for ts, author, note in notes] \
                or [ui.p("No notes yet.", class_="text-muted")]
        except QueryFailed as exc:
            notes_ui = [ui.div(str(exc), class_="alert alert-danger")]
        try:
            events = DB.list_events(v["id"], v["instance"], v["content_guid"])
            history_ui = [ui.div(ui.div(ui.strong(EVENT_LABELS.get(kind, kind)),
                                        ui.span(f"  {_display_value(ts)}", class_="text-muted small")),
                                 ui.div(_details_text(details), class_="small text-muted") if details else None,
                                 class_="timeline-item") for ts, kind, details in events] \
                or [ui.p("No history recorded.", class_="text-muted")]
        except QueryFailed as exc:
            history_ui = [ui.div(str(exc), class_="alert alert-danger")]

        def field(label, value):
            return ui.tags.tr(ui.tags.th(label, class_="pe-3 text-nowrap"), ui.tags.td(value))

        return ui.card(
            ui.card_header(f"{v['app_name']} - {v['instance']} (violation #{v['id']})"),
            ui.layout_columns(
                ui.tags.table(
                    field("Instance", v["instance"]),
                    field("Standalone URL", _safe_link(v.get("app_url"), v.get("app_url") or "-")),
                    field("Connect settings", _safe_link(v.get("dashboard_url"), "Open in Connect")),
                    field("Content GUID", v["content_guid"]),
                    field("Owner", f"{v.get('owner_username') or '-'} ({v.get('owner_email') or 'no email'})"),
                    field("Repository", v.get("repository") or "-"),
                    field("Branch", f"{v.get('detected_branch') or 'unknown'} (required: {v['required_branch']})"),
                    field("Reasons", v.get("reasons") or "-"),
                    field("Status", f"{v['status']}{' - ' + v['resolution'] if v.get('resolution') else ''}"),
                    field("Locked", "yes" if v["locked"] else "no"),
                    *[field(label, _display_value(v.get(key)) or "-") for label, key in (
                        ("First detected", "first_detected_at"), ("Last checked", "last_checked_at"),
                        ("First notice sent", "notified_at"), ("Final warning sent", "final_warning_at"),
                        ("Locked at", "locked_at"), ("Admin unlocked at", "admin_unlocked_at"),
                        ("Resolved at", "resolved_at"))],
                    class_="table table-sm",
                ),
                ui.div(ui.h6("History"), *history_ui, ui.hr(), lock_buttons("viol_lock", "viol_unlock")),
                ui.div(
                    ui.h6("Admin notes"),
                    ui.p("Notes are permanent and recorded with your Posit Connect user name.", class_="text-muted small"),
                    ui.input_text_area("note_text", None, rows=3, width="100%",
                                       placeholder="e.g. Owner contacted on Teams; fix expected Friday."),
                    ui.input_action_button("note_add", "Add note", class_="btn-secondary mb-3",
                                           disabled=not username),
                    *notes_ui,
                ),
                col_widths=(5, 3, 4),
            ),
        )

    @reactive.effect
    @reactive.event(input.viol_lock)
    def _viol_lock():
        v = selected_row()
        if v:
            ask_lock_confirmation(True, v["content_guid"])

    @reactive.effect
    @reactive.event(input.viol_unlock)
    def _viol_unlock():
        v = selected_row()
        if v:
            ask_lock_confirmation(False, v["content_guid"])

    @reactive.effect
    @reactive.event(input.note_add)
    def _add_note():
        v = selected_row()
        if v is None:
            return
        try:
            DB.add_note(v["id"], username, input.note_text())
        except NoteRejected as exc:
            ui.notification_show(str(exc), type="warning")
            return
        except QueryFailed as exc:
            ui.notification_show(str(exc), type="error")
            return
        ui.notification_show("Note saved.", type="message")
        notes_version.set(notes_version.get() + 1)

    @render.download(filename=lambda: f"branch_violations_{datetime.now():%Y%m%d_%H%M}.csv")
    def download_violations():
        columns, rows = violations_raw()
        yield _display_frame(columns, rows).to_csv(index=False)

    # --- all apps -----------------------------------------------------------------

    @reactive.calc
    @reactive.event(input.a_apply, input.a_status, ignore_none=False)
    def apps_raw():
        try:
            result = DB.fetch_content(ContentFilters(status=input.a_status(),
                                                     search=input.a_search()))
            apps_error_msg.set("")
            return result
        except QueryFailed as exc:
            apps_error_msg.set(str(exc))
            return [], []

    @render.ui
    def apps_error():
        msg = apps_error_msg.get()
        return ui.div(msg, class_="alert alert-danger") if msg else None

    @render.data_frame
    def apps_grid():
        columns, rows = apps_raw()
        df = _display_frame(columns, rows)
        statuses = list(df["status"]) if "status" in df.columns else []
        df = _pretty(df, ["app_name", "status", "repository", "branch", "detail", "last_checked_at",
                          "app_url", "content_guid"])
        return render.DataGrid(df, filters=True, selection_mode="row", height="520px", width="100%",
                               styles=_row_styles(statuses))

    @reactive.calc
    def selected_app() -> dict | None:
        selected = apps_grid.data_view(selected=True)
        if selected is None or selected.empty:
            return None
        row = selected.iloc[0]
        return {"name": row[COLUMN_LABELS["app_name"]], "status": row[COLUMN_LABELS["status"]],
                "guid": row[COLUMN_LABELS["content_guid"]]}

    @render.ui
    def apps_actions():
        app = selected_app()
        if app is None:
            return ui.card(ui.p("Select an app in the table to lock or unlock it.", class_="text-muted mb-0"))
        return ui.card(
            ui.card_header(f"{app['name']} - {app['status']}"),
            ui.p(ui.span("GUID: ", class_="text-muted"), ui.code(app["guid"])),
            lock_buttons("apps_lock", "apps_unlock"),
        )

    @reactive.effect
    @reactive.event(input.apps_lock)
    def _apps_lock():
        app = selected_app()
        if app:
            ask_lock_confirmation(True, app["guid"])

    @reactive.effect
    @reactive.event(input.apps_unlock)
    def _apps_unlock():
        app = selected_app()
        if app:
            ask_lock_confirmation(False, app["guid"])

    @render.download(filename=lambda: f"content_compliance_{datetime.now():%Y%m%d_%H%M}.csv")
    def download_apps():
        columns, rows = apps_raw()
        yield _display_frame(columns, rows).to_csv(index=False)

    # --- scan runs --------------------------------------------------------------------

    @reactive.calc
    @reactive.event(input.r_apply, ignore_none=False)
    def runs_raw():
        try:
            result = DB.fetch_runs()
            runs_error_msg.set("")
            return result
        except QueryFailed as exc:
            runs_error_msg.set(str(exc))
            return [], []

    @render.ui
    def runs_error():
        msg = runs_error_msg.get()
        return ui.div(msg, class_="alert alert-danger") if msg else None

    @render.data_frame
    def runs_grid():
        columns, rows = runs_raw()
        df = _display_frame(columns, rows)
        statuses = list(df["status"]) if "status" in df.columns else []
        df = _pretty(df, [c for c in df.columns if c not in ("id", "instance")])
        return render.DataGrid(df, filters=True, height="560px", width="100%", styles=_row_styles(statuses))

    @render.download(filename=lambda: f"scan_runs_{datetime.now():%Y%m%d_%H%M}.csv")
    def download_runs():
        columns, rows = runs_raw()
        yield _display_frame(columns, rows).to_csv(index=False)

    # --- admin tab --------------------------------------------------------------

    admin_version = reactive.value(0)
    pending_lock = reactive.value(None)
    adm_lock_msg = reactive.value(("", ""))
    scope_msg = reactive.value(("", ""))

    def action_instance() -> str | None:
        """Instance label for admin actions: the one this dashboard's database belongs to
        (each Connect instance has its own database). None until the job has run once."""
        try:
            instances = DB.list_instances()
        except QueryFailed:
            return None
        return instances[0] if instances else None

    def ask_lock_confirmation(lock: bool, guid: str | None = None) -> None:
        """Show the confirmation dialog. guid comes from a selected row, or the Admin tab's text box."""
        if CONNECT is None:
            ui.notification_show("Lock / unlock is disabled: COMPLIANCE_CONNECT_API_KEY is not set.", type="warning")
            return
        from_row = guid is not None
        guid = (guid if from_row else (input.adm_guid() or "")).strip().lower()
        if not GUID_RE.match(guid):
            adm_lock_msg.set(("warning", "Enter a valid content GUID (e.g. 1a2b3c4d-1111-2222-3333-444455556666)."))
            return
        instance = action_instance()
        if not instance:
            adm_lock_msg.set(("warning", "Choose an instance in the top bar first."))
            return
        try:
            info = describe_app(CONNECT, guid)
        except ConnectNotFoundError:
            adm_lock_msg.set(("danger", f"No content with GUID {guid} exists on this Connect server."))
            return
        except ConnectAPIError as exc:
            adm_lock_msg.set(("danger", f"Could not read the application from Connect: {exc}"))
            return
        pending_lock.set(dict(guid=guid, lock=lock, instance=instance,
                              message="" if from_row else input.adm_message()))
        verb = "Lock" if lock else "Unlock"
        warning = ("Locking stops the application immediately, ends active sessions and blocks deployments."
                   if lock else
                   "Unlocking makes the application available again. If it is still non-compliant, the job "
                   "starts its fix window and locks it again afterwards.")

        def row(label, value):
            return ui.tags.tr(ui.tags.th(label, class_="pe-3"), ui.tags.td(value))

        ui.modal_show(ui.modal(
            ui.tags.table(
                row("Application", info["name"]),
                row("Standalone URL", _safe_link(info.get("url"), info.get("url") or "-")),
                row("Content GUID", guid),
                row("Instance", instance),
                row("Currently locked", "yes" if info.get("locked") else "no"),
                class_="table table-sm"),
            ui.div(warning, class_="alert alert-warning py-2 mb-0"),
            title=f"{verb} '{info['name']}'?",
            footer=ui.TagList(
                ui.modal_button("Cancel"),
                ui.input_action_button("adm_confirm", f"{verb} now", class_="btn-danger" if lock else "btn-primary")),
            easy_close=True,
        ))

    @reactive.effect
    @reactive.event(input.adm_lock)
    def _ask_lock():
        ask_lock_confirmation(True)

    @reactive.effect
    @reactive.event(input.adm_unlock)
    def _ask_unlock():
        ask_lock_confirmation(False)

    @reactive.effect
    @reactive.event(input.adm_confirm)
    def _confirm_lock():
        pending = pending_lock.get()
        if not pending or CONNECT is None:
            return
        pending_lock.set(None)
        ui.modal_remove()
        try:
            result = set_app_lock(CONNECT, DB, instance=pending["instance"], guid=pending["guid"],
                                  lock=pending["lock"], actor=username, message=pending["message"])
        except QueryFailed as exc:
            adm_lock_msg.set(("danger", f"The Connect change may have been applied, but it could not be recorded "
                                        f"in the database: {exc}"))
            return
        adm_lock_msg.set(("success" if result.ok else "danger", result.message))
        ui.notification_show(result.message, type="message" if result.ok else "error", duration=8)
        admin_version.set(admin_version.get() + 1)
        notes_version.set(notes_version.get() + 1)  # refresh the violation history timeline

    @render.ui
    def adm_lock_result():
        kind, text = adm_lock_msg.get()
        return ui.div(text, class_=f"alert alert-{kind} mt-3 mb-0") if text else None

    def change_scope(list_type: str, add: bool) -> None:
        try:
            result = change_scope_list(DB, instance=action_instance() or "", text=input.scope_guids(),
                                       list_type=list_type, add=add, actor=username, reason=input.scope_reason())
        except QueryFailed as exc:
            scope_msg.set(("danger", str(exc)))
            return
        scope_msg.set(("success" if result.ok else "warning", result.message))
        if result.ok:
            ui.update_text_area("scope_guids", value="")
            admin_version.set(admin_version.get() + 1)

    @reactive.effect
    @reactive.event(input.scope_exclude_add)
    def _exclude_add():
        change_scope(SCOPE_EXCLUDED, True)

    @reactive.effect
    @reactive.event(input.scope_exclude_remove)
    def _exclude_remove():
        change_scope(SCOPE_EXCLUDED, False)

    @reactive.effect
    @reactive.event(input.scope_enforce_add)
    def _enforce_add():
        change_scope(SCOPE_ENFORCE_ONLY, True)

    @reactive.effect
    @reactive.event(input.scope_enforce_remove)
    def _enforce_remove():
        change_scope(SCOPE_ENFORCE_ONLY, False)

    @render.ui
    def scope_result():
        kind, text = scope_msg.get()
        return ui.div(text, class_=f"alert alert-{kind} mt-2 mb-0") if text else None

    @render.data_frame
    def scope_grid():
        admin_version()
        try:
            columns, rows = DB.list_scope()
        except QueryFailed as exc:
            return render.DataGrid(pd.DataFrame({"error": [str(exc)]}))
        df = _pretty(_display_frame(columns, rows), [c for c in columns if c != "instance"])
        return render.DataGrid(df, filters=True, height="300px", width="100%")

    @render.data_frame
    def actions_grid():
        admin_version()
        try:
            columns, rows = DB.list_admin_actions()
        except QueryFailed as exc:
            return render.DataGrid(pd.DataFrame({"error": [str(exc)]}))
        df = _display_frame(columns, rows)
        ok = list(df["success"]) if "success" in df.columns else []
        df = _pretty(df, [c for c in columns if c != "instance"])
        return render.DataGrid(df, filters=True, height="360px", width="100%",
                               styles=_row_styles(ok, {"no": LOCKED_TINT}))

    # --- SQL tab ----------------------------------------------------------------

    @reactive.effect
    @reactive.event(input.sql_example)
    def _load_example():
        if input.sql_example() in EXAMPLES:
            ui.update_text_area("sql_text", value=EXAMPLES[input.sql_example()])

    @reactive.effect
    @reactive.event(input.sql_run)
    def _run_sql():
        try:
            result = DB.run_readonly_sql(input.sql_text(), user=username or "unknown")
        except (QueryRejected, QueryFailed) as exc:
            sql_result.set(None)
            sql_message.set(("danger", str(exc)))
            return
        sql_result.set(result)
        note = f" Showing the first {SETTINGS.sql_max_rows:,} rows only." if result.truncated else ""
        sql_message.set(("success", f"{len(result.rows):,} rows in {result.elapsed_seconds:.2f}s.{note}"))

    @render.ui
    def sql_status():
        kind, text = sql_message.get()
        return ui.div(text, class_=f"alert alert-{kind} mt-3 mb-0") if text else None

    @render.data_frame
    def sql_grid():
        result = sql_result.get()
        if result is None:
            return render.DataGrid(pd.DataFrame())
        return render.DataGrid(_display_frame(result.columns, result.rows), filters=True,
                               height="480px", width="100%")

    @render.download(filename=lambda: f"compliance_query_{datetime.now():%Y%m%d_%H%M}.csv")
    def sql_download():
        result = sql_result.get()
        if result is not None:
            yield _display_frame(result.columns, result.rows).to_csv(index=False)


app = App(app_ui, server)
