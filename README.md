# Posit Connect Branch Compliance

This project checks that every Git-backed application on Posit Connect is deployed from:

- the required branch (`main` by default), and
- a repository in one of your approved GitHub organizations.

It has two parts:

| Part | File | Runs as |
|---|---|---|
| **Compliance job** | `compliance_job.qmd` (or `run_compliance.py`) | A scheduled Quarto document on Connect, e.g. every 15 minutes |
| **Dashboard** | `app.py` | A Shiny for Python app on Connect, restricted to admins |

- **One database per instance:** each Connect instance (for example Dev, QA and Prod, internal and external) has its own job, its own dashboard and its own PostgreSQL database. Rows are also tagged with `COMPLIANCE_INSTANCE`, which labels the data and the emails.
- **No built-in environment values:** server URLs, organizations, SMTP relay, email addresses and database credentials all come from environment variables, set in each content item's **Vars** panel on Connect. The repository contains none of them.

The job does **not** do vulnerability scanning.

## How it works

```
Connect scheduler -> compliance_job.qmd -> compliance_job()
  GET  /__api__/v1/content                    all content (administrator API key)
  GET  /__api__/v1/content/{guid}/repository  404 = not Git-backed; otherwise repository + branch
  classify each item:
    COMPLIANT       required branch + approved org -> log; resolve any open violation
    NON_COMPLIANT   wrong branch / unapproved org  -> record, email, grace period, lock
    UNKNOWN         branch/repo not reported       -> log only, never a violation
  PATCH /__api__/v1/content/{guid} {"locked": true, "locked_message": ...}   (only if enabled)
```

### Timeline for one non-compliant app

The example uses `GRACE_PERIOD_VALUE=3`, `GRACE_PERIOD_UNIT=days` and `BLOCKING_ENABLED=true`.

| When | What happens |
|---|---|
| Day 0 | The violation is recorded. The **first notice** goes to the owner (admins are added if the owner has no email). |
| Every run | Only `last_checked_at` is updated. No duplicate emails are sent. |
| Deadline minus 24 hours | The **final warning** goes to the owner, with admins on Cc. |
| Deadline | The app is **locked** and the **locked notice** goes to the owner and admins. |
| An admin unlocks the app in Connect | The job detects it and sends a **fix-window** email. The owner has `RELOCK_WINDOW_HOURS` to redeploy. |
| Fix window over, still non-compliant | The app is locked again. |
| Redeployed correctly | The violation is marked **RESOLVED**. The job never unlocks anything automatically. |

Emails are HTML, with a plain-text copy included. Run `python preview_emails.py` to see them, using placeholder data.

### Safety rules in the code

- Nothing runs unless `COMPLIANCE_SCAN_ENABLED=true`.
- Nothing is locked unless all of the following are true:
  - `BLOCKING_ENABLED=true`
  - a valid grace period longer than 24 hours is set
  - `DATABASE_URL` is set
  - the final warning was delivered
  - at least 24 hours have passed since that warning
- Status UNKNOWN never leads to an email or a lock.
- Apps locked outside the job are left alone.
- An unsupported lock response is never recorded as locked.
- The dashboard's **Admin** tab maintains two lists in the database. **Excluded** apps are never scanned, emailed or locked. When **Enforce only** has entries, emails and locking apply only to those apps, which is useful for testing.
- A PostgreSQL advisory lock, one per instance, stops two overlapping runs from both acting.
- One app failing doesn't stop the scan. An authentication failure (401 or 403) stops the run.

## Configuration (environment variables)

Set these in **Vars** on each Connect content item. See `.env.example` for the full list.

### Job (`compliance_job.qmd`)

| Variable | Required | Default | Notes |
|---|---|---|---|
| `COMPLIANCE_SCAN_ENABLED` | yes | `false` | Master switch |
| `COMPLIANCE_INSTANCE` | with a database | – | e.g. `prod-internal`, `qa-external`, `dev-internal`. Lowercase letters, digits, `-` and `_`. |
| `CONNECT_SERVER` | yes | *(set automatically by Connect)* | |
| `COMPLIANCE_CONNECT_API_KEY` | yes | – | **Administrator** API key from a dedicated service account. Falls back to `CONNECT_API_KEY`. |
| `ALLOWED_GIT_ORGS` | yes | – | Comma-separated GitHub organizations |
| `ALLOWED_GIT_HOST` | no | `github.com` | |
| `ORG_DISPLAY_NAME` | no | – | Organization name used in email wording |
| `REQUIRED_BRANCH` | no | `main` | |
| `GRACE_PERIOD_VALUE` / `GRACE_PERIOD_UNIT` | no | empty / `days` | `hours` or `days`. Must total **more than 24 hours**. While empty, nothing is ever locked. |
| `RELOCK_WINDOW_HOURS` | no | `4` | Fix window after an admin unlocks an app |
| `BLOCKING_ENABLED` | no | `false` | |
| `EMAIL_ENABLED` | no | `true` | |
| `DRY_RUN` | no | `false` | Detect and log only |
| `DATABASE_URL` | no | *(empty = dry run)* | `postgresql://<user>:<password>@<host>:5432/<db>?sslmode=require` |
| `DB_SCHEMA` | no | `posit_compliance` | |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SENDER` | for email | –, `25`, – | Your SMTP relay and sender address. Use the same values as the `SMTP` / `Server.SenderEmail` settings of your Connect server, so mail goes through the relay Connect already uses. |
| `SMTP_SENDER_NAME` | no | – | Display name, e.g. `Posit Connect` |
| `SMTP_STARTTLS`, `SMTP_USERNAME`, `SMTP_PASSWORD` | no | `false`, –, – | |
| `ADMIN_EMAILS` | recommended | – | Comma-separated. Admins receive the final warning, locked and fix-window emails. |
| `LOCK_MESSAGE` | no | built-in | Markdown shown to visitors of a locked app |
| `SCAN_INTERVAL_MINUTES` | no | `15` | Only used in email text. The real schedule is set in Connect. |

### Dashboard (`app.py`)

| Variable | Notes |
|---|---|
| `DASHBOARD_DATABASE_URL` | A least-privilege login (see `sql/roles.sql`). Falls back to `DATABASE_URL`. |
| `COMPLIANCE_CONNECT_API_KEY` | Administrator key, needed only for **Lock / Unlock** in the Admin tab. Without it, those buttons are disabled. |
| `DB_SCHEMA` | Same value as the job |
| `DASHBOARD_ALLOWED_USERS` / `DASHBOARD_ALLOWED_GROUPS` | Optional allow-list on top of Connect's access settings |
| `SQL_TIMEOUT_SECONDS` / `SQL_MAX_ROWS` | Limits for the SQL tab (defaults `30` / `5000`) |
| `DASHBOARD_DEMO` | `true` = sample data, for a local preview only. **Never set this on Connect.** |

## Database

The job creates everything on its first run, in schema `DB_SCHEMA`:

| Table | Purpose |
|---|---|
| `scan_runs` | One row per run: instance, start and end time, status, counts, error |
| `branch_violations` | One row per violation, holding its current state. At most one open violation per (instance, app), enforced by a unique index. |
| `violation_events` | Add-only history: detected, emailed, final warning, locked, unlocked, resolved, and so on |
| `content_compliance` | The latest status of every app on each instance |
| `branch_violation_notes` | Admin notes from the dashboard. Add-only. |
| `scan_scope` | The Excluded and Enforce-only lists, maintained in the Admin tab |
| `admin_actions` | Add-only audit log of manual lock and unlock actions and list changes |

`sql/roles.sql` creates two logins:
- **Job:** reads and writes the job tables.
- **Dashboard:** reads everything and can add notes, nothing else.

Never point the job at Connect's own internal database.

## Dashboard

- **Violations:**
  - summary cards and filters
  - details for each violation, including the standalone URL
  - history timeline
  - admin notes, which can only be added
- **All apps:** the latest status of every content item.
- **Scan runs:** recent runs, with failed runs highlighted.
- **Admin:**
  - lock or unlock any app by its GUID, after a confirmation that shows the app's name
  - add or remove GUIDs on the **Excluded** and **Enforce only** lists
  - every action is recorded in `admin_actions` with who did it
- **SQL query:** read-only SQL, with three layers of protection:
  - the query is checked before it runs
  - it runs in a read-only transaction with a timeout and a row limit
  - it uses the least-privilege login

  Every query is logged with the Connect user who ran it.

There's an instance selector in the top bar. To preview locally with sample data:

```
pip install -r requirements-dev.txt
DASHBOARD_DEMO=true shiny run app.py        # PowerShell: $env:DASHBOARD_DEMO="true"; shiny run app.py
```

## Testing safely

1. Run the unit tests (no network access needed): `pytest -q`
2. **Dry run against a real server:** set `COMPLIANCE_SCAN_ENABLED=true`, `CONNECT_SERVER`, `COMPLIANCE_CONNECT_API_KEY` and `ALLOWED_GIT_ORGS`, and leave `DATABASE_URL` empty. It only reads from Connect and logs every app's status.
3. **Add the database, blocking still off:** add one test app to **Enforce only** in the dashboard's Admin tab. You should get exactly one email, and `last_checked_at` should advance each run.
4. **Lock cycle on one non-production app:** set `BLOCKING_ENABLED=true` and a 25-hour grace period, and keep the test app on the Enforce-only list. To avoid waiting, move the deadline earlier in the database:
   ```sql
   UPDATE posit_compliance.branch_violations
      SET first_detected_at = now() - interval '25 hours', final_warning_at = now() - interval '25 hours'
    WHERE instance = '<instance>' AND content_guid = '<test guid>' AND status = 'NON_COMPLIANT';
   ```
   Locking ends active sessions immediately, so test it on non-production content first.

Exit codes for `run_compliance.py`: `0` OK, `1` configuration error, `2` Connect authentication failure, `3` other fatal error.

## Scheduling on Posit Connect

1. Publish this folder as a **Quarto document** with `compliance_job.qmd` as the primary file. Use a Python 3.11+ execution environment that includes Quarto.
2. Enter the variables under **Vars**.
3. Under **Schedule**, run it every 15 minutes, with "send email after update" off.
4. Under **Access**, restrict viewing to admins.

Repeat on each Connect instance, with its own `COMPLIANCE_INSTANCE` and API key.

5. On each instance, also publish `app.py` as a Shiny app for the dashboard, pointing at that instance's database.

## Security notes

- **No credentials or environment-specific values in this repository.** Keep them in Connect **Vars**, which stores them encrypted. `.env` files, Posit publishing folders (which contain server URLs), caches and email previews are all excluded by `.gitignore`.
- **Secrets are never logged:** API keys, database passwords and SMTP passwords. Settings objects hide them from `repr()`.
- **API key:** use a dedicated administrator service account for the job, and rotate its key regularly.
- **Email safety:** values in emails are HTML-escaped, and only `http`/`https` links are made clickable.
