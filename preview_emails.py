"""Write sample HTML emails to a folder so they can be reviewed in a browser.

    python preview_emails.py [output_folder]

Uses made-up sample data; nothing is sent and no server or database is used.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from compliance.config import Settings
from compliance.models import Violation
from compliance.notifier import NoticeKind, build_message


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "email_previews")
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    # Placeholder values only (example.com / example-org); nothing real is used.
    settings = Settings(
        admin_emails=("posit-admins@example.com",), database_url="preview", blocking_enabled=True,
        grace_period=timedelta(days=3), smtp_host="preview", smtp_sender="noreply@example.com",
        allowed_git_orgs=("example-org", "example-labs"), org_display_name="Example Org",
    )
    server = "https://connect.example.com"
    guid = "3f2a9c1e-7b4d-4e8a-9f10-2c6d8e4b1a77"
    v = Violation(
        content_guid=guid, app_name="Poverty Dashboard", required_branch="main",
        reasons=["WRONG_BRANCH"], first_detected_at=now - timedelta(days=2), last_checked_at=now,
        instance="prod-internal", connect_server=server, app_url=f"{server}/content/{guid}/",
        dashboard_url=f"{server}/connect/#/apps/{guid}", owner_username="asmith",
        owner_email="asmith@example.com", repository="https://github.com/example-org/poverty-dashboard",
        detected_branch="feature/new-maps",
    )
    samples = {
        "1_first_notice.html": (NoticeKind.FIRST_NOTICE, None),
        "2_final_warning.html": (NoticeKind.FINAL_WARNING, now + timedelta(days=1)),
        "3_locked.html": (NoticeKind.LOCKED, None),
        "4_fix_window.html": (NoticeKind.UNLOCKED_FIX_WINDOW, now + timedelta(hours=4)),
    }
    links = []
    for name, (kind, due) in samples.items():
        content = build_message(kind, v, settings, due)
        (out / name).write_text(content.html, encoding="utf-8")
        (out / name.replace(".html", ".txt")).write_text(f"Subject: {content.subject}\n\n{content.text}", encoding="utf-8")
        links.append(f'<li><a href="{name}">{content.subject}</a></li>')
    (out / "index.html").write_text(
        "<!DOCTYPE html><meta charset='utf-8'><title>Email previews</title>"
        "<body style='font-family:Segoe UI,Arial;padding:24px'><h2>Compliance email previews</h2><ul>"
        + "".join(links) + "</ul></body>", encoding="utf-8")
    print(f"Wrote {len(samples)} previews to {out.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
