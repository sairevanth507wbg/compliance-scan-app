"""Email notifications over SMTP (relay configured with SMTP_HOST / SMTP_PORT).

Every email is sent as multipart/alternative: a styled HTML version plus a
plain-text version for clients that do not render HTML. The HTML uses only
tables and inline styles (no images, scripts or external CSS) so it renders
the same in Outlook desktop, Outlook web and mobile clients. Every value that
comes from Connect or Git is HTML-escaped.
"""

from __future__ import annotations

import html
import logging
import smtplib
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr
from enum import Enum

from .config import Settings
from .models import Violation, ViolationReason

log = logging.getLogger("branch_compliance.email")


class NoticeKind(str, Enum):
    FIRST_NOTICE = "FIRST_NOTICE"
    FINAL_WARNING = "FINAL_WARNING"
    LOCKED = "LOCKED"
    UNLOCKED_FIX_WINDOW = "UNLOCKED_FIX_WINDOW"


_SUBJECTS = {
    NoticeKind.FIRST_NOTICE: "[Action required] Posit Connect app '{name}' is not deployed from an approved main branch",
    NoticeKind.FINAL_WARNING: "[FINAL WARNING] Posit Connect app '{name}' will be locked on {due}",
    NoticeKind.LOCKED: "[Locked] Posit Connect app '{name}' has been locked",
    NoticeKind.UNLOCKED_FIX_WINDOW: "[Fix window] Posit Connect app '{name}' was unlocked - redeploy from main by {due}",
}

# (badge, accent colour, light background) per notice
_THEME = {
    NoticeKind.FIRST_NOTICE: ("Action required", "#b45309", "#fffbeb"),
    NoticeKind.FINAL_WARNING: ("Final warning", "#b91c1c", "#fef2f2"),
    NoticeKind.LOCKED: ("Application locked", "#7f1d1d", "#fef2f2"),
    NoticeKind.UNLOCKED_FIX_WINDOW: ("Fix window open", "#1d4ed8", "#eff6ff"),
}

_FONT = "'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
_MONO = "Consolas, 'Courier New', monospace"


@dataclass(frozen=True)
class EmailContent:
    subject: str
    text: str
    html: str


def _fmt(ts: datetime | None) -> str:
    return ts.strftime("%Y-%m-%d %H:%M UTC") if ts else "-"


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _org_list(settings: Settings) -> str:
    return ", ".join(f"{settings.allowed_git_host}/{o}" for o in settings.allowed_git_orgs)


def _inventory(settings: Settings) -> str:
    """e.g. 'the approved Acme GitHub organizations (github.com/acme, github.com/acme-labs)'"""
    name = f"{settings.org_display_name} " if settings.org_display_name else ""
    return f"the approved {name}GitHub organizations ({_org_list(settings)})"


def _safe_url(url: str | None) -> str | None:
    return url if url and str(url).startswith(("https://", "http://")) else None


# ----- content shared by both formats ------------------------------------------


@dataclass(frozen=True)
class _Parts:
    subject: str
    headline: str
    intro: str
    callout_title: str
    callout: str
    reasons: list[str]          # plain sentences
    steps: list[str]            # plain sentences


def _parts(kind: NoticeKind, v: Violation, settings: Settings, due: datetime | None) -> _Parts:
    subject = _SUBJECTS[kind].format(name=v.app_name, due=_fmt(due))
    if v.instance:
        subject = f"[{v.instance}] {subject}"
    orgs = _org_list(settings)

    if kind is NoticeKind.FIRST_NOTICE:
        headline = "Your application is not deployed from an approved source"
        intro = "Your Posit Connect application does not meet the Git deployment policy."
        if settings.blocking_effective and settings.grace_period is not None:
            callout_title = f"Fix by {_fmt(v.first_detected_at + settings.grace_period)}"
            callout = ("If the application is still non-compliant then, it will be locked. "
                       "You will receive a final warning 24 hours before that.")
        else:
            callout_title = "Please fix this as soon as possible"
            callout = "Non-compliant applications may be locked by the Posit Connect administrators."
    elif kind is NoticeKind.FINAL_WARNING:
        headline = f"Your application will be locked on {_fmt(due)}"
        intro = "This is the final warning: your Posit Connect application is still non-compliant."
        callout_title = f"Locking on or after {_fmt(due)}"
        callout = ("Locking stops the application immediately, ends active sessions, and blocks new "
                   "deployments until an administrator unlocks it.")
    elif kind is NoticeKind.LOCKED:
        hours = settings.relock_window.total_seconds() / 3600
        headline = "Your application has been locked"
        intro = "Your Posit Connect application has been locked because it remained non-compliant."
        callout_title = "Visitors now see a lock message instead of the application"
        callout = ("Locked content cannot be redeployed. Contact the Posit Connect administrators to unlock it. "
                   f"After unlocking you will have {hours:g} hours to redeploy from the approved branch "
                   "before it is locked again.")
    else:
        headline = f"Redeploy from {v.required_branch} by {_fmt(due)}"
        intro = "An administrator has unlocked your Posit Connect application so you can fix it."
        callout_title = f"Fix window ends {_fmt(due)}"
        callout = "If the application is still non-compliant then, it will be locked again."

    reasons = []
    if ViolationReason.UNAPPROVED_REPOSITORY.value in v.reasons:
        reasons.append(f"Repository {v.repository} is not in {_inventory(settings)}.")
    if ViolationReason.WRONG_BRANCH.value in v.reasons:
        reasons.append(f"Deployed from branch '{v.detected_branch}' instead of '{v.required_branch}'.")

    steps = [
        f"Merge your changes into the '{v.required_branch}' branch of a repository under {orgs}.",
        f"Redeploy the application to Posit Connect from that repository and the '{v.required_branch}' branch.",
        "The compliance check runs automatically and closes this issue "
        "automatically once the application is compliant.",
    ]
    return _Parts(subject, headline, intro, callout_title, callout, reasons, steps)


def _detail_rows(v: Violation) -> list[tuple[str, str, bool]]:
    """(label, value, monospace)"""
    return [
        ("Application", v.app_name, False),
        ("Posit Connect", v.connect_server or "-", False),
        ("Standalone URL", v.app_url or "-", False),
        ("Owner", f"{v.owner_username or '-'} ({v.owner_email or 'no email on file'})", False),
        ("Repository", v.repository or "-", True),
        ("Deployed branch", v.detected_branch or "unknown", True),
        ("Required branch", v.required_branch, True),
        ("First detected", _fmt(v.first_detected_at), False),
        ("Content GUID", v.content_guid, True),
    ]


# ----- renderers -------------------------------------------------------------------


def _render_text(p: _Parts, v: Violation, settings: Settings) -> str:
    owner = v.owner_username or "application owner"
    lines = [f"Hello {owner},", "", p.intro, "", f"{p.callout_title}. {p.callout}", ""]
    lines += [f"{label + ':':<18} {value}" for label, value, _ in _detail_rows(v)]
    lines += [f"{'Connect settings:':<18} {v.dashboard_url or '-'}", "", "Issue(s):"]
    lines += [f"  - {r}" for r in p.reasons]
    lines += ["", "What you need to do:"]
    lines += [f"  {i}. {s}" for i, s in enumerate(p.steps, 1)]
    lines += ["", "This is an automated message from the Posit Connect compliance job."]
    if settings.admin_emails:
        lines.append(f"Questions: {', '.join(settings.admin_emails)}")
    return "\n".join(lines)


def _render_html(kind: NoticeKind, p: _Parts, v: Violation, settings: Settings) -> str:
    badge, accent, light = _THEME[kind]
    owner = v.owner_username or "application owner"

    def detail_row(label: str, value: str, mono: bool) -> str:
        link = {"Standalone URL": v.app_url, "Posit Connect": v.connect_server}.get(label)
        if _safe_url(link):
            cell = f'<a href="{_e(link)}" style="color:#1d4ed8;text-decoration:underline;">{_e(link)}</a>'
        else:
            style = f"font-family:{_MONO};font-size:13px;" if mono else ""
            cell = f'<span style="{style}">{_e(value)}</span>'
        return (
            '<tr>'
            f'<td style="padding:7px 12px 7px 0;color:#6b7280;font-size:13px;white-space:nowrap;'
            f'vertical-align:top;border-bottom:1px solid #f3f4f6;width:150px;">{_e(label)}</td>'
            f'<td style="padding:7px 0;color:#111827;font-size:14px;word-break:break-all;'
            f'border-bottom:1px solid #f3f4f6;">{cell}</td>'
            '</tr>'
        )

    def button(url: str | None, label: str, primary: bool) -> str:
        if not _safe_url(url):
            return ""
        bg, fg, border = (accent, "#ffffff", accent) if primary else ("#ffffff", "#1f2937", "#d1d5db")
        return (
            '<td style="padding:0 8px 8px 0;">'
            f'<table role="presentation" cellpadding="0" cellspacing="0"><tr>'
            f'<td bgcolor="{bg}" style="border-radius:6px;border:1px solid {border};">'
            f'<a href="{_e(url)}" style="display:inline-block;padding:10px 18px;font-family:{_FONT};'
            f'font-size:14px;font-weight:600;color:{fg};text-decoration:none;">{_e(label)}</a>'
            '</td></tr></table></td>'
        )

    reasons = "".join(f'<li style="margin:0 0 6px 0;">{_e(r)}</li>' for r in p.reasons)
    steps = "".join(f'<li style="margin:0 0 6px 0;">{_e(s)}</li>' for s in p.steps)
    contact = ""
    if settings.admin_emails:
        links = ", ".join(f'<a href="mailto:{_e(a)}" style="color:#6b7280;">{_e(a)}</a>' for a in settings.admin_emails)
        contact = f"<br>Questions? Contact the Posit Connect administrators: {links}"
    h3 = (f'style="margin:24px 0 10px 0;font-size:15px;color:#111827;font-family:{_FONT};'
          'border-bottom:2px solid #e5e7eb;padding-bottom:6px;"')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
<title>{_e(p.subject)}</title>
</head>
<body style="margin:0;padding:0;background-color:#f3f4f6;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">{_e(p.headline)} - {_e(v.app_name)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#f3f4f6" style="background-color:#f3f4f6;">
<tr><td align="center" style="padding:24px 12px;">
<table role="presentation" width="640" cellpadding="0" cellspacing="0"
       style="width:640px;max-width:100%;background-color:#ffffff;border:1px solid #e5e7eb;border-radius:8px;">
  <tr>
    <td bgcolor="{accent}" style="background-color:{accent};padding:20px 28px;border-radius:8px 8px 0 0;font-family:{_FONT};">
      <div style="font-size:12px;letter-spacing:1px;text-transform:uppercase;color:#ffffff;opacity:0.9;">
        {_e(badge)}{' &middot; ' + _e(v.instance) if v.instance else ''}</div>
      <div style="font-size:21px;line-height:1.3;font-weight:600;color:#ffffff;margin-top:6px;">{_e(p.headline)}</div>
    </td>
  </tr>
  <tr>
    <td style="padding:24px 28px 8px 28px;font-family:{_FONT};font-size:15px;line-height:1.55;color:#1f2937;">
      <p style="margin:0 0 12px 0;">Hello {_e(owner)},</p>
      <p style="margin:0 0 18px 0;">{_e(p.intro)}</p>

      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td bgcolor="{light}" style="background-color:{light};border-left:4px solid {accent};padding:14px 16px;">
          <div style="font-weight:600;color:{accent};font-size:15px;">{_e(p.callout_title)}</div>
          <div style="margin-top:4px;font-size:14px;color:#374151;">{_e(p.callout)}</div>
        </td></tr>
      </table>

      <h3 {h3}>What is wrong</h3>
      <ul style="margin:0;padding-left:20px;font-size:14px;">{reasons}</ul>

      <h3 {h3}>Application details</h3>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-family:{_FONT};">
        {''.join(detail_row(*row) for row in _detail_rows(v))}
      </table>

      <h3 {h3}>What you need to do</h3>
      <ol style="margin:0;padding-left:20px;font-size:14px;">{steps}</ol>

      <table role="presentation" cellpadding="0" cellspacing="0" style="margin-top:20px;"><tr>
        {button(v.app_url, "Open application", True)}
        {button(v.dashboard_url, "Open in Posit Connect", False)}
      </tr></table>

      <p style="margin:18px 0 0 0;font-size:13px;color:#6b7280;">
        Policy: Git-backed applications must be deployed from the <strong>{_e(v.required_branch)}</strong> branch
        of a repository in {_e(_inventory(settings))}.
      </p>
    </td>
  </tr>
  <tr>
    <td style="padding:18px 28px 22px 28px;border-top:1px solid #e5e7eb;font-family:{_FONT};font-size:12px;
               line-height:1.5;color:#6b7280;">
      This is an automated message from the Posit Connect compliance job{(' (' + _e(v.instance) + ')') if v.instance else ''}.{contact}
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>"""


def build_message(kind: NoticeKind, v: Violation, settings: Settings, due: datetime | None = None) -> EmailContent:
    parts = _parts(kind, v, settings, due)
    return EmailContent(parts.subject, _render_text(parts, v, settings), _render_html(kind, parts, v, settings))


class EmailNotifier:
    def __init__(self, settings: Settings):
        self.settings = settings

    def send(self, to: list[str], cc: list[str], content: EmailContent) -> bool:
        """Returns True only when the SMTP server accepted the message."""
        s = self.settings
        to = [a for a in dict.fromkeys(to) if a]
        cc = [a for a in dict.fromkeys(cc) if a and a not in to]
        if not to and cc:
            to, cc = cc, []
        if not to:
            log.warning("No recipients for '%s'; email not sent.", content.subject)
            return False
        if not s.email_effective:
            log.info("Email disabled (EMAIL_ENABLED/SMTP/dry run); would have sent '%s' to %s",
                     content.subject, to + cc)
            return False

        msg = EmailMessage()
        msg["From"] = formataddr((s.smtp_sender_name, s.smtp_sender)) if s.smtp_sender_name else s.smtp_sender
        msg["To"] = ", ".join(to)
        if cc:
            msg["Cc"] = ", ".join(cc)
        msg["Subject"] = content.subject
        msg.set_content(content.text)                    # plain-text fallback
        msg.add_alternative(content.html, subtype="html")  # preferred by mail clients
        try:
            with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=30) as smtp:
                if s.smtp_starttls:
                    smtp.starttls()
                if s.smtp_username:
                    smtp.login(s.smtp_username, s.smtp_password)
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            log.error("Email delivery failed for '%s': %s", content.subject, type(exc).__name__)
            return False
        log.info("Notification sent: '%s' to=%s cc=%s", content.subject, to, cc)
        return True
