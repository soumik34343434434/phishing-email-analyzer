"""Render a Report as JSON, Markdown, or an IOC CSV."""

from __future__ import annotations

import csv
import io
import json

from .analyzer import VERDICT_CLEAN, VERDICT_PHISHING
from .models import Report, Severity
from .urls import defang

_SEVERITY_ICON = {Severity.HIGH: "HIGH", Severity.MEDIUM: "MEDIUM", Severity.LOW: "LOW", Severity.INFO: "INFO"}


def to_dict(report: Report) -> dict:
    email = report.email
    return {
        "source": report.source,
        "verdict": report.verdict,
        "score": report.score,
        "email": {
            "subject": email.subject,
            "from": email.from_addr,
            "from_display": email.from_display,
            "reply_to": email.reply_to,
            "return_path": email.return_path,
            "to": email.to,
            "date": email.date,
            "message_id": email.message_id,
            "attachments": [a.__dict__ for a in email.attachments],
        },
        "findings": [f.to_dict() for f in report.findings],
        "indicators": [i.to_dict() for i in report.indicators],
    }


def to_json(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2)


def to_markdown(report: Report) -> str:
    email = report.email
    lines = [
        f"# Phishing triage: {email.subject or '(no subject)'}",
        "",
        f"**Verdict:** {report.verdict} (score {report.score}/100)",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| From | {_md(email.from_display)} `{email.from_addr}` |",
        f"| Reply-To | {_md(', '.join(email.reply_to)) or '-'} |",
        f"| Return-Path | {_md(email.return_path) or '-'} |",
        f"| To | {_md(', '.join(email.to)) or '-'} |",
        f"| Date | {_md(email.date) or '-'} |",
        f"| Attachments | {len(email.attachments)} |",
        "",
        "## Findings",
        "",
    ]
    visible = [f for f in report.findings if f.severity > Severity.INFO]
    if visible:
        lines += ["| Severity | Finding | Detail | ATT&CK |", "|---|---|---|---|"]
        for f in visible:
            lines.append(f"| {_SEVERITY_ICON[f.severity]} | {_md(f.title)} | {_md(_defang_text(f.detail))} | {f.attack or '-'} |")
    else:
        lines.append("No findings above INFO.")
    notes = [f for f in report.findings if f.severity == Severity.INFO]
    if notes:
        lines += ["", "Notes:"] + [f"- {f.title}: {_defang_text(f.detail)}" for f in notes]

    lines += ["", "## Indicators (defanged)", ""]
    if report.indicators:
        lines += ["| Type | Value | Context |", "|---|---|---|"]
        for ind in report.indicators:
            value = defang(ind.value) if ind.kind == "url" else (ind.value.replace(".", "[.]") if ind.kind in {"domain", "ip"} else ind.value)
            lines.append(f"| {ind.kind} | `{value}` | {_md(ind.context)} |")
    else:
        lines.append("None.")

    lines += ["", "## Recommended actions", ""] + [f"- {a}" for a in recommended_actions(report)]
    return "\n".join(lines) + "\n"


def to_ioc_csv(reports: list[Report]) -> str:
    """Raw (not defanged) IOCs for import into block lists. Review before importing."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["source", "type", "value", "context", "verdict"])
    for report in reports:
        for ind in report.indicators:
            writer.writerow([report.source, ind.kind, ind.value, ind.context, report.verdict])
    return buffer.getvalue()


def recommended_actions(report: Report) -> list[str]:
    if report.verdict == VERDICT_CLEAN:
        return ["No action needed beyond normal handling. Re-check if the user reports more context."]
    actions = []
    if report.verdict == VERDICT_PHISHING:
        actions.append("Search for and remove copies of this message from all mailboxes (same sender, subject or links).")
        actions.append("Block the sender address/domain and the link domains in the email gateway or Tenant Allow/Block List.")
    else:
        actions.append("Hold the message in quarantine and confirm with the sender through a known-good channel.")
    checks = {f.check for f in report.findings}
    if any(c.startswith("links.") for c in checks):
        actions.append("Check proxy/URL-click logs for users who opened the links; reset credentials for anyone who entered them.")
    if any(c.startswith("attachments.") for c in checks):
        actions.append("Hunt for the attachment SHA256 hashes on endpoints (EDR) and block them.")
    if "content.financial" in checks:
        actions.append("Warn finance: verify any payment or bank-detail change by phone using a known number.")
    return actions


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _defang_text(text: str) -> str:
    """Defang any URL inside free text so reports are safe to paste."""
    import re

    return re.sub(r"https?://\S+", lambda m: defang(m.group(0)), text)
