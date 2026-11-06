"""Parse an RFC 5322 / MIME message into a ParsedEmail.

Only the standard library is used, and nothing in the message is executed,
rendered or fetched.
"""

from __future__ import annotations

import hashlib
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path

from .models import Attachment, ParsedEmail


def parse_file(path: str | Path) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes())


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)  # type: ignore[assignment]

    from_display, from_addr = parseaddr(_header(msg, "From"))
    _, return_path = parseaddr(_header(msg, "Return-Path"))

    parsed = ParsedEmail(
        subject=_header(msg, "Subject"),
        from_display=from_display,
        from_addr=from_addr.lower(),
        reply_to=[addr.lower() for _, addr in getaddresses(msg.get_all("Reply-To", [])) if addr],
        return_path=return_path.lower(),
        to=[addr.lower() for _, addr in getaddresses(msg.get_all("To", [])) if addr],
        date=_header(msg, "Date"),
        message_id=_header(msg, "Message-ID"),
        # Header order is top-down: the first Authentication-Results /
        # Received header was added by the server closest to the recipient.
        auth_results=[str(h) for h in msg.get_all("Authentication-Results", [])],
        received=[str(h) for h in msg.get_all("Received", [])],
    )

    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        content_type = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            parsed.attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=content_type,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
        elif content_type == "text/plain":
            text_parts.append(_text(part))
        elif content_type == "text/html":
            html_parts.append(_text(part))

    parsed.text_body = "\n".join(text_parts)
    parsed.html_body = "\n".join(html_parts)
    return parsed


def _header(msg: EmailMessage, name: str) -> str:
    value = msg.get(name)
    return str(value).strip() if value is not None else ""


def _text(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")
