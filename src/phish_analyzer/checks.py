"""Individual checks. Each returns a list of Findings and never raises on bad input."""

from __future__ import annotations

import ipaddress
import re

from . import domains
from .models import Attachment, Finding, ParsedEmail, Severity, domain_of
from .urls import ExtractedLinks, Link, domain_in_text, host_of, userinfo_of

# MITRE ATT&CK technique IDs used below
PHISHING = "T1566"
SPEARPHISHING_ATTACHMENT = "T1566.001"
SPEARPHISHING_LINK = "T1566.002"
IMPERSONATION = "T1656"
DOUBLE_FILE_EXTENSION = "T1036.007"
HTML_SMUGGLING = "T1027.006"

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf",
    "ga", "work", "rest", "support", "cam", "icu", "buzz",
}
EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
    "hta", "ps1", "lnk", "msi", "jar", "dll", "cpl", "reg", "xll",
}
CONTAINER_EXTENSIONS = {"iso", "img", "vhd", "vhdx"}  # bypass Mark-of-the-Web
HTML_EXTENSIONS = {"html", "htm", "shtml", "svg"}
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "ace", "cab"}
DECOY_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "csv"}

KEYWORD_GROUPS: dict[str, tuple[Severity, list[str]]] = {
    "credential": (Severity.LOW, [
        "verify your account", "confirm your password", "password will expire",
        "password expires", "update your payment", "unusual sign-in", "sign in to continue",
        "login to continue", "validate your mailbox", "re-enter your credentials",
    ]),
    "urgency": (Severity.LOW, [
        "urgent", "immediately", "within 24 hours", "will be suspended",
        "final notice", "action required", "act now", "today only",
    ]),
    "financial": (Severity.MEDIUM, [
        "wire transfer", "gift card", "bank details", "change of bank",
        "new bank account", "payment overdue", "outstanding invoice", "remittance",
    ]),
    "secrecy": (Severity.LOW, [
        "keep this confidential", "do not tell", "don't mention this", "between us",
    ]),
}

_IPV4_IN_BRACKETS = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
# Internal ranges skipped when looking for the originating IP. Listed explicitly
# because ipaddress.is_private also covers the RFC 5737 documentation ranges,
# which the bundled samples use in place of real attacker IPs.
_INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8",
)]
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


# ---------------------------------------------------------------- authentication

def parse_auth_results(headers: list[str]) -> dict[str, str]:
    """First result per mechanism, from the top-most (recipient-side) header."""
    results: dict[str, str] = {}
    for header in headers:
        for mechanism, result in _AUTH_RE.findall(header):
            results.setdefault(mechanism.lower(), result.lower())
    return results


def check_authentication(email: ParsedEmail) -> list[Finding]:
    results = parse_auth_results(email.auth_results)
    if not results:
        return [Finding("auth.missing", Severity.LOW, "No authentication results",
                        "The message has no Authentication-Results header, so SPF, DKIM and DMARC "
                        "cannot be confirmed.")]
    findings = []
    dmarc = results.get("dmarc")
    if dmarc == "fail":
        findings.append(Finding("auth.dmarc_fail", Severity.HIGH, "DMARC failed",
                                f"The From domain ({email.from_domain}) is not aligned with a passing SPF "
                                "or DKIM result - a strong spoofing signal.", PHISHING))
    elif dmarc == "none":
        findings.append(Finding("auth.dmarc_none", Severity.LOW, "Sender domain has no DMARC policy",
                                f"{email.from_domain or 'The sender'} publishes no DMARC policy, so "
                                "spoofing it is not blocked."))
    spf = results.get("spf")
    if spf in {"fail", "softfail"}:
        findings.append(Finding("auth.spf_fail", Severity.MEDIUM if spf == "fail" else Severity.LOW,
                                f"SPF {spf}", "The sending server is not authorised by the envelope "
                                "sender's SPF record.", PHISHING))
    dkim = results.get("dkim")
    if dkim == "fail":
        findings.append(Finding("auth.dkim_fail", Severity.MEDIUM, "DKIM signature failed",
                                "The DKIM signature did not verify: the message may have been altered "
                                "or the signature forged.", PHISHING))
    if not findings and all(results.get(m) == "pass" for m in ("spf", "dkim", "dmarc")):
        findings.append(Finding("auth.pass", Severity.INFO, "SPF, DKIM and DMARC passed",
                                "Authentication passed. This proves who sent it, not that it is safe: "
                                "attackers authenticate their own lookalike domains."))
    return findings


# ---------------------------------------------------------------- sender identity

def check_sender(email: ParsedEmail, protected: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    from_domain = email.from_domain

    if from_domain and protected:
        match = domains.lookalike(from_domain, protected)
        if match:
            target, reason, strong = match
            findings.append(Finding("sender.lookalike_domain", Severity.HIGH if strong else Severity.MEDIUM,
                                    "Sender domain imitates a protected domain",
                                    f"{from_domain}: {reason}.", IMPERSONATION))
        if domains.is_punycode(from_domain):
            findings.append(Finding("sender.punycode", Severity.MEDIUM, "Punycode sender domain",
                                    f"{from_domain} decodes to {domains.decode_idna(from_domain)}.",
                                    IMPERSONATION))

    display = email.from_display.lower()
    embedded = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", display)
    if embedded and embedded.group(0) != email.from_addr:
        findings.append(Finding("sender.display_name_address", Severity.HIGH,
                                "Display name contains a different address",
                                f"Display name shows {embedded.group(0)} but the real sender is "
                                f"{email.from_addr}.", IMPERSONATION))
    elif protected and from_domain and not _is_protected(from_domain, protected):
        for p in protected:
            label = domains.registrable_domain(p).split(".")[0]
            if len(label) >= 4 and label in display:
                findings.append(Finding("sender.display_name_brand", Severity.MEDIUM,
                                        "Display name uses a protected brand",
                                        f"'{email.from_display}' but the address is {email.from_addr}.",
                                        IMPERSONATION))
                break

    from_reg = domains.registrable_domain(from_domain) if from_domain else ""
    for reply in email.reply_to:
        reply_reg = domains.registrable_domain(domain_of(reply))
        if from_reg and reply_reg and reply_reg != from_reg:
            findings.append(Finding("sender.reply_to_mismatch", Severity.MEDIUM, "Reply-To goes elsewhere",
                                    f"Replies go to {reply}, not {email.from_addr}.", IMPERSONATION))
    if email.return_path and from_reg:
        rp_reg = domains.registrable_domain(domain_of(email.return_path))
        if rp_reg and rp_reg != from_reg:
            findings.append(Finding("sender.return_path_mismatch", Severity.LOW,
                                    "Return-Path differs from From",
                                    f"Bounces go to {rp_reg}. Normal for some mailing services; "
                                    "suspicious alongside other findings."))
    if not email.message_id:
        findings.append(Finding("sender.no_message_id", Severity.LOW, "Missing Message-ID",
                                "Legitimate mail servers almost always add a Message-ID."))
    return findings


def _is_protected(domain: str, protected: list[str]) -> bool:
    return any(domains.is_same_or_subdomain(domain, p) for p in protected)


def originating_ip(email: ParsedEmail) -> str | None:
    """The first public IPv4 in the bottom-most Received header that has one."""
    for header in reversed(email.received):
        for candidate in _IPV4_IN_BRACKETS.findall(header):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not any(ip in network for network in _INTERNAL_NETWORKS):
                return candidate
    return None


# ---------------------------------------------------------------- links

def check_links(extracted: ExtractedLinks, protected: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for link in extracted.links:
        findings.extend(_check_one_link(link, protected))
    if extracted.has_form:
        findings.append(Finding("links.html_form", Severity.HIGH, "Email contains an HTML form",
                                "Forms inside emails post data straight to the attacker"
                                + (" and this one asks for a password." if extracted.has_password_input else "."),
                                SPEARPHISHING_LINK))
    return findings


def _check_one_link(link: Link, protected: list[str]) -> list[Finding]:
    host = link.host
    findings: list[Finding] = []
    if not host:
        return findings
    shown = f"{link.url}" if len(link.url) <= 80 else link.url[:77] + "..."

    try:
        ipaddress.ip_address(host)
        findings.append(Finding("links.ip_host", Severity.MEDIUM, "Link points to a raw IP address",
                                f"{shown} ({link.source})", SPEARPHISHING_LINK))
    except ValueError:
        pass

    if userinfo_of(link.url):
        findings.append(Finding("links.userinfo", Severity.HIGH, "Link hides its real host behind '@'",
                                f"{shown}: everything before '@' is ignored by the browser.",
                                SPEARPHISHING_LINK))
    if domains.is_punycode(host):
        findings.append(Finding("links.punycode", Severity.MEDIUM, "Punycode link domain",
                                f"{host} decodes to {domains.decode_idna(host)}.", SPEARPHISHING_LINK))
    if domains.registrable_domain(host) in URL_SHORTENERS:
        findings.append(Finding("links.shortener", Severity.LOW, "URL shortener hides the destination",
                                shown, SPEARPHISHING_LINK))
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        findings.append(Finding("links.suspicious_tld", Severity.LOW, "Link uses a high-abuse TLD",
                                shown, SPEARPHISHING_LINK))
    if protected:
        match = domains.lookalike(host, protected)
        if match:
            _, reason, strong = match
            findings.append(Finding("links.lookalike_domain", Severity.HIGH if strong else Severity.MEDIUM,
                                    "Link domain imitates a protected domain", f"{host}: {reason}.",
                                    SPEARPHISHING_LINK))

    if link.anchor_text:
        shown_host = domain_in_text(link.anchor_text)
        if shown_host and domains.registrable_domain(shown_host) != domains.registrable_domain(host):
            findings.append(Finding("links.text_mismatch", Severity.HIGH, "Link text and destination differ",
                                    f"Shows '{link.anchor_text}' but opens {host}.", SPEARPHISHING_LINK))
    return findings


# ---------------------------------------------------------------- attachments

def check_attachments(attachments: list[Attachment]) -> list[Finding]:
    findings: list[Finding] = []
    for att in attachments:
        name = att.filename.lower().strip()
        parts = name.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        previous = parts[-2] if len(parts) > 2 else ""

        if previous in DECOY_EXTENSIONS and ext in EXECUTABLE_EXTENSIONS | HTML_EXTENSIONS | CONTAINER_EXTENSIONS:
            findings.append(Finding("attachments.double_extension", Severity.HIGH, "Double file extension",
                                    f"{att.filename} poses as .{previous} but is .{ext}.", DOUBLE_FILE_EXTENSION))
        if ext in EXECUTABLE_EXTENSIONS:
            findings.append(Finding("attachments.executable", Severity.HIGH, "Executable or script attachment",
                                    f"{att.filename} ({att.size} bytes, SHA256 {att.sha256[:16]}...)",
                                    SPEARPHISHING_ATTACHMENT))
        elif ext in HTML_EXTENSIONS:
            findings.append(Finding("attachments.html", Severity.HIGH, "HTML/SVG attachment",
                                    f"{att.filename}: HTML attachments are used for credential phishing "
                                    "pages and HTML smuggling.", HTML_SMUGGLING))
        elif ext in CONTAINER_EXTENSIONS:
            findings.append(Finding("attachments.container", Severity.HIGH, "Disk-image attachment",
                                    f"{att.filename}: ISO/IMG/VHD files are used to bypass Mark-of-the-Web.",
                                    SPEARPHISHING_ATTACHMENT))
        elif ext in MACRO_EXTENSIONS:
            findings.append(Finding("attachments.macro", Severity.MEDIUM, "Macro-enabled Office file",
                                    att.filename, SPEARPHISHING_ATTACHMENT))
        elif ext in ARCHIVE_EXTENSIONS:
            findings.append(Finding("attachments.archive", Severity.LOW, "Archive attachment",
                                    f"{att.filename}: inspect the contents; password-protected archives "
                                    "evade scanning.", SPEARPHISHING_ATTACHMENT))
    return findings


# ---------------------------------------------------------------- content

def check_content(email: ParsedEmail, html_text: str) -> list[Finding]:
    # Collapse whitespace so phrases split across wrapped lines still match.
    body = re.sub(r"\s+", " ", f"{email.subject}\n{email.text_body}\n{html_text}").lower()
    findings: list[Finding] = []
    for group, (severity, phrases) in KEYWORD_GROUPS.items():
        hits = sorted({p for p in phrases if p in body})
        if hits:
            findings.append(Finding(f"content.{group}", severity, f"{group.capitalize()} language",
                                    "Matched: " + ", ".join(f"'{h}'" for h in hits)))
    return findings
