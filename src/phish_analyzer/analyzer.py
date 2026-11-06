"""Run every check on a parsed email and build a Report."""

from __future__ import annotations

import ipaddress

from . import checks
from .models import Finding, Indicator, ParsedEmail, Report, Severity
from .urls import extract_links

WEIGHTS = {Severity.HIGH: 30, Severity.MEDIUM: 15, Severity.LOW: 5, Severity.INFO: 0}
MAX_REPEATS_PER_CHECK = 2  # ten bad links should not count ten times
PHISHING_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 25

VERDICT_PHISHING = "Likely phishing"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_CLEAN = "No strong phishing indicators"


def analyze(email: ParsedEmail, protected_domains: list[str] | None = None, source: str = "") -> Report:
    protected = [d.lower().strip(".") for d in (protected_domains or []) if d.strip()]
    extracted = extract_links(email.text_body, email.html_body)

    findings: list[Finding] = []
    findings += checks.check_authentication(email)
    findings += checks.check_sender(email, protected)
    findings += checks.check_links(extracted, protected)
    findings += checks.check_attachments(email.attachments)
    findings += checks.check_content(email, extracted.html_text)
    if not protected:
        findings.append(Finding("config.no_protected_domains", Severity.INFO, "Lookalike checks skipped",
                                "Pass --protected-domain (your organisation's domains) to detect "
                                "lookalike senders and links."))

    score = score_findings(findings)
    return Report(
        source=source,
        email=email,
        findings=sorted(findings, key=lambda f: (-f.severity, f.check)),
        indicators=collect_indicators(email, extracted.links),
        score=score,
        verdict=verdict_for(score, findings),
    )


def score_findings(findings: list[Finding]) -> int:
    counts: dict[str, int] = {}
    total = 0
    for finding in findings:
        counts[finding.check] = counts.get(finding.check, 0) + 1
        if counts[finding.check] <= MAX_REPEATS_PER_CHECK:
            total += WEIGHTS[finding.severity]
    return min(total, 100)


def verdict_for(score: int, findings: list[Finding]) -> str:
    if score >= PHISHING_THRESHOLD:
        return VERDICT_PHISHING
    if score >= SUSPICIOUS_THRESHOLD or any(f.severity == Severity.HIGH for f in findings):
        return VERDICT_SUSPICIOUS
    return VERDICT_CLEAN


def collect_indicators(email: ParsedEmail, links) -> list[Indicator]:
    indicators: list[Indicator] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, context: str) -> None:
        if value and (kind, value) not in seen:
            seen.add((kind, value))
            indicators.append(Indicator(kind, value, context))

    add("email", email.from_addr, "From address")
    for reply in email.reply_to:
        add("email", reply, "Reply-To address")
    if email.from_domain:
        add("domain", email.from_domain, "Sender domain")
    ip = checks.originating_ip(email)
    if ip:
        add("ip", ip, "Originating IP (first public hop in Received headers)")
    for link in links:
        add("url", link.url, f"Link ({link.source})")
        if link.host:
            add("ip" if _is_ip(link.host) else "domain", link.host, "Link host")
    for att in email.attachments:
        add("sha256", att.sha256, f"Attachment {att.filename}")
    return indicators


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
