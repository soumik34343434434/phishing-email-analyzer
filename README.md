# phish-analyzer

[![CI](https://github.com/soumik34343434434/phishing-email-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/soumik34343434434/phishing-email-analyzer/actions/workflows/ci.yml)

**Offline phishing triage for `.eml` files.** It reads a reported email and tells you, in under a second, why it is or isn't phishing. Every finding comes with evidence and a MITRE ATT&CK technique, and the IOCs are ready to paste into a block list.

I built this because reported-phishing triage is a large part of my SOC work, and the same questions come up every time:
- Did authentication pass?
- Is the sender imitating us?
- Does the link go where the text says?
- Is the attachment what it claims to be?

This tool answers them consistently and writes the answers up.

- **Offline by design.** It never fetches a URL, renders HTML or opens an attachment, so it is safe to run on live phishing.
- **No dependencies.** Python standard library only.
- **Explainable.** No black-box score. Every point in the score maps to a finding you can read.

## Quick start

```bash
pip install git+https://github.com/soumik34343434434/phishing-email-analyzer.git
phish-analyzer suspicious.eml --protected-domain yourcompany.com
```

Or from a clone, with no install:

```bash
PYTHONPATH=src python3 -m phish_analyzer samples/*.eml -p example.com
```

## Example

`samples/02_credential_phish.eml` is a fake "password expiry" email from `examp1e.com` (a 1-for-l swap of `example.com`):

```
$ phish-analyzer samples/02_credential_phish.eml -p example.com
```

**Verdict:** Likely phishing (score 100/100)

| Severity | Finding | Detail | ATT&CK |
|---|---|---|---|
| HIGH | DMARC failed | The From domain (examp1e.com) is not aligned with a passing SPF or DKIM result | T1566 |
| HIGH | Email contains an HTML form | Forms inside emails post data straight to the attacker and this one asks for a password. | T1566.002 |
| HIGH | Link domain imitates a protected domain | examp1e-login.test: hides the protected name 'example' behind character substitution. | T1566.002 |
| HIGH | Link text and destination differ | Shows 'hxxps://login[.]example[.]com/reset' but opens examp1e-login.test. | T1566.002 |
| HIGH | Sender domain imitates a protected domain | examp1e.com: character substitution imitating example.com | T1656 |
| MEDIUM | Reply-To goes elsewhere | Replies go to helpdesk@secure-mailbox.test, not it-support@examp1e.com. | T1656 |
| ... | | | |

The report continues with **defanged indicators** (`hxxp://examp1e-login[.]test/...`) and **recommended actions**:
- purge the message from mailboxes;
- block the sender and link domains;
- check URL-click logs;
- reset credentials for users who clicked.

## What it checks

| Area | Checks | ATT&CK |
|---|---|---|
| **Authentication** | SPF fail/softfail, DKIM fail, DMARC fail or no policy, missing `Authentication-Results`. Results are read from the top-most header, which your own server added. | T1566 |
| **Sender identity** | Lookalike sender domain, punycode domains, display name hiding a different address, display name using your brand, Reply-To and Return-Path mismatches, missing Message-ID | T1656 |
| **Links** | Visible text vs real destination, raw-IP hosts, `user@host` obfuscation, punycode, URL shorteners, high-abuse TLDs, lookalike link domains, embedded HTML forms (and password fields) | T1566.002 |
| **Attachments** | Double extensions (`Invoice.pdf.exe`), executables and scripts, HTML/SVG (smuggling), ISO/IMG/VHD (Mark-of-the-Web bypass), macro-enabled Office files, archives. SHA256 for every file. | T1566.001, T1036.007, T1027.006 |
| **Language** | Credential, urgency, financial (BEC) and secrecy phrases, matched across line breaks | - |

### Lookalike detection

With `--protected-domain example.com`, a sender or link domain is compared to each protected domain in several ways:

- **Character substitution:** `examp1e`, `exarnple` (rn→m), `ex@mple`, Cyrillic `еxample`.
- **Punycode:** labels are decoded first, so `xn--...` homoglyph domains are caught.
- **Edit distance ≤ 2:** catches typosquats like `exampel`.
- **Same name, other suffix:** `example.net`.
- **Brand inside another name:** `example-security.test`. This one is weaker, so it is reported at MEDIUM.

Subdomains of a protected domain (`mail.example.com`) are never flagged.

## Output formats

```bash
phish-analyzer mail.eml -p example.com                    # Markdown report to stdout
phish-analyzer mail.eml -p example.com -f json -o r.json  # JSON for SOAR / tickets
phish-analyzer *.eml   -p example.com --iocs iocs.csv     # raw IOCs for block lists
```

- **Markdown** reports are **defanged**, so they are safe to paste into tickets and chats.
- **The IOC CSV** keeps raw values (email, domain, IP, URL, SHA256) for import into a gateway or Tenant Allow/Block List. Review it before importing.

## Scoring

| Severity | Points |
|---|---|
| HIGH | 30 |
| MEDIUM | 15 |
| LOW | 5 |
| INFO | 0 |

- **Repeats:** each check counts at most twice, so ten bad links don't count ten times.
- **Cap:** the score is capped at 100.
- **Verdicts:**
  - **60+** → Likely phishing
  - **25+** → Suspicious (any HIGH finding also counts as Suspicious)
  - **Otherwise** → No strong phishing indicators

**A pass is not proof of safety.** Sample `04_bec_wire_transfer.eml` passes SPF, DKIM and DMARC, because the attacker registered `exarnple.com`. It is still flagged as Likely phishing because of the lookalike domain, the Reply-To mismatch and the payment-change language.

## Samples

`samples/` holds four synthetic emails:

| File | Scenario | Verdict |
|---|---|---|
| `01_legit_newsletter.eml` | Internal IT newsletter | No strong phishing indicators |
| `02_credential_phish.eml` | Password-expiry lure with a lookalike domain and an HTML form | Likely phishing |
| `03_malicious_attachments.eml` | Overdue invoice with `Invoice_4471.pdf.exe` and an `.htm` attachment | Likely phishing |
| `04_bec_wire_transfer.eml` | CEO fraud from an authenticated lookalike domain | Likely phishing |

The samples are safe:
- **Domains:** they use only reserved domains (`example.com` per RFC 2606, `.test` per RFC 6761).
- **IPs:** they use only documentation addresses (RFC 5737).
- **Attachments:** the attachments are harmless text.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The 34 tests cover each check, the lookalike engine (including a generated punycode homoglyph), every sample's verdict, defanging and the CLI. CI runs them on Python 3.10-3.13.

## Limitations

- **Domain parsing is approximate.** It uses a short list of multi-label suffixes (`co.uk`, `co.in`, ...) instead of the full Public Suffix List.
- **Keyword checks are heuristic.** They are tuned for English and kept LOW/MEDIUM so they never decide a verdict alone.
- **It is not a sandbox.** It does not detonate attachments or follow redirects. Use it for first-pass triage, then a sandbox for anything that needs one.
- **Only `.eml` files are read.** Outlook `.msg` files need converting first.

## Roadmap

- Opt-in enrichment (VirusTotal, URLhaus) behind an explicit flag.
- Public Suffix List support.
- `.msg` input.
- Optional output as a Microsoft Sentinel / Defender incident comment.

## How it was built

I designed and reviewed this project, and wrote it with help from **Claude Code** (Anthropic's AI coding assistant). The checks come from the phishing patterns I see in day-to-day triage.

## License

MIT
