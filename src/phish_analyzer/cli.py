"""Command-line entry point: phish-analyzer EMAIL.eml [...]"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .parser import parse_file
from .report import to_ioc_csv, to_json, to_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phish-analyzer",
        description="Offline phishing triage for .eml files: authentication, lookalike domains, "
                    "links, attachments and language, with MITRE ATT&CK-mapped findings.",
    )
    parser.add_argument("emails", nargs="+", type=Path, help=".eml file(s) to analyse")
    parser.add_argument("-p", "--protected-domain", action="append", default=[], metavar="DOMAIN",
                        help="your organisation's domain (repeatable); enables lookalike detection")
    parser.add_argument("-f", "--format", choices=["md", "json"], default="md", help="report format (default: md)")
    parser.add_argument("-o", "--output", type=Path, help="write the report(s) here instead of stdout")
    parser.add_argument("--iocs", type=Path, metavar="CSV", help="also write raw IOCs to this CSV for block lists")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    reports = []
    for path in args.emails:
        if not path.is_file():
            print(f"error: {path} is not a file", file=sys.stderr)
            return 2
        reports.append(analyze(parse_file(path), args.protected_domain, source=path.name))

    if args.format == "json":
        rendered = to_json(reports[0]) if len(reports) == 1 else "[\n" + ",\n".join(to_json(r) for r in reports) + "\n]"
    else:
        rendered = "\n---\n\n".join(to_markdown(r) for r in reports)

    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    if args.iocs:
        args.iocs.write_text(to_ioc_csv(reports), encoding="utf-8")

    for report in reports:
        print(f"{report.source}: {report.verdict} ({report.score}/100)", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
