import csv
import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phish_analyzer import analyze, parse_file  # noqa: E402
from phish_analyzer.analyzer import VERDICT_CLEAN, VERDICT_PHISHING  # noqa: E402
from phish_analyzer.cli import main  # noqa: E402
from phish_analyzer.report import to_ioc_csv, to_markdown  # noqa: E402

SAMPLES = ROOT / "samples"
PROTECTED = ["example.com"]


def run(name):
    return analyze(parse_file(SAMPLES / name), PROTECTED, source=name)


class SampleVerdictTests(unittest.TestCase):
    def test_legitimate_newsletter(self):
        report = run("01_legit_newsletter.eml")
        self.assertEqual(report.verdict, VERDICT_CLEAN)
        self.assertEqual(report.score, 0)

    def test_credential_phish(self):
        report = run("02_credential_phish.eml")
        self.assertEqual(report.verdict, VERDICT_PHISHING)
        checks = {f.check for f in report.findings}
        for expected in ("auth.dmarc_fail", "sender.lookalike_domain", "links.text_mismatch",
                         "links.html_form", "sender.reply_to_mismatch"):
            self.assertIn(expected, checks)
        ips = {i.value for i in report.indicators if i.kind == "ip"}
        self.assertIn("203.0.113.45", ips)

    def test_malicious_attachments(self):
        report = run("03_malicious_attachments.eml")
        self.assertEqual(report.verdict, VERDICT_PHISHING)
        self.assertEqual(len(report.email.attachments), 3)
        hashes = [i for i in report.indicators if i.kind == "sha256"]
        self.assertEqual(len(hashes), 3)
        self.assertIn("T1036.007", {f.attack for f in report.findings})

    def test_bec_passes_authentication_but_is_flagged(self):
        report = run("04_bec_wire_transfer.eml")
        checks = {f.check for f in report.findings}
        self.assertIn("auth.pass", checks)  # authentication alone is not safety
        self.assertIn("sender.lookalike_domain", checks)
        self.assertIn("content.financial", checks)
        self.assertEqual(report.verdict, VERDICT_PHISHING)


class OutputTests(unittest.TestCase):
    def test_markdown_is_defanged(self):
        markdown = to_markdown(run("02_credential_phish.eml"))
        self.assertIn("hxxp://examp1e-login[.]test", markdown)
        self.assertNotIn("http://examp1e-login.test", markdown)

    def test_ioc_csv_keeps_raw_values(self):
        rows = list(csv.DictReader(io.StringIO(to_ioc_csv([run("02_credential_phish.eml")]))))
        values = {row["value"] for row in rows}
        self.assertIn("http://examp1e-login.test/verify?user=alex", values)

    def test_cli_json_and_iocs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, iocs = pathlib.Path(tmp, "r.json"), pathlib.Path(tmp, "iocs.csv")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = main([str(SAMPLES / "02_credential_phish.eml"), "-p", "example.com",
                             "-f", "json", "-o", str(out), "--iocs", str(iocs)])
            self.assertEqual(code, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["verdict"], VERDICT_PHISHING)
            self.assertTrue(iocs.read_text().startswith("source,type,value"))

    def test_cli_rejects_missing_file(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["does-not-exist.eml"]), 2)


if __name__ == "__main__":
    unittest.main()
