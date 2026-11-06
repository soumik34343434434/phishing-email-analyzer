import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from phish_analyzer import checks  # noqa: E402
from phish_analyzer.models import Attachment, ParsedEmail, Severity  # noqa: E402
from phish_analyzer.urls import defang, extract_links  # noqa: E402


def ids(findings):
    return {f.check for f in findings}


class AuthenticationTests(unittest.TestCase):
    def test_parses_top_most_result_first(self):
        headers = ["mx.example.com; spf=fail smtp.mailfrom=x.test; dkim=none; dmarc=fail",
                   "older.example.com; spf=pass; dmarc=pass"]
        self.assertEqual(checks.parse_auth_results(headers), {"spf": "fail", "dkim": "none", "dmarc": "fail"})

    def test_dmarc_fail_is_high(self):
        email = ParsedEmail(from_addr="a@x.test", auth_results=["mx; spf=fail; dkim=fail; dmarc=fail"])
        found = {f.check: f for f in checks.check_authentication(email)}
        self.assertEqual(found["auth.dmarc_fail"].severity, Severity.HIGH)
        self.assertIn("auth.spf_fail", found)
        self.assertIn("auth.dkim_fail", found)

    def test_missing_header(self):
        self.assertEqual(ids(checks.check_authentication(ParsedEmail())), {"auth.missing"})

    def test_all_pass_is_info_only(self):
        email = ParsedEmail(auth_results=["mx; spf=pass; dkim=pass; dmarc=pass"])
        self.assertEqual(ids(checks.check_authentication(email)), {"auth.pass"})


class SenderTests(unittest.TestCase):
    def test_display_name_hides_other_address(self):
        email = ParsedEmail(from_display="ceo@example.com", from_addr="x@evil.test", message_id="<1@evil.test>")
        self.assertIn("sender.display_name_address", ids(checks.check_sender(email, ["example.com"])))

    def test_reply_to_and_lookalike(self):
        email = ParsedEmail(from_display="Example Payroll", from_addr="payroll@examp1e.com",
                            reply_to=["collect@freemail.test"], message_id="<1@examp1e.com>")
        found = ids(checks.check_sender(email, ["example.com"]))
        self.assertTrue({"sender.lookalike_domain", "sender.reply_to_mismatch", "sender.display_name_brand"} <= found)

    def test_internal_sender_is_clean(self):
        email = ParsedEmail(from_display="Example IT", from_addr="it@example.com",
                            reply_to=["helpdesk@example.com"], message_id="<1@example.com>")
        self.assertEqual(checks.check_sender(email, ["example.com"]), [])

    def test_originating_ip_skips_internal_hops(self):
        email = ParsedEmail(received=[
            "from mx (mx [10.0.0.5]) by mailbox",
            "from relay (relay [198.51.100.9]) by mx",
            "from laptop (laptop [192.168.1.20]) by relay",
        ])
        self.assertEqual(checks.originating_ip(email), "198.51.100.9")


class LinkTests(unittest.TestCase):
    def check_html(self, html, protected=("example.com",)):
        return ids(checks.check_links(extract_links("", html), list(protected)))

    def test_text_and_destination_mismatch(self):
        found = self.check_html('<a href="http://evil.test/x">https://login.example.com</a>')
        self.assertIn("links.text_mismatch", found)

    def test_matching_text_is_fine(self):
        found = self.check_html('<a href="https://login.example.com/a">login.example.com</a>')
        self.assertEqual(found, set())

    def test_obfuscation_tricks(self):
        found = self.check_html(
            '<a href="http://203.0.113.9/a">x</a>'
            '<a href="https://login.example.com@evil.test/">y</a>'
            '<a href="https://bit.ly/abc">z</a>'
            '<a href="https://prize.top/win">w</a>'
        )
        self.assertTrue({"links.ip_host", "links.userinfo", "links.shortener", "links.suspicious_tld"} <= found)

    def test_form_with_password(self):
        found = checks.check_links(extract_links("", '<form action="https://x.test/p"><input type="password"></form>'), [])
        form = [f for f in found if f.check == "links.html_form"][0]
        self.assertIn("password", form.detail)

    def test_plain_text_urls_are_extracted(self):
        extracted = extract_links("Go to https://examp1e.com/login. Thanks", "")
        self.assertEqual([link.url for link in extracted.links], ["https://examp1e.com/login"])

    def test_defang(self):
        self.assertEqual(defang("https://evil.test/a.b"), "hxxps://evil[.]test/a.b")
        self.assertEqual(defang("http://203.0.113.5/x"), "hxxp://203[.]0[.]113[.]5/x")


class AttachmentTests(unittest.TestCase):
    def att(self, name):
        return Attachment(filename=name, content_type="application/octet-stream", size=1, sha256="0" * 64)

    def test_double_extension_and_executable(self):
        found = ids(checks.check_attachments([self.att("Invoice.pdf.exe")]))
        self.assertEqual(found, {"attachments.double_extension", "attachments.executable"})

    def test_html_container_macro_archive(self):
        self.assertEqual(ids(checks.check_attachments([self.att("form.HTM")])), {"attachments.html"})
        self.assertEqual(ids(checks.check_attachments([self.att("photos.iso")])), {"attachments.container"})
        self.assertEqual(ids(checks.check_attachments([self.att("budget.xlsm")])), {"attachments.macro"})
        self.assertEqual(ids(checks.check_attachments([self.att("files.zip")])), {"attachments.archive"})

    def test_ordinary_documents_are_clean(self):
        self.assertEqual(checks.check_attachments([self.att("report.pdf"), self.att("notes.docx")]), [])


class ContentTests(unittest.TestCase):
    def test_phrases_match_across_line_breaks(self):
        email = ParsedEmail(text_body="Please send the new bank\ndetails and a gift card today.")
        found = ids(checks.check_content(email, ""))
        self.assertIn("content.financial", found)


if __name__ == "__main__":
    unittest.main()
