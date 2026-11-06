import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from phish_analyzer import domains  # noqa: E402

PROTECTED = ["example.com"]


class RegistrableDomainTests(unittest.TestCase):
    def test_simple_and_multi_label_suffixes(self):
        self.assertEqual(domains.registrable_domain("mail.example.com"), "example.com")
        self.assertEqual(domains.registrable_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(domains.registrable_domain("shop.example.co.in"), "example.co.in")
        self.assertEqual(domains.registrable_domain("localhost"), "localhost")


class LevenshteinTests(unittest.TestCase):
    def test_distances(self):
        self.assertEqual(domains.levenshtein("example", "example"), 0)
        self.assertEqual(domains.levenshtein("exampel", "example"), 2)
        self.assertEqual(domains.levenshtein("examples", "example"), 1)
        self.assertEqual(domains.levenshtein("", "abc"), 3)


class LookalikeTests(unittest.TestCase):
    def assertLookalike(self, host, strong=True):
        match = domains.lookalike(host, PROTECTED)
        self.assertIsNotNone(match, f"{host} should be flagged")
        self.assertEqual(match[2], strong, match[1])

    def test_legitimate_domains_are_not_flagged(self):
        for host in ("example.com", "mail.example.com", "intranet.example.com", "unrelated.org", "github.com"):
            self.assertIsNone(domains.lookalike(host, PROTECTED), host)

    def test_character_substitution(self):
        self.assertLookalike("examp1e.com")      # 1 -> l
        self.assertLookalike("exarnple.com")     # rn -> m
        self.assertLookalike("examp1e-login.test")  # brand hidden behind a swap

    def test_typo_and_suffix_swap(self):
        self.assertLookalike("exampel.com")      # transposition
        self.assertLookalike("example.net")      # same name, other TLD

    def test_brand_inside_other_domain_is_weak(self):
        self.assertLookalike("example-security.test", strong=False)

    def test_cyrillic_homoglyph_in_punycode(self):
        puny = "exаmple.com".encode("idna").decode("ascii")  # Cyrillic 'a'
        self.assertTrue(domains.is_punycode(puny))
        self.assertLookalike(puny)

    def test_short_brands_do_not_overmatch(self):
        self.assertIsNone(domains.lookalike("abd.com", ["abc.com"]))


if __name__ == "__main__":
    unittest.main()
