"""Automated tests for PhishGuard, using Python's built-in unittest module.

Run all tests from the project folder with:
    python -m unittest -v
"""

import unittest

import phishguard


class TestValidateUrl(unittest.TestCase):
    """Tests for the input validation step."""

    def test_valid_https_url(self):
        is_valid, parsed, message = phishguard.validate_url("https://www.example.com/login?user=1")
        self.assertTrue(is_valid)
        self.assertEqual(parsed.hostname, "www.example.com")
        self.assertEqual(parsed.path, "/login")
        self.assertEqual(parsed.query, "user=1")

    def test_valid_http_url(self):
        is_valid, parsed, message = phishguard.validate_url("http://example.com")
        self.assertTrue(is_valid)

    def test_spaces_around_url_are_removed(self):
        is_valid, parsed, message = phishguard.validate_url("   https://example.com   ")
        self.assertTrue(is_valid)

    def test_uppercase_scheme_is_accepted(self):
        is_valid, parsed, message = phishguard.validate_url("HTTPS://WWW.EXAMPLE.COM")
        self.assertTrue(is_valid)
        self.assertEqual(parsed.hostname, "www.example.com")

    def test_empty_string_is_invalid(self):
        is_valid, parsed, message = phishguard.validate_url("")
        self.assertFalse(is_valid)
        self.assertIsNone(parsed)

    def test_only_spaces_is_invalid(self):
        is_valid, parsed, message = phishguard.validate_url("     ")
        self.assertFalse(is_valid)

    def test_none_is_invalid(self):
        is_valid, parsed, message = phishguard.validate_url(None)
        self.assertFalse(is_valid)

    def test_number_is_invalid(self):
        is_valid, parsed, message = phishguard.validate_url(12345)
        self.assertFalse(is_valid)

    def test_missing_scheme_is_invalid(self):
        is_valid, parsed, message = phishguard.validate_url("example.com")
        self.assertFalse(is_valid)
        self.assertIn("http", message)

    def test_unsupported_scheme_is_invalid(self):
        for url in ("ftp://files.example.com", "javascript:alert(1)"):
            with self.subTest(url=url):
                is_valid, parsed, message = phishguard.validate_url(url)
                self.assertFalse(is_valid)

    def test_space_inside_url_is_invalid(self):
        is_valid, parsed, message = phishguard.validate_url("http://exa mple.com")
        self.assertFalse(is_valid)
        self.assertIn("spaces", message)

    def test_missing_hostname_is_invalid(self):
        is_valid, parsed, message = phishguard.validate_url("https://")
        self.assertFalse(is_valid)

    def test_malformed_brackets_do_not_crash(self):
        is_valid, parsed, message = phishguard.validate_url("http://[::1")
        self.assertFalse(is_valid)

    def test_bad_port_does_not_crash(self):
        is_valid, parsed, message = phishguard.validate_url("http://example.com:99999")
        self.assertFalse(is_valid)

    def test_very_long_input_is_invalid(self):
        is_valid, parsed, message = phishguard.validate_url("https://example.com/" + "a" * 3000)
        self.assertFalse(is_valid)


class TestIndividualRules(unittest.TestCase):
    """Tests for each rule on its own."""

    def parse(self, url):
        """Helper: parse a URL that we know is valid."""
        is_valid, parsed, message = phishguard.validate_url(url)
        self.assertTrue(is_valid, message)
        return parsed

    def test_is_ip_address(self):
        self.assertTrue(phishguard.is_ip_address("192.168.1.1"))
        self.assertTrue(phishguard.is_ip_address("3232235777"))   # disguised IP
        self.assertTrue(phishguard.is_ip_address("::1"))          # IPv6
        self.assertFalse(phishguard.is_ip_address("example.com"))
        self.assertFalse(phishguard.is_ip_address("999.999.999.999"))

    def test_http_is_flagged_but_https_is_not(self):
        self.assertIsNotNone(phishguard.check_https(self.parse("http://example.com")))
        self.assertIsNone(phishguard.check_https(self.parse("https://example.com")))

    def test_ip_address_is_flagged(self):
        self.assertIsNotNone(phishguard.check_ip_address("192.168.1.1"))
        self.assertIsNone(phishguard.check_ip_address("example.com"))

    def test_keywords_are_found(self):
        result = phishguard.check_keywords(self.parse("https://example.com/login/verify"))
        self.assertEqual(result["points"], 20)
        self.assertIn("login", result["message"])
        self.assertIn("verify", result["message"])

    def test_keywords_are_not_case_sensitive(self):
        result = phishguard.check_keywords(self.parse("https://example.com/LOGIN"))
        self.assertIsNotNone(result)

    def test_keyword_points_are_capped(self):
        url = "https://example.com/login/verify/password/account/secure"
        result = phishguard.check_keywords(self.parse(url))
        self.assertEqual(result["points"], phishguard.MAX_KEYWORD_POINTS)

    def test_clean_url_has_no_keywords(self):
        self.assertIsNone(phishguard.check_keywords(self.parse("https://www.example.com/news")))

    def test_long_url_is_flagged(self):
        long_url = "https://example.com/" + "a" * 100
        self.assertIsNotNone(phishguard.check_long_url(long_url))
        self.assertIsNone(phishguard.check_long_url("https://example.com"))

    def test_at_symbol_is_flagged(self):
        self.assertIsNotNone(phishguard.check_at_symbol(self.parse("https://paypal.com@evil.com")))
        self.assertIsNone(phishguard.check_at_symbol(self.parse("https://example.com/a@b")))

    def test_unusual_port_is_flagged(self):
        self.assertIsNotNone(phishguard.check_odd_port(self.parse("http://example.com:8080")))
        self.assertIsNone(phishguard.check_odd_port(self.parse("https://example.com:443")))
        self.assertIsNone(phishguard.check_odd_port(self.parse("https://example.com")))

    def test_embedded_url_is_flagged(self):
        flagged = self.parse("https://example.com/redirect?url=http://evil.com")
        self.assertIsNotNone(phishguard.check_embedded_url(flagged))
        self.assertIsNone(phishguard.check_embedded_url(self.parse("https://example.com/page")))

    def test_many_subdomains_are_flagged(self):
        self.assertIsNotNone(phishguard.check_subdomains("a.b.c.example.com"))
        self.assertIsNone(phishguard.check_subdomains("www.example.com"))
        self.assertIsNone(phishguard.check_subdomains("example.com"))

    def test_many_hyphens_are_flagged(self):
        self.assertIsNotNone(phishguard.check_hyphens("my-secure-bank-login.com"))
        self.assertIsNone(phishguard.check_hyphens("my-site.com"))

    def test_punycode_is_flagged_without_double_counting_hyphens(self):
        self.assertIsNotNone(phishguard.check_punycode("xn--pple-43d.com"))
        self.assertIsNone(phishguard.check_hyphens("xn--pple-43d.com"))
        self.assertIsNone(phishguard.check_punycode("example.com"))

    def test_shortener_is_flagged(self):
        self.assertIsNotNone(phishguard.check_shortener("bit.ly"))
        self.assertIsNotNone(phishguard.check_shortener("www.bit.ly"))
        self.assertIsNone(phishguard.check_shortener("orbit.ly.example.com"))
        self.assertIsNone(phishguard.check_shortener("example.com"))


class TestAnalyzeUrl(unittest.TestCase):
    """Tests for the complete analysis (all rules together)."""

    def test_safe_looking_url_scores_zero(self):
        result = phishguard.analyze_url("https://www.google.com")
        self.assertTrue(result["valid"])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "Low")
        self.assertEqual(result["reasons"], [])

    def test_ip_address_login_over_http_is_high(self):
        result = phishguard.analyze_url("http://192.168.1.1/login")
        self.assertEqual(result["score"], 60)
        self.assertEqual(result["level"], "High")
        self.assertEqual(len(result["reasons"]), 3)

    def test_at_symbol_url_is_medium(self):
        result = phishguard.analyze_url("https://paypal.com@evil-site.com/signin")
        self.assertEqual(result["score"], 30)
        self.assertEqual(result["level"], "Medium")

    def test_stacked_subdomains_and_keywords_are_medium(self):
        result = phishguard.analyze_url("https://secure.login.account.verify.example.com/")
        self.assertEqual(result["score"], 45)
        self.assertEqual(result["level"], "Medium")

    def test_obviously_bad_url_is_high(self):
        url = ("http://secure-paypal-login.verify-account.example.com"
               "/update/password?next=http://evil.com")
        result = phishguard.analyze_url(url)
        self.assertEqual(result["score"], 75)
        self.assertEqual(result["level"], "High")

    def test_score_never_goes_above_100(self):
        url = ("http://user@192.168.1.1:8080/login/verify/password/account"
               "?next=http://evil.com/aaaaaaaaaaaaaaaaaaaaaaaa")
        result = phishguard.analyze_url(url)
        total_points = sum(reason["points"] for reason in result["reasons"])
        self.assertGreater(total_points, 100)   # the raw total is over 100...
        self.assertEqual(result["score"], 100)  # ...but the score is capped

    def test_every_reason_has_points_and_message(self):
        result = phishguard.analyze_url("http://192.168.1.1/login")
        for reason in result["reasons"]:
            self.assertIn("points", reason)
            self.assertIn("message", reason)
            self.assertTrue(reason["message"])

    def test_invalid_input_gives_no_score(self):
        result = phishguard.analyze_url("not a url")
        self.assertFalse(result["valid"])
        self.assertIsNone(result["score"])
        self.assertIsNone(result["level"])

    def test_analyze_never_crashes_on_strange_input(self):
        strange_inputs = [
            "", " ", None, 123, [], "http://", "://", "http://[", "\n",
            "http://a b", "a" * 5000, "http://:80", "http://@", "https://.",
        ]
        for value in strange_inputs:
            with self.subTest(value=repr(value)[:30]):
                result = phishguard.analyze_url(value)
                self.assertIn("valid", result)


class TestClassifyScore(unittest.TestCase):
    """Tests for the Low / Medium / High boundaries."""

    def test_boundaries(self):
        self.assertEqual(phishguard.classify_score(0), "Low")
        self.assertEqual(phishguard.classify_score(29), "Low")
        self.assertEqual(phishguard.classify_score(30), "Medium")
        self.assertEqual(phishguard.classify_score(59), "Medium")
        self.assertEqual(phishguard.classify_score(60), "High")
        self.assertEqual(phishguard.classify_score(100), "High")


class TestFormatReport(unittest.TestCase):
    """Tests for the text shown to the user."""

    def test_report_for_valid_url(self):
        report = phishguard.format_report(phishguard.analyze_url("http://192.168.1.1/login"))
        self.assertIn("Risk score : 60 / 100", report)
        self.assertIn("HIGH", report)
        self.assertIn("IP address", report)

    def test_report_always_includes_limitation_note(self):
        report = phishguard.format_report(phishguard.analyze_url("https://www.google.com"))
        self.assertIn("cannot prove", report)

    def test_report_for_invalid_url(self):
        report = phishguard.format_report(phishguard.analyze_url(""))
        self.assertIn("Invalid input", report)


if __name__ == "__main__":
    unittest.main()