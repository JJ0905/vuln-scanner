import os
import tempfile
import unittest
from datetime import datetime, timezone

from scanner import cli
from scanner.cve import LookupResult, Vulnerability
from scanner.html_report import NVD_NOTICE, html_report, write_html
from scanner.portscan import PortResult
from scanner.report import build_report

EVIL = '<script>alert("xss")</script>'
STARTED = datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)


def make_report(results, vulns=None, target="127.0.0.1"):
    return build_report(target, "127.0.0.1", 10, results, STARTED, 1.234, vulns)


def vuln(cve_id="CVE-2024-0001", score=7.5, severity="HIGH", summary="A bug."):
    return Vulnerability(cve_id, score, severity, summary, "2024-01-01")


SSH = PortResult(22, "open", "SSH-2.0-OpenSSH_9.6p1 Ubuntu")


class TestHtmlReport(unittest.TestCase):
    def test_basic_report(self):
        page = html_report(make_report([SSH, PortResult(23, "closed", "")]))
        self.assertIn("<table>", page)
        self.assertIn("OpenSSH 9.6p1", page)
        self.assertIn("127.0.0.1", page)
        self.assertNotIn("Known vulnerabilities", page)
        self.assertNotIn(NVD_NOTICE, page)

    def test_no_open_ports(self):
        page = html_report(make_report([PortResult(22, "closed", "")]))
        self.assertIn("No open ports found.", page)

    def test_hostile_banner_is_escaped(self):
        page = html_report(make_report([PortResult(22, "open", "SSH-2.0-" + EVIL)]))
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_hostile_target_is_escaped(self):
        page = html_report(make_report([SSH], target=EVIL))
        self.assertNotIn("<script>", page)

    def test_control_characters_removed(self):
        page = html_report(make_report([PortResult(22, "open", "SSH-2.0-x\x1b[2Jy")]))
        self.assertNotIn("\x1b", page)

    def test_csp_present_and_no_scripts(self):
        page = html_report(make_report([SSH]))
        self.assertIn("Content-Security-Policy", page)
        self.assertIn("default-src 'none'", page)
        self.assertNotIn("<script", page.lower())
        self.assertNotIn("http://", page)
        self.assertNotIn("https://", page)  # no CVE lookup, so no links at all


class TestCveSection(unittest.TestCase):
    def report_with(self, lookup):
        return make_report([SSH], {22: lookup})

    def test_cves_listed_with_nvd_link_and_notice(self):
        lookup = LookupResult("ok", cpe="x", cves=[vuln()], total=1)
        page = html_report(self.report_with(lookup))
        self.assertIn("Known vulnerabilities", page)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2024-0001", page)
        self.assertIn("7.5", page)
        self.assertIn(NVD_NOTICE, page)
        self.assertIn("leads, not confirmed findings", page)

    def test_hostile_nvd_text_is_escaped(self):
        lookup = LookupResult("ok", cpe="x", total=1,
                              cves=[vuln(summary=EVIL, severity=EVIL)])
        page = html_report(self.report_with(lookup))
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_malformed_cve_id_is_not_linked(self):
        bad = 'CVE-2024-1"><script>x</script>'
        lookup = LookupResult("ok", cpe="x", total=1, cves=[vuln(cve_id=bad)])
        page = html_report(self.report_with(lookup))
        self.assertNotIn("<script>", page)
        self.assertNotIn("nvd.nist.gov/vuln/detail/CVE-2024-1", page)

    def test_unknown_severity_cannot_inject_class(self):
        lookup = LookupResult("ok", cpe="x", total=1,
                              cves=[vuln(severity='x" onmouseover="evil()')])
        page = html_report(self.report_with(lookup))
        self.assertIn("sev-other", page)
        self.assertNotIn('onmouseover="evil()"', page)

    def test_missing_score_shows_na(self):
        lookup = LookupResult("ok", cpe="x", total=1, cves=[vuln(score=None, severity="UNKNOWN")])
        self.assertIn("n/a", html_report(self.report_with(lookup)))

    def test_no_cves_found(self):
        page = html_report(self.report_with(LookupResult("ok", cpe="x")))
        self.assertIn("No known CVEs", page)

    def test_not_checked_and_error_statuses(self):
        page = html_report(self.report_with(LookupResult("no_mapping")))
        self.assertIn("no NVD mapping", page)
        page = html_report(self.report_with(LookupResult("error", error="timed out")))
        self.assertIn("Lookup failed: timed out", page)

    def test_long_list_is_capped(self):
        many = [vuln(cve_id=f"CVE-2024-{i:04d}") for i in range(1, 121)]
        lookup = LookupResult("ok", cpe="x", cves=many, total=120)
        page = html_report(self.report_with(lookup))
        self.assertIn("Showing the top 50 of 120", page)
        self.assertEqual(page.count("nvd.nist.gov/vuln/detail/"), 50)


class TestWriteAndCli(unittest.TestCase):
    def test_write_html_creates_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.html")
            write_html(make_report([SSH]), path)
            with open(path, encoding="utf-8") as f:
                self.assertTrue(f.read().startswith("<!DOCTYPE html>"))

    def test_cli_html_option_parses(self):
        args = cli.build_parser().parse_args(["127.0.0.1", "--html", "out.html"])
        self.assertEqual(args.html, "out.html")

    def test_cli_unwritable_html_path_fails_cleanly(self):
        code = cli.main(["127.0.0.1", "--ports", "1", "--html",
                         "/nonexistent-dir/definitely/r.html"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
