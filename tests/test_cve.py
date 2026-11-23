import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from scanner.cli import main
from scanner.cve import (CveCache, LookupResult, NvdClient, Vulnerability,
                         build_cpe, parse_response)
from scanner.portscan import PortResult
from scanner.report import build_report
from tests.test_portscan import FakeService


def nvd_payload(cves, total=None):
    """cves: list of (id, score, severity). Mimics the NVD 2.0 response shape."""
    items = []
    for cve_id, score, severity in cves:
        metrics = {}
        if score is not None:
            metrics["cvssMetricV31"] = [{"cvssData": {"baseScore": score,
                                                      "baseSeverity": severity}}]
        items.append({"cve": {
            "id": cve_id,
            "published": "2024-01-01T00:00:00.000",
            "descriptions": [{"lang": "es", "value": "hola"},
                             {"lang": "en", "value": f"Description of {cve_id}"}],
            "metrics": metrics,
        }})
    return {"resultsPerPage": len(items), "startIndex": 0,
            "totalResults": len(items) if total is None else total,
            "vulnerabilities": items}


class FakeFetch:
    """Stands in for the network. Returns queued (status, body) answers in order."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers)))
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer


class FakeTime:
    """A clock that only moves when the code 'sleeps', so tests run instantly."""

    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def ok(payload):
    return (200, json.dumps(payload))


def make_client(*answers, **kwargs):
    fetch = FakeFetch(*answers)
    fake_time = FakeTime()
    client = NvdClient(fetch=fetch, sleep=fake_time.sleep, clock=fake_time.clock, **kwargs)
    return client, fetch, fake_time


class TestBuildCpe(unittest.TestCase):
    def test_openssh_splits_the_p_release(self):
        self.assertEqual(build_cpe("OpenSSH", "9.6p1"),
                         ("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*", None))

    def test_plain_versions(self):
        self.assertEqual(build_cpe("nginx", "1.24.0")[0],
                         "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*")
        self.assertEqual(build_cpe("Apache", "2.4.58")[0],
                         "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*")

    def test_reasons_when_no_cpe_can_be_built(self):
        self.assertEqual(build_cpe("", "1.0"), (None, "no_product"))
        self.assertEqual(build_cpe("SimpleHTTP", "0.6"), (None, "no_mapping"))
        self.assertEqual(build_cpe("nginx", ""), (None, "no_version"))

    def test_hostile_versions_are_rejected(self):
        for bad in ("1.0;rm -rf", "1.0:*:*", "../etc/passwd", "1.0&isVulnerable=false",
                    "1.0 2.0", "%00", "1.2.3.4.5.6.7", "latest"):
            self.assertEqual(build_cpe("nginx", bad), (None, "no_version"), bad)


class TestParseResponse(unittest.TestCase):
    def test_basic_fields(self):
        vulns, total = parse_response(nvd_payload([("CVE-2024-0001", 9.8, "CRITICAL")]))
        self.assertEqual(total, 1)
        v = vulns[0]
        self.assertEqual((v.cve_id, v.score, v.severity), ("CVE-2024-0001", 9.8, "CRITICAL"))
        self.assertEqual(v.summary, "Description of CVE-2024-0001")

    def test_newer_cvss_version_is_preferred(self):
        payload = nvd_payload([("CVE-2024-0001", None, "")])
        payload["vulnerabilities"][0]["cve"]["metrics"] = {
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
            "cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}],
        }
        v = parse_response(payload)[0][0]
        self.assertEqual((v.score, v.severity), (8.1, "HIGH"))

    def test_cvss_v2_severity_lives_outside_cvss_data(self):
        payload = nvd_payload([("CVE-2010-0001", None, "")])
        payload["vulnerabilities"][0]["cve"]["metrics"] = {
            "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}]}
        v = parse_response(payload)[0][0]
        self.assertEqual((v.score, v.severity), (7.5, "HIGH"))

    def test_missing_metrics(self):
        v = parse_response(nvd_payload([("CVE-2024-0002", None, "")]))[0][0]
        self.assertEqual((v.score, v.severity), (None, "UNKNOWN"))

    def test_bad_cve_ids_are_skipped(self):
        payload = nvd_payload([("CVE-2024-0001", 5.0, "MEDIUM"), ("not-a-cve", 9.0, "HIGH"),
                               ("CVE-2024-1; DROP", 9.0, "HIGH")])
        self.assertEqual([v.cve_id for v in parse_response(payload)[0]], ["CVE-2024-0001"])

    def test_unexpected_values_are_handled(self):
        payload = nvd_payload([("CVE-2024-0003", 5.0, "WEIRD")])
        payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = True
        v = parse_response(payload)[0][0]
        self.assertIsNone(v.score)
        self.assertEqual(v.severity, "UNKNOWN")

    def test_control_characters_and_length_are_cleaned(self):
        payload = nvd_payload([("CVE-2024-0004", 5.0, "MEDIUM")])
        payload["vulnerabilities"][0]["cve"]["descriptions"] = [
            {"lang": "en", "value": "bad\x1b[2Jtext " + "A" * 1000}]
        summary = parse_response(payload)[0][0].summary
        self.assertNotIn("\x1b", summary)
        self.assertLessEqual(len(summary), 300)

    def test_garbage_payloads_never_raise(self):
        for payload in (None, [], "text", 5, {}, {"vulnerabilities": "x"},
                        {"vulnerabilities": [None, 5, {"cve": None}, {"cve": {}}]}):
            vulns, total = parse_response(payload)
            self.assertEqual(vulns, [])


class TestCache(unittest.TestCase):
    def _result(self):
        return LookupResult("ok", cpe="cpe:x", total=1,
                            cves=[Vulnerability("CVE-2024-0001", 9.8, "CRITICAL", "s", "2024")])

    def test_round_trip_and_marked_cached(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cache.json")
            CveCache(path).put(self._result())
            hit = CveCache(path).get("cpe:x")   # a fresh object reads it from disk
        self.assertTrue(hit.cached)
        self.assertEqual(hit.cves[0].cve_id, "CVE-2024-0001")

    def test_entries_expire(self):
        now = [1000.0]
        with tempfile.TemporaryDirectory() as tmp:
            cache = CveCache(os.path.join(tmp, "c.json"), ttl_seconds=100, clock=lambda: now[0])
            cache.put(self._result())
            now[0] += 99
            self.assertIsNotNone(cache.get("cpe:x"))
            now[0] += 2
            self.assertIsNone(cache.get("cpe:x"))

    def test_corrupt_cache_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w") as f:
                f.write("{ this is not json")
            self.assertIsNone(CveCache(path).get("cpe:x"))

    def test_malformed_entry_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w") as f:
                json.dump({"cpe:x": {"fetched_at": 1, "cves": [{"bogus": 1}]}}, f)
            self.assertIsNone(CveCache(path).get("cpe:x"))

    def test_unwritable_location_does_not_raise(self):
        with tempfile.NamedTemporaryFile() as blocker:
            cache = CveCache(os.path.join(blocker.name, "sub", "c.json"))
            cache.put(self._result())   # parent is a file, so saving fails quietly


class TestClient(unittest.TestCase):
    def test_successful_lookup(self):
        client, fetch, _ = make_client(ok(nvd_payload([("CVE-2024-0001", 9.8, "CRITICAL")])))
        result = client.lookup("OpenSSH", "9.6p1")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.total, 1)
        self.assertFalse(result.truncated)
        url = fetch.calls[0][0]
        self.assertIn("cpeName=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh%3A9.6%3Ap1", url)
        self.assertTrue(url.endswith("&isVulnerable"))

    def test_zero_results_is_a_real_answer(self):
        client, _, _ = make_client(ok(nvd_payload([])))
        result = client.lookup("nginx", "1.24.0")
        self.assertEqual((result.status, result.total), ("ok", 0))

    def test_cannot_ask_means_no_request(self):
        client, fetch, _ = make_client(ok(nvd_payload([])))
        for product, version, status in (("SimpleHTTP", "0.6", "no_mapping"),
                                         ("", "", "no_product"),
                                         ("nginx", "", "no_version")):
            self.assertEqual(client.lookup(product, version).status, status)
        self.assertEqual(fetch.calls, [])

    def test_second_lookup_uses_the_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = CveCache(os.path.join(tmp, "c.json"))
            client, fetch, _ = make_client(ok(nvd_payload([("CVE-2024-0001", 5.0, "MEDIUM")])),
                                           cache=cache)
            first = client.lookup("nginx", "1.24.0")
            second = client.lookup("nginx", "1.24.0")
        self.assertEqual(len(fetch.calls), 1)
        self.assertFalse(first.cached)
        self.assertTrue(second.cached)

    def test_failures_are_not_cached(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = CveCache(os.path.join(tmp, "c.json"))
            client, fetch, _ = make_client((500, ""), cache=cache)
            client.lookup("nginx", "1.24.0")
            client.lookup("nginx", "1.24.0")
        self.assertEqual(len(fetch.calls), 2)

    def test_requests_are_throttled_without_a_key(self):
        client, _, fake_time = make_client(ok(nvd_payload([])))
        client.lookup("nginx", "1.24.0")
        client.lookup("nginx", "1.25.0")
        self.assertEqual(len(fake_time.sleeps), 1)
        self.assertAlmostEqual(fake_time.sleeps[0], 6.5)

    def test_api_key_is_sent_as_a_header_only_and_speeds_things_up(self):
        client, fetch, fake_time = make_client(ok(nvd_payload([])), api_key="SECRET-KEY-123")
        client.lookup("nginx", "1.24.0")
        client.lookup("nginx", "1.25.0")
        url, headers = fetch.calls[0]
        self.assertEqual(headers["apiKey"], "SECRET-KEY-123")
        self.assertNotIn("SECRET-KEY-123", url)
        self.assertAlmostEqual(fake_time.sleeps[0], 0.7)

    def test_no_key_means_no_key_header(self):
        client, fetch, _ = make_client(ok(nvd_payload([])))
        client.lookup("nginx", "1.24.0")
        self.assertNotIn("apiKey", fetch.calls[0][1])

    def test_rate_limit_is_retried_then_succeeds(self):
        client, fetch, fake_time = make_client(
            (403, ""), ok(nvd_payload([("CVE-2024-0001", 5.0, "MEDIUM")])))
        result = client.lookup("nginx", "1.24.0")
        self.assertEqual(result.status, "ok")
        self.assertEqual(len(fetch.calls), 2)
        self.assertIn(30.0, fake_time.sleeps)

    def test_rate_limit_exhausted_is_an_error_not_zero_results(self):
        client, fetch, _ = make_client((403, ""))
        result = client.lookup("nginx", "1.24.0")
        self.assertEqual(result.status, "error")
        self.assertIn("403", result.error)
        self.assertEqual(len(fetch.calls), 3)   # first try plus two retries

    def test_unknown_cpe(self):
        client, _, _ = make_client((404, ""))
        self.assertEqual(client.lookup("nginx", "1.24.0").status, "unknown_cpe")

    def test_server_error(self):
        client, _, _ = make_client((500, ""))
        result = client.lookup("nginx", "1.24.0")
        self.assertEqual(result.status, "error")
        self.assertIn("500", result.error)

    def test_network_failure_is_an_error_not_zero_results(self):
        client, _, _ = make_client(OSError("no route"))
        result = client.lookup("nginx", "1.24.0")
        self.assertEqual(result.status, "error")
        self.assertIn("OSError", result.error)

    def test_unreadable_response_is_an_error(self):
        client, _, _ = make_client((200, "<html>not json</html>"))
        self.assertEqual(client.lookup("nginx", "1.24.0").status, "error")

    def test_errors_never_contain_the_api_key(self):
        client, _, _ = make_client((500, ""), api_key="SECRET-KEY-123")
        self.assertNotIn("SECRET-KEY-123", client.lookup("nginx", "1.24.0").error)

    def test_pagination_collects_every_page(self):
        page1 = nvd_payload([("CVE-2024-0001", 5.0, "MEDIUM"), ("CVE-2024-0002", 6.0, "MEDIUM")], total=3)
        page2 = nvd_payload([("CVE-2024-0003", 7.0, "HIGH")], total=3)
        client, fetch, _ = make_client(ok(page1), ok(page2), page_size=2)
        result = client.lookup("nginx", "1.24.0")
        self.assertEqual(len(result.cves), 3)
        self.assertFalse(result.truncated)
        self.assertIn("startIndex=2", fetch.calls[1][0])

    def test_truncation_is_reported_when_the_page_cap_is_hit(self):
        page = nvd_payload([("CVE-2024-0001", 5.0, "MEDIUM"), ("CVE-2024-0002", 6.0, "MEDIUM")], total=50)
        client, fetch, _ = make_client(ok(page), page_size=2, max_pages=2)
        result = client.lookup("nginx", "1.24.0")
        self.assertTrue(result.truncated)
        self.assertEqual(result.total, 50)
        self.assertEqual(len(fetch.calls), 2)

    def test_empty_page_stops_pagination(self):
        client, fetch, _ = make_client(ok(nvd_payload([], total=10)), page_size=2)
        client.lookup("nginx", "1.24.0")
        self.assertEqual(len(fetch.calls), 1)


STARTED = datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)


class TestReportIntegration(unittest.TestCase):
    def test_cves_are_sorted_by_score_with_unscored_last(self):
        lookup = LookupResult("ok", cpe="c", total=3, cves=[
            Vulnerability("CVE-2024-0001", None, "UNKNOWN", "a", ""),
            Vulnerability("CVE-2024-0002", 5.0, "MEDIUM", "b", ""),
            Vulnerability("CVE-2024-0003", 9.8, "CRITICAL", "c", "")])
        results = [PortResult(22, "open", "SSH-2.0-OpenSSH_9.6p1")]
        report = build_report("h", "10.0.0.5", 1, results, STARTED, 1, {22: lookup})
        ids = [c["cve_id"] for c in report["open_ports"][0]["vulnerabilities"]["cves"]]
        self.assertEqual(ids, ["CVE-2024-0003", "CVE-2024-0002", "CVE-2024-0001"])
        self.assertTrue(report["cve_lookup"])

    def test_without_lookup_there_is_no_vulnerability_data(self):
        results = [PortResult(22, "open", "SSH-2.0-OpenSSH_9.6p1")]
        report = build_report("h", "10.0.0.5", 1, results, STARTED, 1)
        self.assertNotIn("vulnerabilities", report["open_ports"][0])
        self.assertFalse(report["cve_lookup"])

    def test_report_with_vulnerabilities_is_json_serialisable(self):
        lookup = LookupResult("ok", cpe="c", total=1,
                              cves=[Vulnerability("CVE-2024-0001", 9.8, "CRITICAL", "s", "p")])
        results = [PortResult(22, "open", "SSH-2.0-OpenSSH_9.6p1")]
        json.dumps(build_report("h", "10.0.0.5", 1, results, STARTED, 1, {22: lookup}))


class FakeNvdClient:
    """Replaces the real client in CLI tests so nothing touches the network."""
    instances = []

    def __init__(self, api_key=None, cache=None):
        self.api_key = api_key
        self.lookups = []
        FakeNvdClient.instances.append(self)

    def lookup(self, product, version):
        self.lookups.append((product, version))
        return LookupResult("ok", cpe="cpe:fake", total=2, cves=[
            Vulnerability("CVE-2024-0001", 9.8, "CRITICAL", "Remote code execution", "2024"),
            Vulnerability("CVE-2024-0002", 5.0, "MEDIUM", "Information leak", "2024")])


class TestCliCve(unittest.TestCase):
    def setUp(self):
        FakeNvdClient.instances = []

    def _run(self, banner, extra, env=None):
        service = FakeService(banner=banner)
        self.addCleanup(service.close)
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch("scanner.cli.NvdClient", FakeNvdClient), \
                mock.patch.dict(os.environ, env or {}, clear=False), \
                contextlib.redirect_stdout(out):
            code = main(["127.0.0.1", "--ports", str(service.port), "--timeout", "1",
                         "--cve", "--cache-file", os.path.join(tmp, "c.json")] + extra)
        return code, out.getvalue(), service

    def test_cve_section_is_printed(self):
        code, text, _ = self._run(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n", [])
        self.assertEqual(code, 0)
        self.assertIn("Known vulnerabilities", text)
        self.assertIn("2 CVE(s), highest 9.8 CRITICAL", text)
        self.assertIn("CVE-2024-0001", text)
        self.assertEqual(FakeNvdClient.instances[0].lookups, [("OpenSSH", "9.6p1")])

    def test_product_that_cannot_be_checked_is_reported_honestly(self):
        with mock.patch("scanner.cli.NvdClient") as client_class:
            client_class.return_value.lookup.return_value = LookupResult("no_mapping")
            service = FakeService(banner=b"SSH-2.0-weird\r\n")
            self.addCleanup(service.close)
            out = io.StringIO()
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(out):
                main(["127.0.0.1", "--ports", str(service.port), "--timeout", "1",
                      "--cve", "--cache-file", os.path.join(tmp, "c.json")])
        self.assertIn("not checked (no NVD mapping", out.getvalue())
        self.assertNotIn("no known CVEs", out.getvalue())

    def test_lookup_failure_is_shown_as_a_failure(self):
        with mock.patch("scanner.cli.NvdClient") as client_class:
            client_class.return_value.lookup.return_value = LookupResult(
                "error", error="NVD returned HTTP 503")
            service = FakeService(banner=b"SSH-2.0-OpenSSH_9.6p1\r\n")
            self.addCleanup(service.close)
            out = io.StringIO()
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(out):
                main(["127.0.0.1", "--ports", str(service.port), "--timeout", "1",
                      "--cve", "--cache-file", os.path.join(tmp, "c.json")])
        self.assertIn("lookup failed (NVD returned HTTP 503)", out.getvalue())
        self.assertNotIn("no known CVEs", out.getvalue())

    def test_api_key_comes_from_the_environment(self):
        self._run(b"SSH-2.0-OpenSSH_9.6p1\r\n", [], env={"NVD_API_KEY": "ENV-KEY"})
        self.assertEqual(FakeNvdClient.instances[0].api_key, "ENV-KEY")

    def test_json_includes_vulnerabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "scan.json")
            self._run(b"SSH-2.0-OpenSSH_9.6p1\r\n", ["--json", path])
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        block = data["open_ports"][0]["vulnerabilities"]
        self.assertEqual(block["status"], "ok")
        self.assertEqual(block["cves"][0]["cve_id"], "CVE-2024-0001")
        self.assertTrue(data["cve_lookup"])

    def test_no_cve_flag_means_no_lookup(self):
        service = FakeService(banner=b"SSH-2.0-OpenSSH_9.6p1\r\n")
        self.addCleanup(service.close)
        out = io.StringIO()
        with mock.patch("scanner.cli.NvdClient") as client_class, contextlib.redirect_stdout(out):
            main(["127.0.0.1", "--ports", str(service.port), "--timeout", "1"])
        client_class.assert_not_called()
        self.assertNotIn("Known vulnerabilities", out.getvalue())


if __name__ == "__main__":
    unittest.main()
