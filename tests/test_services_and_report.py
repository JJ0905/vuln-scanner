import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone

from scanner.cli import main
from scanner.portscan import PortResult
from scanner.report import build_report, write_json
from scanner.services import identify
from tests.test_portscan import FakeService


class TestIdentifySsh(unittest.TestCase):
    def test_openssh_with_comment(self):
        s = identify(22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
        self.assertEqual((s.name, s.product, s.version, s.confidence),
                         ("ssh", "OpenSSH", "9.6p1", "banner"))

    def test_dropbear(self):
        s = identify(22, "SSH-2.0-dropbear_2022.83")
        self.assertEqual((s.product, s.version), ("Dropbear", "2022.83"))

    def test_libssh_with_hyphen(self):
        s = identify(2222, "SSH-2.0-libssh-0.9.6")
        self.assertEqual((s.product, s.version), ("libssh", "0.9.6"))

    def test_ssh_without_version(self):
        s = identify(22, "SSH-2.0-weird")
        self.assertEqual((s.name, s.product, s.version), ("ssh", "weird", ""))

    def test_banner_beats_port_number(self):
        self.assertEqual(identify(8080, "SSH-2.0-OpenSSH_9.6").name, "ssh")


class TestIdentifyHttp(unittest.TestCase):
    def test_nginx(self):
        s = identify(80, "HTTP/1.1 200 OK | Server: nginx/1.24.0 | Date: today")
        self.assertEqual((s.name, s.product, s.version), ("http", "nginx", "1.24.0"))

    def test_apache_with_os_comment(self):
        s = identify(80, "HTTP/1.1 200 OK | Server: Apache/2.4.58 (Ubuntu)")
        self.assertEqual((s.product, s.version), ("Apache", "2.4.58"))

    def test_python_simple_http_server(self):
        s = identify(8080, "HTTP/1.0 200 OK | Server: SimpleHTTP/0.6 Python/3.12.3")
        self.assertEqual((s.product, s.version), ("SimpleHTTP", "0.6"))

    def test_iis(self):
        s = identify(80, "HTTP/1.1 200 OK | Server: Microsoft-IIS/10.0")
        self.assertEqual((s.product, s.version), ("Microsoft IIS", "10.0"))

    def test_server_header_without_version(self):
        s = identify(80, "HTTP/1.1 200 OK | Server: nginx")
        self.assertEqual((s.product, s.version), ("nginx", ""))

    def test_header_name_is_case_insensitive(self):
        s = identify(80, "HTTP/1.1 200 OK | server: NGINX/1.24.0")
        self.assertEqual((s.product, s.version), ("nginx", "1.24.0"))

    def test_http_without_server_header(self):
        s = identify(80, "HTTP/1.1 403 Forbidden")
        self.assertEqual((s.name, s.product, s.confidence), ("http", "", "banner"))

    def test_http_on_nonstandard_port(self):
        self.assertEqual(identify(31337, "HTTP/1.0 200 OK | Server: nginx/1.2.3").name, "http")


class TestIdentifyFtpAndSmtp(unittest.TestCase):
    def test_vsftpd(self):
        s = identify(21, "220 (vsFTPd 3.0.5)")
        self.assertEqual((s.name, s.product, s.version), ("ftp", "vsFTPd", "3.0.5"))

    def test_proftpd(self):
        s = identify(21, "220 ProFTPD 1.3.8 Server (Debian) [::ffff:10.0.0.5]")
        self.assertEqual((s.product, s.version), ("ProFTPD", "1.3.8"))

    def test_generic_ftp(self):
        s = identify(2121, "220 Welcome to the archive")
        self.assertEqual((s.name, s.product), ("ftp", ""))

    def test_postfix_has_no_version(self):
        s = identify(25, "220 mail.example.com ESMTP Postfix (Ubuntu)")
        self.assertEqual((s.name, s.product, s.version), ("smtp", "Postfix", ""))

    def test_exim_with_version(self):
        s = identify(25, "220 mail.example.com ESMTP Exim 4.97 Thu, 12 Nov 2026 10:00:00")
        self.assertEqual((s.name, s.product, s.version), ("smtp", "Exim", "4.97"))

    def test_smtp_is_not_mistaken_for_ftp(self):
        self.assertEqual(identify(2525, "220 mx.example.com ESMTP ready").name, "smtp")


class TestIdentifyFallbacks(unittest.TestCase):
    def test_empty_banner_falls_back_to_port(self):
        s = identify(22, "")
        self.assertEqual((s.name, s.product, s.confidence), ("ssh", "", "port"))
        self.assertEqual(identify(5432, "").name, "postgresql")

    def test_unknown_port_and_banner(self):
        s = identify(31337, "")
        self.assertEqual((s.name, s.confidence), ("unknown", "unknown"))

    def test_unrecognized_banner_on_known_port(self):
        s = identify(3306, "binary-ish junk")
        self.assertEqual((s.name, s.confidence), ("mysql", "port"))

    def test_none_banner_is_safe(self):
        self.assertEqual(identify(80, None).name, "http")

    def test_hostile_long_fields_are_truncated(self):
        s = identify(80, "HTTP/1.1 200 OK | Server: " + "A" * 500 + "/" + "9" * 500)
        self.assertLessEqual(len(s.product), 64)
        self.assertLessEqual(len(s.version), 64)


STARTED = datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)


def sample_results():
    return [
        PortResult(22, "open", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"),
        PortResult(23, "closed"),
        PortResult(80, "open", "HTTP/1.1 200 OK | Server: nginx/1.24.0"),
        PortResult(81, "filtered"),
        PortResult(82, "closed"),
    ]


class TestReport(unittest.TestCase):
    def test_structure_and_counts(self):
        report = build_report("host.local", "10.0.0.5", 5, sample_results(), STARTED, 1.234)
        self.assertEqual(report["tool"], "vuln-scanner")
        self.assertEqual(report["target"], "host.local")
        self.assertEqual(report["address"], "10.0.0.5")
        self.assertEqual(report["ports_scanned"], 5)
        self.assertEqual(report["duration_seconds"], 1.23)
        self.assertEqual(report["started"], "2026-11-23T12:00:00+00:00")
        self.assertEqual(report["summary"], {"open": 2, "closed": 2, "filtered": 1})

    def test_only_open_ports_are_listed_with_service_details(self):
        report = build_report("h", "10.0.0.5", 5, sample_results(), STARTED, 1)
        self.assertEqual([p["port"] for p in report["open_ports"]], [22, 80])
        ssh = report["open_ports"][0]
        self.assertEqual((ssh["service"], ssh["product"], ssh["version"]),
                         ("ssh", "OpenSSH", "9.6p1"))
        self.assertEqual(ssh["confidence"], "banner")

    def test_empty_results(self):
        report = build_report("h", "10.0.0.5", 0, [], STARTED, 0)
        self.assertEqual(report["open_ports"], [])
        self.assertEqual(report["summary"], {"open": 0, "closed": 0, "filtered": 0})

    def test_write_json_round_trip(self):
        report = build_report("h", "10.0.0.5", 5, sample_results(), STARTED, 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "scan.json")
            write_json(report, path)
            with open(path, encoding="utf-8") as f:
                self.assertEqual(json.load(f), report)


class TestCliJson(unittest.TestCase):
    def test_cli_writes_json_for_a_real_local_service(self):
        service = FakeService(banner=b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
        self.addCleanup(service.close)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "scan.json")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["127.0.0.1", "--ports", str(service.port),
                             "--timeout", "1", "--json", path])
            self.assertEqual(code, 0)
            self.assertIn("Wrote JSON report", out.getvalue())
            self.assertIn("OpenSSH 9.6p1", out.getvalue())
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        self.assertEqual(data["summary"]["open"], 1)
        self.assertEqual(data["open_ports"][0]["product"], "OpenSSH")
        self.assertEqual(data["open_ports"][0]["version"], "9.6p1")

    def test_cli_reports_unwritable_json_path_without_a_traceback(self):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = main(["127.0.0.1", "--ports", "1", "--timeout", "1",
                         "--json", "/nonexistent-folder/scan.json"])
        self.assertEqual(code, 1)
        self.assertIn("could not write", err.getvalue())


if __name__ == "__main__":
    unittest.main()
