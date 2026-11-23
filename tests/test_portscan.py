import contextlib
import io
import socket
import threading
import unittest
from unittest import mock

from scanner.cli import is_private_address, main
from scanner.portscan import clean_banner, parse_ports, scan_port, scan_ports


class FakeService:
    """A tiny TCP server on 127.0.0.1 so tests never touch a real network."""

    def __init__(self, banner=b"", wait_for_request=False, reply=b""):
        self.banner = banner
        self.wait_for_request = wait_for_request
        self.reply = reply
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(10)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    if self.banner:
                        conn.sendall(self.banner)
                    conn.settimeout(2)
                    if self.wait_for_request:
                        conn.recv(1024)
                        conn.sendall(self.reply)
                    else:
                        conn.recv(1)  # hold the connection until the client leaves
                except OSError:
                    pass

    def close(self):
        self.sock.close()


def free_closed_port():
    """A port that nothing is listening on."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestParsePorts(unittest.TestCase):
    def test_single_and_list(self):
        self.assertEqual(parse_ports("22"), [22])
        self.assertEqual(parse_ports("80,22"), [22, 80])

    def test_ranges_and_mixed(self):
        self.assertEqual(parse_ports("20-22"), [20, 21, 22])
        self.assertEqual(parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])

    def test_duplicates_removed(self):
        self.assertEqual(parse_ports("22,22,20-22"), [20, 21, 22])

    def test_whitespace_tolerated(self):
        self.assertEqual(parse_ports(" 22 , 80 "), [22, 80])

    def test_invalid_specs_raise(self):
        for bad in ("", "  ", "0", "65536", "abc", "5-3", "22,,80", "-5", "22-", "1.5"):
            with self.assertRaises(ValueError, msg=bad):
                parse_ports(bad)


class TestCleanBanner(unittest.TestCase):
    def test_plain_banner(self):
        self.assertEqual(clean_banner(b"SSH-2.0-OpenSSH_9.6\r\n"), "SSH-2.0-OpenSSH_9.6")

    def test_multiple_lines_joined(self):
        self.assertEqual(clean_banner(b"HTTP/1.0 200 OK\r\nServer: x\r\n\r\n"),
                         "HTTP/1.0 200 OK | Server: x")

    def test_control_characters_removed(self):
        cleaned = clean_banner(b"\x1b[31mevil\x00\x07 text")
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\x00", cleaned)
        self.assertNotIn("\x07", cleaned)

    def test_long_banner_truncated(self):
        self.assertEqual(len(clean_banner(b"A" * 5000)), 200)

    def test_invalid_utf8_does_not_crash(self):
        self.assertIsInstance(clean_banner(b"\xff\xfe\xfdabc"), str)

    def test_empty(self):
        self.assertEqual(clean_banner(b""), "")


class TestScanPort(unittest.TestCase):
    def test_open_port_with_banner(self):
        service = FakeService(banner=b"SSH-2.0-TestServer_1.0\r\n")
        self.addCleanup(service.close)
        result = scan_port("127.0.0.1", service.port, timeout=1, banner_timeout=1)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.banner, "SSH-2.0-TestServer_1.0")

    def test_open_port_that_stays_silent(self):
        service = FakeService()
        self.addCleanup(service.close)
        result = scan_port("127.0.0.1", service.port, timeout=1, banner_timeout=0.3)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.banner, "")

    def test_http_probe_gets_server_header(self):
        service = FakeService(wait_for_request=True,
                              reply=b"HTTP/1.0 200 OK\r\nServer: TestHTTP/1.2\r\n\r\n")
        self.addCleanup(service.close)
        result = scan_port("127.0.0.1", service.port, timeout=1, banner_timeout=1,
                           http_ports={service.port})
        self.assertEqual(result.state, "open")
        self.assertIn("Server: TestHTTP/1.2", result.banner)

    def test_hostile_banner_is_sanitized(self):
        service = FakeService(banner=b"\x1b[2Jpwned\x00\r\n")
        self.addCleanup(service.close)
        result = scan_port("127.0.0.1", service.port, timeout=1, banner_timeout=1)
        self.assertNotIn("\x1b", result.banner)
        self.assertNotIn("\x00", result.banner)

    def test_closed_port(self):
        result = scan_port("127.0.0.1", free_closed_port(), timeout=1)
        self.assertEqual(result.state, "closed")
        self.assertEqual(result.banner, "")

    def test_timeout_is_filtered(self):
        with mock.patch("scanner.portscan.socket.create_connection", side_effect=TimeoutError):
            self.assertEqual(scan_port("10.0.0.1", 80).state, "filtered")

    def test_network_error_is_filtered(self):
        with mock.patch("scanner.portscan.socket.create_connection",
                        side_effect=OSError("unreachable")):
            self.assertEqual(scan_port("10.0.0.1", 80).state, "filtered")


class TestScanPorts(unittest.TestCase):
    def test_mixed_results_sorted_by_port(self):
        a = FakeService(banner=b"one\r\n")
        b = FakeService(banner=b"two\r\n")
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        closed = free_closed_port()
        ports = [b.port, closed, a.port]
        results = scan_ports("127.0.0.1", ports, timeout=1, banner_timeout=1, workers=10)
        self.assertEqual([r.port for r in results], sorted(ports))
        states = {r.port: r.state for r in results}
        self.assertEqual(states[a.port], "open")
        self.assertEqual(states[b.port], "open")
        self.assertEqual(states[closed], "closed")

    def test_empty_port_list(self):
        self.assertEqual(scan_ports("127.0.0.1", []), [])

    def test_more_workers_than_ports_is_fine(self):
        results = scan_ports("127.0.0.1", [free_closed_port()], timeout=1, workers=500)
        self.assertEqual(len(results), 1)


class TestSafetyAndCli(unittest.TestCase):
    def test_private_addresses(self):
        for address in ("127.0.0.1", "10.1.2.3", "192.168.1.20", "172.16.5.5", "169.254.1.1"):
            self.assertTrue(is_private_address(address), address)

    def test_public_addresses(self):
        for address in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
            self.assertFalse(is_private_address(address), address)

    def test_cli_refuses_public_address_without_flag(self):
        stderr = io.StringIO()
        with mock.patch("scanner.cli.scan_ports") as scan, \
                contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
            main(["8.8.8.8", "--ports", "80"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("public address", stderr.getvalue())
        scan.assert_not_called()

    def test_cli_allows_public_address_with_flag(self):
        with mock.patch("scanner.cli.scan_ports", return_value=[]) as scan, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["8.8.8.8", "--ports", "80", "--allow-public"]), 0)
        scan.assert_called_once()

    def test_cli_rejects_bad_ports_and_options(self):
        for argv in (["127.0.0.1", "--ports", "abc"],
                     ["127.0.0.1", "--ports", "22", "--workers", "0"],
                     ["127.0.0.1", "--ports", "22", "--workers", "501"],
                     ["127.0.0.1", "--ports", "22", "--timeout", "0"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(argv)

    def test_cli_unresolvable_host(self):
        with mock.patch("scanner.cli.socket.gethostbyname", side_effect=OSError), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["no-such-host.invalid", "--ports", "22"])

    def test_cli_end_to_end_against_local_service(self):
        service = FakeService(banner=b"SSH-2.0-TestServer_1.0\r\n")
        self.addCleanup(service.close)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["127.0.0.1", "--ports", str(service.port), "--timeout", "1"])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn(str(service.port), text)
        self.assertIn("open", text)
        self.assertIn("SSH-2.0-TestServer_1.0", text)
        self.assertIn("1 open", text)

    def test_cli_reports_no_open_ports(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["127.0.0.1", "--ports", str(free_closed_port()), "--timeout", "1"])
        self.assertIn("No open ports found.", out.getvalue())


if __name__ == "__main__":
    unittest.main()
