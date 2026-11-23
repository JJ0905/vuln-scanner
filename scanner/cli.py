"""Command-line interface for the port scanner.

Examples:
    python3 -m scanner 127.0.0.1 --ports 1-1024
    python3 -m scanner 127.0.0.1 --ports 1-1024 --json scan.json
    python3 -m scanner 127.0.0.1 --ports 1-1024 --cve --html report.html

Safety: the scanner refuses public IP addresses unless --allow-public is
given. Only scan systems you own or have written permission to test.

CVE lookups (--cve) send only a product name and version to the National
Vulnerability Database, never the target. An optional NVD API key is read
from the NVD_API_KEY environment variable (not a command-line option, so it
never lands in your shell history).
"""
import argparse
import ipaddress
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from scanner.cve import CveCache, NvdClient
from scanner.portscan import parse_ports, scan_ports
from scanner.html_report import write_html
from scanner.report import STATUS_TEXT, build_report, write_json
from scanner.services import identify

DEFAULT_CACHE = Path.home() / ".cache" / "vuln-scanner" / "nvd-cache.json"

def is_private_address(address: str) -> bool:
    """True for loopback, private (RFC 1918), and link-local addresses."""
    ip = ipaddress.ip_address(address)
    return ip.is_private or ip.is_loopback or ip.is_link_local


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="TCP port scanner with banner grabbing, service detection and "
                    "optional CVE lookup. Only scan systems you own or have written "
                    "permission to test.",
    )
    parser.add_argument("target", help="hostname or IPv4 address to scan")
    parser.add_argument("--ports", default="1-1024",
                        help='ports to scan, e.g. "22,80,8000-8010" (default 1-1024)')
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="connect timeout in seconds (default 0.5)")
    parser.add_argument("--workers", type=int, default=100,
                        help="parallel connections, 1-500 (default 100)")
    parser.add_argument("--cve", action="store_true",
                        help="look up known CVEs for detected products in the NVD "
                             "(sends only product and version)")
    parser.add_argument("--cache-file", default=str(DEFAULT_CACHE),
                        help="where to cache NVD answers (default: %(default)s)")
    parser.add_argument("--json", metavar="FILE",
                        help="write the results to FILE as JSON")
    parser.add_argument("--html", metavar="FILE",
                        help="write a standalone HTML report to FILE")
    parser.add_argument("--allow-public", action="store_true",
                        help="allow scanning public IP addresses (only with permission)")
    return parser


def lookup_cves(results, client) -> dict:
    """Look up each open port's product and version. One NVD query per unique pair."""
    seen = {}
    by_port = {}
    for r in results:
        if r.state != "open":
            continue
        service = identify(r.port, r.banner)
        key = (service.product, service.version)
        if key not in seen:
            seen[key] = client.lookup(*key)
        by_port[r.port] = seen[key]
    return by_port


def _score_text(score) -> str:
    return f"{score:.1f}" if score is not None else "n/a"


def print_cve_section(report: dict) -> None:
    print("\nKnown vulnerabilities (from the NVD, based on the versions services claim; verify before acting):")
    for p in report["open_ports"]:
        block = p.get("vulnerabilities")
        if block is None:
            continue
        label = f"{p['port']}  {(p['product'] + ' ' + p['version']).strip() or p['service']}"
        status = block["status"]
        if status == "ok":
            cves = block["cves"]
            if not cves:
                print(f"  {label}: no known CVEs in the NVD for this version")
                continue
            top = cves[0]
            note = " (list truncated)" if block["truncated"] else ""
            print(f"  {label}: {block['total']} CVE(s){note}, highest "
                  f"{_score_text(top['score'])} {top['severity']}")
            for c in cves[:5]:
                print(f"      {c['cve_id']:<16}{_score_text(c['score']):>4}  "
                      f"{c['severity']:<8} {c['summary'][:90]}")
        elif status == "error":
            print(f"  {label}: lookup failed ({block['error']})")
        else:
            print(f"  {label}: {STATUS_TEXT.get(status, status)}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as err:
        parser.error(str(err))
    if not 1 <= args.workers <= 500:
        parser.error("--workers must be between 1 and 500")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    try:
        address = socket.gethostbyname(args.target)
    except (OSError, UnicodeError):
        parser.error(f"cannot resolve {args.target}")

    if not is_private_address(address) and not args.allow_public:
        parser.error(
            f"{address} is a public address. Only scan systems you own or have "
            "written permission to test, then add --allow-public.")

    print(f"Scanning {args.target} ({address}), {len(ports)} port(s)...")
    started_at = datetime.now(timezone.utc)
    started = time.monotonic()
    results = scan_ports(address, ports, timeout=args.timeout, workers=args.workers)
    elapsed = time.monotonic() - started

    vulnerabilities = None
    if args.cve:
        print("Looking up CVEs in the National Vulnerability Database "
              "(only product and version are sent; this can take a while)...")
        client = NvdClient(api_key=os.environ.get("NVD_API_KEY") or None,
                           cache=CveCache(args.cache_file))
        vulnerabilities = lookup_cves(results, client)

    report = build_report(args.target, address, len(ports), results, started_at,
                          elapsed, vulnerabilities)

    if report["open_ports"]:
        print(f"{'PORT':<8}{'SERVICE':<12}{'VERSION':<26}BANNER")
        for p in report["open_ports"]:
            version = f"{p['product']} {p['version']}".strip()
            print(f"{p['port']:<8}{p['service']:<12}{version:<26}{p['banner']}")
    else:
        print("No open ports found.")

    s = report["summary"]
    print(f"Done in {elapsed:.1f}s: {s['open']} open, {s['closed']} closed, {s['filtered']} filtered.")

    if args.cve:
        print_cve_section(report)

    if args.json:
        try:
            write_json(report, args.json)
        except OSError as err:
            print(f"error: could not write {args.json}: {err}", file=sys.stderr)
            return 1
        print(f"Wrote JSON report to {args.json}")

    if args.html:
        try:
            write_html(report, args.html)
        except OSError as err:
            print(f"error: could not write {args.html}: {err}", file=sys.stderr)
            return 1
        print(f"Wrote HTML report to {args.html}")
    return 0
