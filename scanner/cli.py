"""Command-line interface for the port scanner.

Example:
    python3 -m scanner 127.0.0.1 --ports 1-1024

Safety: the scanner refuses public IP addresses unless --allow-public is
given. Only scan systems you own or have written permission to test.
"""
import argparse
import ipaddress
import socket
import time
from typing import List, Optional

from scanner.portscan import parse_ports, scan_ports


def is_private_address(address: str) -> bool:
    """True for loopback, private (RFC 1918), and link-local addresses."""
    ip = ipaddress.ip_address(address)
    return ip.is_private or ip.is_loopback or ip.is_link_local


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="TCP port scanner with banner grabbing. "
                    "Only scan systems you own or have written permission to test.",
    )
    parser.add_argument("target", help="hostname or IPv4 address to scan")
    parser.add_argument("--ports", default="1-1024",
                        help='ports to scan, e.g. "22,80,8000-8010" (default 1-1024)')
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="connect timeout in seconds (default 0.5)")
    parser.add_argument("--workers", type=int, default=100,
                        help="parallel connections, 1-500 (default 100)")
    parser.add_argument("--allow-public", action="store_true",
                        help="allow scanning public IP addresses (only with permission)")
    return parser


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
    started = time.monotonic()
    results = scan_ports(address, ports, timeout=args.timeout, workers=args.workers)
    elapsed = time.monotonic() - started

    open_ports = [r for r in results if r.state == "open"]
    if open_ports:
        print(f"{'PORT':<8}{'STATE':<8}BANNER")
        for r in open_ports:
            print(f"{r.port:<8}{r.state:<8}{r.banner}")
    else:
        print("No open ports found.")

    closed = sum(1 for r in results if r.state == "closed")
    filtered = sum(1 for r in results if r.state == "filtered")
    print(f"Done in {elapsed:.1f}s: {len(open_ports)} open, {closed} closed, {filtered} filtered.")
    return 0
