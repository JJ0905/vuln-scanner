"""Identify services and software versions from banners.

This is a best guess, not proof. A server can hide or fake its banner, and
Linux distributions often backport security fixes without changing the
version number. So a version found here says "this is what the service
claims to be", and any CVE match built on it can be wrong in both directions.

Order of evidence: the banner wins; if the banner says nothing useful, we
fall back to the conventional service for that port number and mark the
result as a weaker guess ("port").
"""
import re
from dataclasses import dataclass
from typing import Optional

MAX_FIELD = 64

WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 993: "imaps",
    995: "pop3s", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http", 8443: "https", 27017: "mongodb",
}

# Consistent product names, so later steps can match them against CVE data.
CANONICAL = {
    "openssh": "OpenSSH", "dropbear": "Dropbear", "libssh": "libssh",
    "nginx": "nginx", "apache": "Apache", "lighttpd": "lighttpd",
    "microsoft-iis": "Microsoft IIS", "simplehttp": "SimpleHTTP",
    "vsftpd": "vsFTPd", "proftpd": "ProFTPD", "pure-ftpd": "Pure-FTPd",
    "postfix": "Postfix", "exim": "Exim", "sendmail": "Sendmail",
}


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    product: str = ""
    version: str = ""
    confidence: str = "unknown"   # "banner", "port", or "unknown"


SSH_RE = re.compile(r"^SSH-\d\.\d+-(?P<software>\S+)", re.I)
SSH_SOFTWARE_RE = re.compile(r"^(?P<product>[A-Za-z][A-Za-z0-9_]*?)[_-](?P<version>\d[\w.+~-]*)$")
HTTP_RE = re.compile(r"^HTTP/\d", re.I)
SERVER_HEADER_RE = re.compile(r"\bServer:\s*(?P<value>[^|]+)", re.I)
FIRST_TOKEN_RE = re.compile(r"(?P<product>[A-Za-z0-9._-]+)(?:/(?P<version>[A-Za-z0-9._+~-]+))?")
SMTP_RE = re.compile(r"^220[ -]\S+\s+E?SMTP\s*(?P<rest>.*)", re.I)
FTP_BANNER_RE = re.compile(r"^220[ -]")
SMTP_PRODUCT_RE = re.compile(r"(?P<product>[A-Za-z][\w-]*)(?:[ /](?P<version>\d[\w.]*))?")

FTP_PRODUCTS = [
    ("vsFTPd", re.compile(r"vsFTPd\s+(\d[\w.]*)", re.I)),
    ("ProFTPD", re.compile(r"ProFTPD\s+(\d[\w.]*)", re.I)),
    ("Pure-FTPd", re.compile(r"Pure-FTPd", re.I)),
]


def _trim(text: str) -> str:
    return text.strip()[:MAX_FIELD]


def _canonical(product: str) -> str:
    return _trim(CANONICAL.get(product.lower(), product))


def _ssh(banner: str) -> Optional[ServiceInfo]:
    m = SSH_RE.match(banner)
    if not m:
        return None
    software = m.group("software")
    parts = SSH_SOFTWARE_RE.match(software)
    if parts:
        return ServiceInfo("ssh", _canonical(parts.group("product")),
                           _trim(parts.group("version")), "banner")
    return ServiceInfo("ssh", _canonical(software), "", "banner")


def _http(banner: str) -> Optional[ServiceInfo]:
    if not HTTP_RE.match(banner):
        return None
    header = SERVER_HEADER_RE.search(banner)
    if not header:
        return ServiceInfo("http", confidence="banner")
    token = FIRST_TOKEN_RE.match(header.group("value").strip())
    if not token:
        return ServiceInfo("http", confidence="banner")
    return ServiceInfo("http", _canonical(token.group("product")),
                       _trim(token.group("version") or ""), "banner")


def _smtp(banner: str) -> Optional[ServiceInfo]:
    m = SMTP_RE.match(banner)
    if not m:
        return None
    rest = m.group("rest").strip()
    token = SMTP_PRODUCT_RE.match(rest) if rest else None
    if not token:
        return ServiceInfo("smtp", confidence="banner")
    return ServiceInfo("smtp", _canonical(token.group("product")),
                       _trim(token.group("version") or ""), "banner")


def _ftp(banner: str) -> Optional[ServiceInfo]:
    if not FTP_BANNER_RE.match(banner):
        return None
    for product, pattern in FTP_PRODUCTS:
        m = pattern.search(banner)
        if m:
            return ServiceInfo("ftp", product, _trim(m.group(1)) if m.lastindex else "", "banner")
    return ServiceInfo("ftp", confidence="banner")


def identify(port: int, banner: str) -> ServiceInfo:
    """Best-guess service for a port, from its banner first and its number second."""
    banner = (banner or "").strip()
    for detector in (_ssh, _http, _smtp, _ftp):   # SMTP before FTP: both start with 220
        info = detector(banner)
        if info:
            return info
    guess = WELL_KNOWN_PORTS.get(port)
    if guess:
        return ServiceInfo(guess, confidence="port")
    return ServiceInfo("unknown")
