"""TCP connect port scanner with banner grabbing.

How it works:
  - A port is "open" if a full TCP connection succeeds, "closed" if the
    target actively refuses it, and "filtered" if nothing answers in time
    (usually a firewall dropping packets).
  - For open ports we read whatever the service says first (SSH, FTP and
    SMTP announce themselves). Web servers stay silent until asked, so on
    common HTTP ports we send a minimal HEAD request.
  - Ports are scanned in parallel with a thread pool.

Banners come from the machine being scanned, so they are untrusted input.
They are stripped of control characters and truncated before use.
"""
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Iterable, List

HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
MAX_BANNER_CHARS = 200


@dataclass(frozen=True)
class PortResult:
    port: int
    state: str          # "open", "closed", or "filtered"
    banner: str = ""


def _to_port(text: str) -> int:
    try:
        value = int(text.strip())
    except ValueError:
        raise ValueError(f"not a port number: {text!r}") from None
    if not 1 <= value <= 65535:
        raise ValueError(f"port out of range (1-65535): {value}")
    return value


def parse_ports(spec: str) -> List[int]:
    """Turn '22,80,8000-8010' into a sorted list of unique port numbers."""
    if not spec or not spec.strip():
        raise ValueError("no ports given")
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise ValueError("empty entry in port list")
        if "-" in part:
            low_text, _, high_text = part.partition("-")
            low, high = _to_port(low_text), _to_port(high_text)
            if low > high:
                raise ValueError(f"invalid range: {part}")
            ports.update(range(low, high + 1))
        else:
            ports.add(_to_port(part))
    return sorted(ports)


def clean_banner(data: bytes) -> str:
    """Make a raw banner safe to print: one line, printable characters only."""
    text = data.decode("utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    joined = " | ".join(lines)
    safe = "".join(c if c.isprintable() else "?" for c in joined)
    return safe[:MAX_BANNER_CHARS]


def _grab_banner(sock, host: str, port: int, banner_timeout: float, http_ports) -> str:
    sock.settimeout(banner_timeout)
    try:
        if port in http_ports:
            request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
            sock.sendall(request.encode("ascii", errors="replace"))
        data = sock.recv(1024)
    except OSError:
        return ""
    return clean_banner(data)


def scan_port(host: str, port: int, timeout: float = 0.5,
              banner_timeout: float = 0.5, http_ports=HTTP_PORTS) -> PortResult:
    """Scan one port and return its state and any banner."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        return PortResult(port, "closed")
    except OSError:  # timeouts, unreachable networks, and so on
        return PortResult(port, "filtered")
    with sock:
        banner = _grab_banner(sock, host, port, banner_timeout, http_ports)
    return PortResult(port, "open", banner)


def scan_ports(host: str, ports: Iterable[int], timeout: float = 0.5,
               banner_timeout: float = 0.5, workers: int = 100,
               http_ports=HTTP_PORTS) -> List[PortResult]:
    """Scan many ports in parallel. Results are sorted by port number."""
    ports = list(ports)
    if not ports:
        return []
    workers = max(1, min(workers, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(
            lambda p: scan_port(host, p, timeout, banner_timeout, http_ports), ports))
    return sorted(results, key=lambda r: r.port)
