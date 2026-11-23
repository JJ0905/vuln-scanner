"""Look up known vulnerabilities (CVEs) for a detected product and version.

Data source: the National Vulnerability Database (NVD) CVE API 2.0.

What this can and cannot tell you:
  * The version comes from a banner the service chose to send. It may be
    hidden, faked, or patched without a version change (Linux distributions
    backport fixes). A match means "this version has known CVEs", not "this
    host is exploitable".
  * "No CVEs found" is only reported when NVD was actually asked and
    answered. If we could not ask (unknown product, no version, network
    error), the result carries a different status that says so.

Privacy: only the product and version are sent to NVD, never the target.
The API key, if any, is read from the environment and sent as a header. It
is never put in a URL, a log line, or an error message.
"""
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

USER_AGENT = "vuln-scanner-learning-project/0.3"
MAX_RESPONSE_BYTES = 10_000_000
RETRY_STATUSES = {403, 429, 503}   # NVD answers 403 when you exceed the rate limit
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}

# Product name (as scanner.services reports it) -> (CPE vendor, CPE product).
CPE_PRODUCTS = {
    "OpenSSH": ("openbsd", "openssh"),
    "Dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
    "libssh": ("libssh", "libssh"),
    "nginx": ("nginx", "nginx"),
    "Apache": ("apache", "http_server"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "Microsoft IIS": ("microsoft", "internet_information_services"),
    "vsFTPd": ("beasts", "vsftpd"),
    "ProFTPD": ("proftpd", "proftpd"),
    "Pure-FTPd": ("pureftpd", "pure-ftpd"),
    "Postfix": ("postfix", "postfix"),
    "Exim": ("exim", "exim"),
    "Sendmail": ("sendmail", "sendmail"),
}

# Versions come from an untrusted banner and end up inside a CPE name and a
# URL, so only a strict, simple shape is allowed.
VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,4}(?:[A-Za-z]{1,3}\d{0,3})?$")
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    score: Optional[float]
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, NONE, or UNKNOWN
    summary: str
    published: str


@dataclass
class LookupResult:
    # ok, no_product, no_mapping, no_version, unknown_cpe, or error
    status: str
    cpe: str = ""
    cves: List[Vulnerability] = field(default_factory=list)
    total: int = 0
    truncated: bool = False
    cached: bool = False
    error: str = ""


def build_cpe(product: str, version: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (cpe_name, None), or (None, reason) when no CPE can be built."""
    if not product:
        return None, "no_product"
    mapping = CPE_PRODUCTS.get(product)
    if not mapping:
        return None, "no_mapping"
    if not version or not VERSION_RE.match(version):
        return None, "no_version"
    vendor, name = mapping
    update = "*"
    if product == "OpenSSH":   # NVD writes 9.6p1 as version 9.6, update p1
        m = re.match(r"^(\d+(?:\.\d+)*)(p\d+)$", version)
        if m:
            version, update = m.group(1), m.group(2)
    return f"cpe:2.3:a:{vendor}:{name}:{version}:{update}:*:*:*:*:*:*", None


def _clean(text, limit: int) -> str:
    return "".join(c if c.isprintable() else " " for c in str(text))[:limit]


def _best_metric(metrics: dict) -> Tuple[Optional[float], str]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries or not isinstance(entries[0], dict):
            continue
        entry = entries[0]
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            score = None
        severity = str(data.get("baseSeverity") or entry.get("baseSeverity") or "").upper()
        return score, severity if severity in SEVERITIES else "UNKNOWN"
    return None, "UNKNOWN"


def parse_response(payload) -> Tuple[List[Vulnerability], int]:
    """Turn one NVD response page into Vulnerability objects. Never raises."""
    if not isinstance(payload, dict):
        return [], 0
    items = payload.get("vulnerabilities")
    if not isinstance(items, list):
        return [], 0

    vulns: List[Vulnerability] = []
    for item in items:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("id", ""))
        if not CVE_ID_RE.match(cve_id):
            continue
        summary = ""
        for desc in cve.get("descriptions") or []:
            if isinstance(desc, dict) and desc.get("lang") == "en":
                summary = desc.get("value", "")
                break
        metrics = cve.get("metrics")
        score, severity = _best_metric(metrics if isinstance(metrics, dict) else {})
        vulns.append(Vulnerability(
            cve_id=cve_id,
            score=score,
            severity=severity,
            summary=_clean(summary, 300),
            published=_clean(cve.get("published", ""), 40),
        ))

    total = payload.get("totalResults")
    if isinstance(total, bool) or not isinstance(total, int):
        total = len(vulns)
    return vulns, total


class CveCache:
    """A small JSON file cache, so repeat scans don't hit NVD's rate limit."""

    def __init__(self, path, ttl_seconds: int = 86400, clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self.ttl = ttl_seconds
        self.clock = clock
        self._data = self._load()

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def get(self, cpe: str) -> Optional[LookupResult]:
        entry = self._data.get(cpe)
        if not isinstance(entry, dict):
            return None
        try:
            if self.clock() - float(entry["fetched_at"]) > self.ttl:
                return None
            cves = [Vulnerability(**c) for c in entry["cves"]]
            return LookupResult("ok", cpe=cpe, cves=cves, total=int(entry["total"]),
                                truncated=bool(entry["truncated"]), cached=True)
        except (KeyError, TypeError, ValueError):
            return None

    def put(self, result: LookupResult) -> None:
        self._data[result.cpe] = {
            "fetched_at": self.clock(),
            "total": result.total,
            "truncated": result.truncated,
            "cves": [asdict(v) for v in result.cves],
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._data), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            pass  # the cache is an optimisation; it must never break a scan


def _http_fetch(url: str, headers: dict, timeout: float) -> Tuple[int, str]:
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise OSError("response too large")
            return response.status, body.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        return err.code, ""


class NvdClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, cache: Optional[CveCache] = None,
                 fetch=None, sleep=time.sleep, clock=time.monotonic,
                 page_size: int = 500, max_pages: int = 5, max_retries: int = 2,
                 retry_wait: float = 30.0, timeout: float = 20.0):
        self.api_key = api_key
        self.cache = cache
        self.fetch = fetch or _http_fetch
        self._sleep = sleep
        self._clock = clock
        self.page_size = page_size
        self.max_pages = max_pages
        self.max_retries = max_retries
        self.retry_wait = retry_wait
        self.timeout = timeout
        # NVD allows 5 requests per 30 seconds without a key, 50 with one.
        self.min_interval = 0.7 if api_key else 6.5
        self._last_request = None

    def _wait_turn(self) -> None:
        if self._last_request is not None:
            elapsed = self._clock() - self._last_request
            if elapsed < self.min_interval:
                self._sleep(self.min_interval - elapsed)
        self._last_request = self._clock()

    def _request(self, cpe: str, start: int) -> Tuple[int, str]:
        query = urllib.parse.urlencode(
            {"cpeName": cpe, "resultsPerPage": self.page_size, "startIndex": start})
        url = f"{self.BASE_URL}?{query}&isVulnerable"
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        status, text = 0, ""
        for attempt in range(self.max_retries + 1):
            self._wait_turn()
            status, text = self.fetch(url, headers, self.timeout)
            if status not in RETRY_STATUSES:
                break
            if attempt < self.max_retries:
                self._sleep(self.retry_wait)
        return status, text

    def lookup(self, product: str, version: str) -> LookupResult:
        cpe, reason = build_cpe(product, version)
        if cpe is None:
            return LookupResult(reason)

        if self.cache is not None:
            cached = self.cache.get(cpe)
            if cached is not None:
                return cached

        collected: List[Vulnerability] = []
        total, start = 0, 0
        try:
            for _ in range(self.max_pages):
                status, text = self._request(cpe, start)
                if status == 404:
                    return LookupResult("unknown_cpe", cpe=cpe,
                                        error="NVD does not recognise this exact product and version")
                if status != 200:
                    return LookupResult("error", cpe=cpe, error=f"NVD returned HTTP {status}")
                try:
                    payload = json.loads(text)
                except ValueError:
                    return LookupResult("error", cpe=cpe, error="NVD returned an unreadable response")
                page, total = parse_response(payload)
                collected.extend(page)
                start += self.page_size
                if not page or start >= total:
                    break
        except OSError as err:
            return LookupResult("error", cpe=cpe, error=f"could not reach NVD ({type(err).__name__})")

        result = LookupResult("ok", cpe=cpe, cves=collected,
                              total=max(total, len(collected)),
                              truncated=len(collected) < total)
        if self.cache is not None:
            self.cache.put(result)
        return result
