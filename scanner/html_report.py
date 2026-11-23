"""Standalone HTML report for a scan.

Banners come from the scanned host and CVE text comes from a web API, so
neither is trusted. Everything is cleaned and HTML-escaped, the page carries
a Content-Security-Policy that blocks scripts and remote resources, and the
only links are to NVD pages built from CVE IDs that pass a strict pattern.
"""
import html
import re
from typing import Optional

from scanner.report import STATUS_TEXT

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")
KNOWN_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
MAX_CVES_PER_PORT = 50
NVD_NOTICE = ("This product uses data from the NVD API but is not endorsed or "
              "certified by the NVD.")
CAVEAT = ("CVE matches are leads, not confirmed findings. They are based on the "
          "version a service reports, which can be wrong, and many Linux "
          "distributions patch vulnerabilities without changing the version number.")

CSS = """
body { font-family: -apple-system, system-ui, sans-serif; margin: 2rem; color: #1a1a1a; max-width: 70rem; }
h1 { margin-bottom: 0.25rem; }
h2 { margin-top: 2rem; }
.meta { color: #555; }
.cards { display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }
.card { border: 1px solid #ccc; border-radius: 8px; padding: 0.75rem 1.25rem; }
.card b { display: block; font-size: 1.8rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; margin-bottom: 1rem; }
th, td { border: 1px solid #ddd; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #f3f3f3; }
code { font-family: ui-monospace, Menlo, monospace; font-size: 0.85rem; }
.sev { font-weight: 600; }
.sev-critical, .sev-high { color: #b00020; }
.sev-medium { color: #b26a00; }
.sev-low, .sev-other { color: #555; }
.wrap { word-break: break-word; }
.nowrap { white-space: nowrap; }
.note { background: #fff8e1; border: 1px solid #e6c200; border-radius: 6px; padding: 0.6rem 0.9rem; }
footer { margin-top: 2rem; color: #555; font-size: 0.85rem; }
"""


def clean(text, limit: int = 300) -> str:
    """Replace non-printable characters (such as terminal escape codes)."""
    return "".join(c if c.isprintable() else "?" for c in str(text))[:limit]


def _esc(text, limit: int = 300) -> str:
    return html.escape(clean(text, limit))


def _score(score) -> str:
    return f"{score:.1f}" if isinstance(score, (int, float)) else "n/a"


def _cve_cell(cve_id) -> str:
    if isinstance(cve_id, str) and CVE_ID_RE.match(cve_id):
        return (f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}" '
                f'rel="noopener noreferrer">{cve_id}</a>')
    return html.escape(clean(cve_id, 40))


def _cve_section(port: dict) -> str:
    block = port.get("vulnerabilities")
    if block is None:
        return ""
    status = block.get("status")
    name = (f"{port['product']} {port['version']}".strip() or port["service"])
    heading = f"<h3>Port {int(port['port'])}: {html.escape(clean(name, 80))}</h3>"
    if status == "error":
        return heading + f"<p>Lookup failed: {_esc(block.get('error'))}</p>"
    if status != "ok":
        return heading + f"<p>{_esc(STATUS_TEXT.get(status, status))}</p>"
    cves = block.get("cves", [])
    if not cves:
        return heading + "<p>No known CVEs in the NVD for this version.</p>"

    shown = cves[:MAX_CVES_PER_PORT]
    rows = []
    for c in shown:
        sev = str(c.get("severity") or "").upper()
        sev_class = sev.lower() if sev in KNOWN_SEVERITIES else "other"
        rows.append(
            "<tr>"
            f'<td class="nowrap">{_cve_cell(c.get("cve_id"))}</td>'
            f"<td>{_score(c.get('score'))}</td>"
            f'<td class="sev sev-{sev_class}">{_esc(sev or "n/a", 20)}</td>'
            f'<td class="wrap">{_esc(c.get("summary", ""))}</td>'
            "</tr>"
        )
    total = int(block.get("total", len(cves)))
    extra = ""
    if total > len(shown) or block.get("truncated"):
        extra = f"<p>Showing the top {len(shown)} of {total}+ by score.</p>"
    cached = " (from cache)" if block.get("cached") else ""
    return (heading + f"<p>{total} CVE(s){cached}.</p>"
            "<table><thead><tr><th>CVE</th><th>Score</th><th>Severity</th>"
            "<th>Summary</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>" + extra)


def html_report(report: dict, title: Optional[str] = None) -> str:
    title = title or "vuln-scanner report"
    s = report["summary"]
    cards = "".join(
        f'<div class="card"><b>{int(n)}</b>{label}</div>'
        for label, n in (("open", s["open"]), ("closed", s["closed"]),
                         ("filtered", s["filtered"])))

    if report["open_ports"]:
        rows = []
        for p in report["open_ports"]:
            version = f"{p['product']} {p['version']}".strip()
            rows.append(
                "<tr>"
                f"<td>{int(p['port'])}</td>"
                f"<td>{_esc(p['service'], 64)}</td>"
                f"<td>{_esc(version, 130)}</td>"
                f"<td>{_esc(p['confidence'], 20)}</td>"
                f'<td class="wrap"><code>{_esc(p["banner"], 200)}</code></td>'
                "</tr>"
            )
        ports = ("<table><thead><tr><th>Port</th><th>Service</th><th>Version</th>"
                 "<th>Identified by</th><th>Banner</th></tr></thead><tbody>"
                 + "".join(rows) + "</tbody></table>")
    else:
        ports = "<p>No open ports found.</p>"

    cve_html = ""
    if report.get("cve_lookup"):
        sections = "".join(_cve_section(p) for p in report["open_ports"])
        cve_html = (f"<h2>Known vulnerabilities</h2>"
                    f'<p class="note">{html.escape(CAVEAT)}</p>{sections}')

    meta = (f"Target {_esc(report['target'], 255)} ({_esc(report['address'], 64)}) &middot; "
            f"{int(report['ports_scanned'])} port(s) scanned in "
            f"{float(report['duration_seconds']):.1f}s &middot; started "
            f"{_esc(report['started'], 40)} UTC &middot; "
            f"{_esc(report['tool'], 40)} {_esc(report['tool_version'], 20)}")
    footer = f"<footer>{html.escape(NVD_NOTICE)}</footer>" if report.get("cve_lookup") else ""

    return (
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body>"
        f"<h1>{html.escape(title)}</h1><p class=\"meta\">{meta}</p>"
        f'<div class="cards">{cards}</div>'
        f"<h2>Open ports</h2>{ports}{cve_html}{footer}</body></html>\n"
    )


def write_html(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_report(report))
