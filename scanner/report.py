"""Build and write scan reports.

The report is a plain dictionary so it can go straight to JSON, and so later
steps (HTML) can read the same structure.
"""
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from scanner.cve import LookupResult
from scanner.portscan import PortResult
from scanner.services import identify

TOOL_VERSION = "0.3.0"


def _vulnerability_block(lookup: LookupResult) -> dict:
    # Highest score first; entries without a score go last.
    cves = sorted(lookup.cves, key=lambda v: (v.score is None, -(v.score or 0.0), v.cve_id))
    return {
        "status": lookup.status,
        "cpe": lookup.cpe,
        "total": lookup.total,
        "truncated": lookup.truncated,
        "cached": lookup.cached,
        "error": lookup.error,
        "cves": [asdict(v) for v in cves],
    }


def build_report(target: str, address: str, ports_scanned: int,
                 results: Iterable[PortResult], started: datetime,
                 duration_seconds: float,
                 vulnerabilities: Optional[Dict[int, LookupResult]] = None) -> dict:
    results = list(results)
    open_ports: List[dict] = []
    for result in results:
        if result.state != "open":
            continue
        service = identify(result.port, result.banner)
        entry = {
            "port": result.port,
            "service": service.name,
            "product": service.product,
            "version": service.version,
            "confidence": service.confidence,
            "banner": result.banner,
        }
        if vulnerabilities is not None and result.port in vulnerabilities:
            entry["vulnerabilities"] = _vulnerability_block(vulnerabilities[result.port])
        open_ports.append(entry)

    return {
        "tool": "vuln-scanner",
        "tool_version": TOOL_VERSION,
        "target": target,
        "address": address,
        "started": started.isoformat(timespec="seconds"),
        "duration_seconds": round(duration_seconds, 2),
        "ports_scanned": ports_scanned,
        "cve_lookup": vulnerabilities is not None,
        "summary": {
            "open": len(open_ports),
            "closed": sum(1 for r in results if r.state == "closed"),
            "filtered": sum(1 for r in results if r.state == "filtered"),
        },
        "open_ports": open_ports,
    }


def write_json(report: dict, path: str) -> None:
    Path(path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
