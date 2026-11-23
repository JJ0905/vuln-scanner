"""Build and write scan reports.

The report is a plain dictionary so it can go straight to JSON, and so later
steps (CVE lookup, HTML) can read the same structure.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable, List

from scanner.portscan import PortResult
from scanner.services import identify

TOOL_VERSION = "0.2.0"


def build_report(target: str, address: str, ports_scanned: int,
                 results: Iterable[PortResult], started: datetime,
                 duration_seconds: float) -> dict:
    results = list(results)
    open_ports: List[dict] = []
    for result in results:
        if result.state != "open":
            continue
        service = identify(result.port, result.banner)
        open_ports.append({
            "port": result.port,
            "service": service.name,
            "product": service.product,
            "version": service.version,
            "confidence": service.confidence,
            "banner": result.banner,
        })

    return {
        "tool": "vuln-scanner",
        "tool_version": TOOL_VERSION,
        "target": target,
        "address": address,
        "started": started.isoformat(timespec="seconds"),
        "duration_seconds": round(duration_seconds, 2),
        "ports_scanned": ports_scanned,
        "summary": {
            "open": len(open_ports),
            "closed": sum(1 for r in results if r.state == "closed"),
            "filtered": sum(1 for r in results if r.state == "filtered"),
        },
        "open_ports": open_ports,
    }


def write_json(report: dict, path: str) -> None:
    Path(path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
