"""Report generation utilities for CyberShield."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


REPORT_PATH = Path(__file__).resolve().parent / "reports" / "report.json"


def save_report(results: list[dict[str, Any]]) -> None:
    """Build and save a JSON report from scan results.

    Args:
        results: List of scanned file results. Each item must contain
            ``file``, ``hash`` and ``status`` keys. Results with
            ``status == "MALWARE"`` are included in the detections list.
    """
    # Only malicious files are listed in the detailed detections section.
    detections = [
        {
            "file": str(result["file"]),
            "hash": str(result["hash"]),
        }
        for result in results
        if result.get("status") == "MALWARE"
    ]

    # The report keeps high-level counters plus details for confirmed matches.
    report = {
        "scan_date": datetime.now().isoformat(timespec="seconds"),
        "files_scanned": len(results),
        "malware_found": len(detections),
        "detections": detections,
    }

    # Ensure the reports directory exists before writing the JSON file.
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with REPORT_PATH.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2, ensure_ascii=False)
