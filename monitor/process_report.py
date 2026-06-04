"""Process report generation utilities for CyberShield."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


PROCESS_REPORT_PATH = (
    Path(__file__).resolve().parent.parent / "reports" / "process_report.json"
)


def save_process_report(processes: list[dict[str, Any]]) -> None:
    """Save active process information to ``reports/process_report.json``.

    Args:
        processes: List of process dictionaries, typically returned by
            ``ProcessMonitor.get_active_processes()``.
    """
    report = {
        "scan_date": datetime.now().isoformat(timespec="seconds"),
        "process_count": len(processes),
        "processes": processes,
    }

    # Ensure the reports directory exists before writing the JSON report.
    PROCESS_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with PROCESS_REPORT_PATH.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2, ensure_ascii=False)
