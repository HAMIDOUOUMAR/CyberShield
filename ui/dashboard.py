"""Dashboard widgets for CyberShield EDR.

The dashboard reads existing JSON reports and displays high-level security
metrics for the user interface.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PyQt6.QtWidgets import (
    QGridLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCAN_REPORT_PATH = PROJECT_ROOT / "reports" / "report.json"
QUARANTINE_LOG_PATH = PROJECT_ROOT / "quarantine" / "quarantine_log.json"


def load_dashboard_metrics() -> dict[str, int]:
    """Load dashboard counters from existing JSON reports.

    Returns:
        A dictionary containing file scan, threat, and quarantine counters.
    """
    scan_report = _read_json_file(SCAN_REPORT_PATH, default={})
    quarantine_log = _read_json_file(QUARANTINE_LOG_PATH, default=[])

    return {
        "files_scanned": int(scan_report.get("files_scanned", 0)),
        "malware_found": int(scan_report.get("malware_found", 0)),
        "quarantined_files": len(quarantine_log) if isinstance(quarantine_log, list) else 0,
    }


class DashboardWidget(QWidget):
    """Display CyberShield counters loaded from report files."""

    def __init__(self) -> None:
        """Initialize the dashboard and load the current metrics."""
        super().__init__()
        self.files_scanned_value = QLabel("0")
        self.malware_found_value = QLabel("0")
        self.quarantine_value = QLabel("0")

        self._setup_ui()
        self.refresh()

    def refresh(self) -> None:
        """Reload dashboard values from JSON report files."""
        metrics = load_dashboard_metrics()
        self.files_scanned_value.setText(str(metrics["files_scanned"]))
        self.malware_found_value.setText(str(metrics["malware_found"]))
        self.quarantine_value.setText(str(metrics["quarantined_files"]))

    def _setup_ui(self) -> None:
        """Create the dashboard layout and metric cards."""
        layout = QGridLayout(self)
        layout.setSpacing(12)

        layout.addWidget(
            self._create_metric_card("Fichiers scannes", self.files_scanned_value),
            0,
            0,
        )
        layout.addWidget(
            self._create_metric_card("Menaces detectees", self.malware_found_value),
            0,
            1,
        )
        layout.addWidget(
            self._create_metric_card("Fichiers en quarantaine", self.quarantine_value),
            0,
            2,
        )

    def _create_metric_card(self, title: str, value_label: QLabel) -> QWidget:
        """Create a compact metric card for the dashboard."""
        card = QWidget()
        card.setObjectName("metricCard")
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        title_label = QLabel(title)
        title_label.setObjectName("metricTitle")
        value_label.setObjectName("metricValue")

        card_layout = QVBoxLayout(card)
        card_layout.addWidget(title_label)
        card_layout.addWidget(value_label)

        # Local styling keeps the widget usable even before a global theme exists.
        card.setStyleSheet(
            """
            QWidget#metricCard {
                background-color: #ffffff;
                border: 1px solid #c9d1d9;
                border-radius: 6px;
                padding: 10px;
            }
            QLabel#metricTitle {
                color: #475569;
                font-size: 12px;
                font-weight: 600;
            }
            QLabel#metricValue {
                color: #111827;
                font-size: 28px;
                font-weight: 700;
            }
            """
        )
        return card


def _read_json_file(path: Path, default: Any) -> Any:
    """Read a JSON file and return a default value when it is unavailable."""
    try:
        if not path.is_file():
            return default

        with path.open("r", encoding="utf-8") as json_file:
            return json.load(json_file)
    except (OSError, json.JSONDecodeError):
        # A broken or missing report should not prevent the UI from opening.
        return default
