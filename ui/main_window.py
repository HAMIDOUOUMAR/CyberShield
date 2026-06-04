"""Main PyQt6 window for CyberShield EDR.

The interface presents CyberShield as a desktop EDR console with dashboard
metrics, quick actions, realtime protection controls, logs, and process data.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QStatusBar,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from watchdog.events import FileCreatedEvent, FileSystemEventHandler
from watchdog.observers import Observer


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from monitor.process_monitor import ProcessMonitor
from monitor.process_report import save_process_report
from report_engine import save_report
from scanner.file_scanner import scan_directory
from ui.dashboard import load_dashboard_metrics


QUARANTINE_LOG_PATH = PROJECT_ROOT / "quarantine" / "quarantine_log.json"


def format_scan_result(result: dict[str, object]) -> str:
    """Return a readable log line for one file scan result."""
    status = result.get("status")
    file_path = result.get("file")

    if status == "MALWARE":
        quarantine_status = "quarantined" if result.get("quarantined") else "not quarantined"
        error = result.get("error")
        if error:
            return f"[MALWARE DETECTED] {file_path} ({quarantine_status}) - {error}"
        return f"[MALWARE DETECTED] {file_path} ({quarantine_status})"

    if status == "ERROR":
        return f"[ERROR] {file_path} - {result.get('error')}"

    return f"[SAFE] {file_path}"


class RealtimeEventHandler(FileSystemEventHandler):
    """Forward newly created files to the realtime Qt worker."""

    def __init__(self, worker: "RealtimeWorker") -> None:
        """Store the worker used to scan files and emit UI logs."""
        super().__init__()
        self.worker = worker

    def on_created(self, event: FileCreatedEvent) -> None:
        """Scan new files detected by watchdog."""
        if event.is_directory:
            return

        self.worker.scan_new_file(Path(event.src_path))


class RealtimeWorker(QThread):
    """Run watchdog monitoring outside the GUI thread."""

    log_message = pyqtSignal(str)
    scan_result = pyqtSignal(dict)
    stopped = pyqtSignal()

    def __init__(self, directory_path: str | Path) -> None:
        """Initialize the realtime worker for a directory."""
        super().__init__()
        self.directory_path = Path(directory_path)
        self.observer: Observer | None = None
        self._running = False

    def run(self) -> None:
        """Start the watchdog observer and keep it alive until stopped."""
        try:
            if not self.directory_path.is_dir():
                self.log_message.emit(f"[REALTIME ERROR] Invalid folder: {self.directory_path}")
                return

            self._running = True
            self.observer = Observer()
            self.observer.schedule(
                RealtimeEventHandler(self),
                str(self.directory_path),
                recursive=False,
            )
            self.observer.start()
            self.log_message.emit(f"[REALTIME STARTED] {self.directory_path}")

            while self._running:
                time.sleep(0.5)
        except Exception as error:
            self.log_message.emit(f"[REALTIME ERROR] {error}")
        finally:
            self._stop_observer()
            self.log_message.emit("[REALTIME STOPPED]")
            self.stopped.emit()

    def stop(self) -> None:
        """Request the realtime worker to stop."""
        self._running = False

    def scan_new_file(self, file_path: Path) -> None:
        """Scan a newly created file and emit log lines for the UI."""
        self.log_message.emit(f"[NEW FILE DETECTED] {file_path}")

        try:
            # Wait briefly so the file writer can close the handle.
            time.sleep(0.5)
            results = scan_directory(file_path)
            for result in results:
                self.log_message.emit(format_scan_result(result))
                self.scan_result.emit(result)
        except Exception as error:
            self.log_message.emit(f"[WATCHER ERROR] {file_path}: {error}")

    def _stop_observer(self) -> None:
        """Stop watchdog safely when realtime monitoring ends."""
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()


class MainWindow(QMainWindow):
    """Main application window for CyberShield EDR."""

    def __init__(self) -> None:
        """Initialize the window and build the interface."""
        super().__init__()
        self.setWindowTitle("CyberShield EDR")
        self.resize(1320, 820)
        self.setMinimumSize(1100, 700)

        self.realtime_worker: RealtimeWorker | None = None

        self.files_scanned_value = QLabel("0")
        self.threats_value = QLabel("0")
        self.quarantine_value = QLabel("0")
        self.realtime_state = QLabel("Inactive")
        self.selected_folder = QLabel("No protected folder")

        self.scan_button = QPushButton("Scan Folder")
        self.process_button = QPushButton("Process Monitor")
        self.realtime_button = QPushButton("Start Protection")
        self.refresh_button = QPushButton("Refresh Dashboard")

        self.log_output = QTextEdit()
        self.process_table = QTableWidget(0, 4)
        self.quarantine_table = QTableWidget(0, 4)
        self.content_stack = QStackedWidget()
        self.nav_buttons: list[QPushButton] = []

        self._setup_ui()
        self._connect_signals()
        self.refresh_dashboard()
        self.load_quarantine_table()

    def _setup_ui(self) -> None:
        """Create the visual structure of the CyberShield dashboard."""
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._create_sidebar())
        root_layout.addWidget(self._create_main_panel(), stretch=1)

        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("CyberShield EDR ready")
        self._apply_styles()

    def _create_sidebar(self) -> QWidget:
        """Create the left navigation and product identity panel."""
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(240)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(22, 24, 22, 24)
        layout.setSpacing(14)

        brand = QLabel("CyberShield")
        brand.setObjectName("brand")
        subtitle = QLabel("Endpoint Detection\nand Response")
        subtitle.setObjectName("subtitle")

        layout.addWidget(brand)
        layout.addWidget(subtitle)
        layout.addSpacing(22)
        layout.addWidget(self._sidebar_label("Overview"))
        layout.addWidget(self._sidebar_label("File Scanner"))
        layout.addWidget(self._sidebar_label("Process Monitor"))
        layout.addWidget(self._sidebar_label("Realtime Guard"))
        layout.addWidget(self._sidebar_label("Quarantine"))
        layout.addStretch()

        build = QLabel("Local EDR Console")
        build.setObjectName("sidebarFooter")
        layout.addWidget(build)
        return sidebar

    def _create_main_panel(self) -> QWidget:
        """Create dashboard, actions, logs, and data tables."""
        panel = QWidget()
        panel.setObjectName("mainPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(26, 22, 26, 18)
        layout.setSpacing(16)

        layout.addWidget(self._create_header())
        layout.addLayout(self._create_metrics_grid())
        layout.addWidget(self._create_actions_panel())

        content_layout = QGridLayout()
        content_layout.setSpacing(14)
        content_layout.addWidget(self._create_logs_panel(), 0, 0, 2, 1)
        content_layout.addWidget(self._create_process_panel(), 0, 1)
        content_layout.addWidget(self._create_quarantine_panel(), 1, 1)
        content_layout.setColumnStretch(0, 3)
        content_layout.setColumnStretch(1, 2)

        layout.addLayout(content_layout, stretch=1)
        return panel

    def _create_header(self) -> QWidget:
        """Create the top header with current realtime status."""
        header = QFrame()
        header.setObjectName("hero")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(18, 16, 18, 16)

        title_group = QVBoxLayout()
        title = QLabel("CyberShield EDR")
        title.setObjectName("heroTitle")
        description = QLabel("Security operations dashboard for scans, processes, quarantine, and realtime protection.")
        description.setObjectName("heroDescription")
        title_group.addWidget(title)
        title_group.addWidget(description)

        status_group = QVBoxLayout()
        status_label = QLabel("Realtime Protection")
        status_label.setObjectName("smallLabel")
        self.realtime_state.setObjectName("realtimeState")
        self.selected_folder.setObjectName("selectedFolder")
        status_group.addWidget(status_label)
        status_group.addWidget(self.realtime_state)
        status_group.addWidget(self.selected_folder)

        layout.addLayout(title_group, stretch=1)
        layout.addLayout(status_group)
        return header

    def _create_metrics_grid(self) -> QGridLayout:
        """Create the three main dashboard metrics."""
        grid = QGridLayout()
        grid.setSpacing(14)
        grid.addWidget(self._metric_card("Files scanned", self.files_scanned_value, "Last file scan report"), 0, 0)
        grid.addWidget(self._metric_card("Threats detected", self.threats_value, "Known malicious hashes"), 0, 1)
        grid.addWidget(self._metric_card("Quarantined", self.quarantine_value, "Files moved to isolation"), 0, 2)
        return grid

    def _create_actions_panel(self) -> QWidget:
        """Create the quick action area."""
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        self.scan_button.setObjectName("primaryButton")
        self.process_button.setObjectName("secondaryButton")
        self.realtime_button.setObjectName("dangerButton")
        self.refresh_button.setObjectName("secondaryButton")

        layout.addWidget(self.scan_button)
        layout.addWidget(self.process_button)
        layout.addWidget(self.realtime_button)
        layout.addStretch()
        layout.addWidget(self.refresh_button)
        return panel

    def _create_logs_panel(self) -> QWidget:
        """Create the log panel used by all features."""
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)

        title = QLabel("Activity Logs")
        title.setObjectName("sectionTitle")
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Scan, process, quarantine, and realtime events appear here.")
        layout.addWidget(title)
        layout.addWidget(self.log_output)
        return panel

    def _create_process_panel(self) -> QWidget:
        """Create the process monitor table."""
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)

        title = QLabel("Processes")
        title.setObjectName("sectionTitle")
        self.process_table.setHorizontalHeaderLabels(["PID", "Name", "CPU", "Memory"])
        self._prepare_table(self.process_table)
        layout.addWidget(title)
        layout.addWidget(self.process_table)
        return panel

    def _create_quarantine_panel(self) -> QWidget:
        """Create the quarantine history table."""
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)

        title = QLabel("Quarantine")
        title.setObjectName("sectionTitle")
        self.quarantine_table.setHorizontalHeaderLabels(["Original", "Quarantine", "Hash", "Date"])
        self._prepare_table(self.quarantine_table)
        layout.addWidget(title)
        layout.addWidget(self.quarantine_table)
        return panel

    def _metric_card(self, title: str, value_label: QLabel, caption: str) -> QWidget:
        """Create a polished dashboard metric card."""
        card = QFrame()
        card.setObjectName("metricCard")
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)

        label = QLabel(title)
        label.setObjectName("metricTitle")
        value_label.setObjectName("metricValue")
        hint = QLabel(caption)
        hint.setObjectName("metricHint")

        layout.addWidget(label)
        layout.addWidget(value_label)
        layout.addWidget(hint)
        return card

    def _sidebar_label(self, text: str) -> QLabel:
        """Create a sidebar item label."""
        label = QLabel(text)
        label.setObjectName("sidebarItem")
        return label

    def _prepare_table(self, table: QTableWidget) -> None:
        """Apply common table behavior and sizing."""
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setAlternatingRowColors(True)

    def _connect_signals(self) -> None:
        """Connect UI buttons to CyberShield features."""
        self.scan_button.clicked.connect(self.scan_folder)
        self.process_button.clicked.connect(self.monitor_processes)
        self.realtime_button.clicked.connect(self.toggle_realtime_protection)
        self.refresh_button.clicked.connect(self.refresh_dashboard)

    def scan_folder(self) -> None:
        """Open a folder selector, scan the chosen folder, and display results."""
        folder_path = QFileDialog.getExistingDirectory(self, "Select folder to scan")
        if not folder_path:
            return

        self.add_log(f"[SCAN STARTED] {folder_path}")

        try:
            results = scan_directory(folder_path)
            save_report(results)

            for result in results:
                self.add_log(format_scan_result(result))

            self.add_log("[REPORT SAVED] reports/report.json")
            self.refresh_dashboard()
            self.load_quarantine_table()
        except Exception as error:
            self.add_log(f"[SCAN ERROR] {error}")
            QMessageBox.critical(self, "Scan error", str(error))

    def monitor_processes(self) -> None:
        """Collect active processes, display them, and save a process report."""
        self.add_log("[PROCESS MONITOR STARTED]")

        try:
            processes = ProcessMonitor().get_active_processes()
            self.process_table.setRowCount(0)

            for process in processes:
                self._add_process_row(process)

            save_process_report(processes)
            self.add_log(f"[PROCESS REPORT SAVED] {len(processes)} processes written to reports/process_report.json")
        except Exception as error:
            self.add_log(f"[PROCESS MONITOR ERROR] {error}")
            QMessageBox.critical(self, "Process monitor error", str(error))

    def toggle_realtime_protection(self) -> None:
        """Start or stop realtime protection based on current worker state."""
        if self.realtime_worker and self.realtime_worker.isRunning():
            self.add_log("[REALTIME STOP REQUESTED]")
            self.realtime_worker.stop()
            self.realtime_button.setEnabled(False)
            return

        folder_path = QFileDialog.getExistingDirectory(self, "Select folder to protect")
        if not folder_path:
            return

        self.realtime_worker = RealtimeWorker(folder_path)
        self.realtime_worker.log_message.connect(self.add_log)
        self.realtime_worker.scan_result.connect(self._handle_realtime_scan_result)
        self.realtime_worker.stopped.connect(self._on_realtime_stopped)
        self.realtime_worker.start()

        self.realtime_button.setText("Stop Protection")
        self.realtime_state.setText("Active")
        self.selected_folder.setText(folder_path)
        self.statusBar().showMessage("Real-time protection running")

    def refresh_dashboard(self) -> None:
        """Refresh dashboard metric values from existing reports."""
        metrics = load_dashboard_metrics()
        self.files_scanned_value.setText(str(metrics["files_scanned"]))
        self.threats_value.setText(str(metrics["malware_found"]))
        self.quarantine_value.setText(str(metrics["quarantined_files"]))
        self.statusBar().showMessage("Dashboard refreshed")

    def load_quarantine_table(self) -> None:
        """Load quarantine history into the table."""
        self.quarantine_table.setRowCount(0)

        try:
            if not QUARANTINE_LOG_PATH.is_file():
                return

            with QUARANTINE_LOG_PATH.open("r", encoding="utf-8") as log_file:
                entries = json.load(log_file)

            if not isinstance(entries, list):
                return

            for entry in entries[-25:]:
                self._add_quarantine_row(entry)
        except (OSError, json.JSONDecodeError) as error:
            self.add_log(f"[QUARANTINE LOG ERROR] {error}")

    def _handle_realtime_scan_result(self, result: dict) -> None:
        """Refresh dashboard tables after a realtime file scan."""
        self.refresh_dashboard()
        if result.get("status") == "MALWARE":
            self.load_quarantine_table()

    def _on_realtime_stopped(self) -> None:
        """Reset realtime UI state after the worker stops."""
        self.realtime_button.setText("Start Protection")
        self.realtime_button.setEnabled(True)
        self.realtime_state.setText("Inactive")
        self.statusBar().showMessage("Ready")

    def _add_process_row(self, process: dict[str, object]) -> None:
        """Append one process to the process table."""
        row = self.process_table.rowCount()
        self.process_table.insertRow(row)
        values = [
            process.get("pid", ""),
            process.get("name", ""),
            f"{float(process.get('cpu') or 0.0):.1f}%",
            f"{float(process.get('memory') or 0.0):.2f}%",
        ]

        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter)
            self.process_table.setItem(row, column, item)

    def _add_quarantine_row(self, entry: dict[str, object]) -> None:
        """Append one quarantine entry to the quarantine table."""
        row = self.quarantine_table.rowCount()
        self.quarantine_table.insertRow(row)
        values = [
            entry.get("original_path", ""),
            entry.get("quarantine_path", ""),
            entry.get("hash", ""),
            entry.get("date", ""),
        ]

        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter)
            self.quarantine_table.setItem(row, column, item)

    def add_log(self, message: str) -> None:
        """Append a message to the log area and update the status bar."""
        self.log_output.append(message)
        self.statusBar().showMessage(message)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        """Stop realtime monitoring before closing the window."""
        if self.realtime_worker and self.realtime_worker.isRunning():
            self.realtime_worker.stop()
            self.realtime_worker.wait(3000)
        event.accept()

    def _apply_styles(self) -> None:
        """Apply the CyberShield visual theme."""
        self.setStyleSheet(
            """
            QMainWindow {
                background: #eef3f7;
            }
            QWidget#mainPanel {
                background: #eef3f7;
            }
            QFrame#sidebar {
                background: #07111f;
            }
            QLabel#brand {
                color: #ffffff;
                font-size: 28px;
                font-weight: 800;
            }
            QLabel#subtitle, QLabel#sidebarFooter {
                color: #94a3b8;
                font-size: 12px;
                line-height: 18px;
            }
            QLabel#sidebarItem {
                color: #dbeafe;
                background: rgba(255, 255, 255, 0.06);
                border-radius: 6px;
                padding: 10px 12px;
                font-weight: 600;
            }
            QFrame#hero {
                background: #ffffff;
                border: 1px solid #d8e1ea;
                border-radius: 8px;
            }
            QLabel#heroTitle {
                color: #0f172a;
                font-size: 30px;
                font-weight: 800;
            }
            QLabel#heroDescription, QLabel#metricHint, QLabel#smallLabel, QLabel#selectedFolder {
                color: #64748b;
                font-size: 12px;
            }
            QLabel#realtimeState {
                color: #0f766e;
                font-size: 22px;
                font-weight: 800;
            }
            QFrame#panel, QFrame#metricCard {
                background: #ffffff;
                border: 1px solid #d8e1ea;
                border-radius: 8px;
            }
            QLabel#metricTitle {
                color: #475569;
                font-size: 12px;
                font-weight: 700;
                text-transform: uppercase;
            }
            QLabel#metricValue {
                color: #0f172a;
                font-size: 34px;
                font-weight: 800;
            }
            QLabel#sectionTitle {
                color: #0f172a;
                font-size: 16px;
                font-weight: 800;
            }
            QPushButton {
                min-height: 38px;
                border-radius: 7px;
                padding: 6px 16px;
                font-weight: 700;
            }
            QPushButton#primaryButton {
                color: #ffffff;
                background: #0f766e;
                border: 1px solid #0f766e;
            }
            QPushButton#secondaryButton {
                color: #0f172a;
                background: #e8eef5;
                border: 1px solid #cad6e2;
            }
            QPushButton#dangerButton {
                color: #ffffff;
                background: #1d4ed8;
                border: 1px solid #1d4ed8;
            }
            QPushButton:disabled {
                color: #94a3b8;
                background: #e2e8f0;
                border: 1px solid #cbd5e1;
            }
            QTextEdit {
                background: #08111f;
                color: #d1fae5;
                border: 1px solid #1f2937;
                border-radius: 6px;
                font-family: Consolas, monospace;
                font-size: 12px;
                padding: 8px;
            }
            QTableWidget {
                background: #ffffff;
                alternate-background-color: #f8fafc;
                border: 1px solid #d8e1ea;
                border-radius: 6px;
                gridline-color: #e5edf4;
                font-size: 12px;
            }
            QHeaderView::section {
                background: #f1f5f9;
                color: #334155;
                border: 0;
                border-bottom: 1px solid #d8e1ea;
                padding: 7px;
                font-weight: 700;
            }
            QStatusBar {
                color: #334155;
                background: #e8eef5;
            }
            """
        )


def run_app() -> None:
    """Start the CyberShield EDR graphical application."""
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()


if __name__ == "__main__":
    run_app()
