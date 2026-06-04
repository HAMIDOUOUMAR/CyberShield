"""Quarantine management utilities for CyberShield.

This module moves malicious files into a dedicated quarantine directory and
keeps a JSON audit log of each quarantined file.
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any


class QuarantineManager:
    """Manage quarantined files and their metadata log."""

    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    QUARANTINE_ROOT = PROJECT_ROOT / "quarantine"
    QUARANTINE_FOLDER = QUARANTINE_ROOT / "quarantine_folder"
    QUARANTINE_LOG = QUARANTINE_ROOT / "quarantine_log.json"

    def __init__(self) -> None:
        """Initialize the manager and ensure the quarantine folder exists."""
        self.create_quarantine_folder()

    def create_quarantine_folder(self) -> None:
        """Create the quarantine storage folder if it does not already exist."""
        self.QUARANTINE_FOLDER.mkdir(parents=True, exist_ok=True)

    def quarantine_file(self, file_path: str | Path, file_hash: str) -> dict[str, str]:
        """Move a detected malicious file into quarantine.

        Args:
            file_path: Original path of the malicious file.
            file_hash: SHA-256 hash of the malicious file.

        Returns:
            The quarantine log entry created for the moved file.

        Raises:
            FileNotFoundError: If the file to quarantine does not exist.
            OSError: If the file cannot be moved.
        """
        self.create_quarantine_folder()

        source_path = Path(file_path)
        if not source_path.is_file():
            raise FileNotFoundError(f"Le fichier '{file_path}' est introuvable.")

        quarantine_path = self._build_quarantine_path(source_path)

        # Move the malicious file out of its original location.
        shutil.move(str(source_path), str(quarantine_path))

        log_entry = {
            "original_path": str(source_path),
            "quarantine_path": str(quarantine_path),
            "hash": file_hash,
            "date": datetime.now().isoformat(timespec="seconds"),
        }
        self.save_quarantine_log(log_entry)
        return log_entry

    def save_quarantine_log(self, log_entry: dict[str, str] | None = None) -> None:
        """Save quarantine metadata to ``quarantine/quarantine_log.json``.

        Args:
            log_entry: Optional entry to append to the quarantine log. When no
                entry is provided, the method ensures an empty log file exists.
        """
        self.QUARANTINE_ROOT.mkdir(parents=True, exist_ok=True)

        log_entries = self._load_existing_log()
        if log_entry is not None:
            log_entries.append(log_entry)

        with self.QUARANTINE_LOG.open("w", encoding="utf-8") as log_file:
            json.dump(log_entries, log_file, indent=2, ensure_ascii=False)

    def _build_quarantine_path(self, source_path: Path) -> Path:
        """Return a unique destination path inside the quarantine folder."""
        destination = self.QUARANTINE_FOLDER / source_path.name
        if not destination.exists():
            return destination

        # Avoid overwriting previously quarantined files with the same name.
        counter = 1
        while True:
            candidate = (
                self.QUARANTINE_FOLDER
                / f"{source_path.stem}_{counter}{source_path.suffix}"
            )
            if not candidate.exists():
                return candidate
            counter += 1

    def _load_existing_log(self) -> list[dict[str, Any]]:
        """Load existing quarantine log entries from disk."""
        if not self.QUARANTINE_LOG.is_file():
            return []

        with self.QUARANTINE_LOG.open("r", encoding="utf-8") as log_file:
            data = json.load(log_file)

        if isinstance(data, list):
            return data

        # If the log was manually edited into one object, preserve it as history.
        if isinstance(data, dict):
            return [data]

        return []
