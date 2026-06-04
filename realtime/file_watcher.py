"""Realtime file watcher for CyberShield.

The watcher observes a directory and sends newly created files to the existing
file scanning engine.
"""
from __future__ import annotations

import time
from pathlib import Path

from watchdog.events import FileCreatedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from scanner.file_scanner import scan_directory


class FileCreatedHandler(FileSystemEventHandler):
    """Handle newly created files and scan them with CyberShield."""

    def on_created(self, event: FileCreatedEvent) -> None:
        """Scan a file as soon as it is created in the watched directory."""
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        print(f"[NEW FILE DETECTED] {file_path}")

        try:
            # Give the operating system a short moment to finish writing the file.
            time.sleep(0.5)
            scan_directory(file_path)
        except Exception as error:
            print(f"[WATCHER ERROR] Impossible de scanner {file_path}: {error}")


class FileWatcher:
    """Observe a directory and scan new files in realtime."""

    def __init__(self, directory_path: str | Path) -> None:
        """Initialize the watcher for a target directory.

        Args:
            directory_path: Directory to observe for newly created files.
        """
        self.directory_path = Path(directory_path)
        self.observer = Observer()

    def start(self) -> None:
        """Start watching the directory until the user stops the program.

        Raises:
            FileNotFoundError: If the watched directory does not exist.
            NotADirectoryError: If the watched path is not a directory.
        """
        if not self.directory_path.exists():
            raise FileNotFoundError(f"Le dossier '{self.directory_path}' est introuvable.")

        if not self.directory_path.is_dir():
            raise NotADirectoryError(f"'{self.directory_path}' n'est pas un dossier.")

        event_handler = FileCreatedHandler()
        self.observer.schedule(event_handler, str(self.directory_path), recursive=False)
        self.observer.start()

        print(f"[WATCHING] {self.directory_path}")
        print("Appuyez sur Ctrl+C pour arreter la surveillance.")

        try:
            while self.observer.is_alive():
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[STOPPED] Surveillance arretee.")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the observer and release watcher resources."""
        if self.observer.is_alive():
            self.observer.stop()
        self.observer.join()


def watch_directory(directory_path: str | Path) -> None:
    """Convenience function to start realtime monitoring for a directory."""
    watcher = FileWatcher(directory_path)
    watcher.start()
