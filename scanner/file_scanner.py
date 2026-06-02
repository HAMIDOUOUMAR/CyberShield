"""file_scanner.py

Directory scanning utilities for CyberShield.
"""
from pathlib import Path
from typing import Iterator


def scan_directory(path: Path | str) -> Iterator[Path]:
    """Yield Path objects for all files under `path` recursively.

    If `path` is a file, yields that file. If `path` does not exist, raises FileNotFoundError.

    Args:
        path: Directory or file path to scan.

    Yields:
        Path objects for each file found.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Le chemin '{path}' n'existe pas.")

    if root.is_file():
        yield root
        return

    for p in root.rglob("*"):
        if p.is_file():
            yield p
