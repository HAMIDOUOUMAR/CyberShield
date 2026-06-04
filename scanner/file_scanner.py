"""file_scanner.py

Directory scanning utilities for CyberShield.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

from quarantine.quarantine_manager import QuarantineManager
from scanner.hash_engine import calculate_sha256
from scanner.signature_engine import SignatureEngine


def iter_files(path: Path | str) -> Iterator[Path]:
    """Yield Path objects for all files under ``path`` recursively.

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


def scan_directory(path: Path | str) -> list[dict[str, Any]]:
    """Scan files and return structured scan results.

    For every file found, this function calculates its SHA-256 hash, checks it
    against the signature database, quarantines malicious files, prints readable
    scan logs, and stores structured results for report generation.

    Args:
        path: Directory or file path to scan.

    Returns:
        A list of dictionaries containing ``file``, ``hash`` and ``status``.

    Raises:
        FileNotFoundError: If the scanned path or signature database does not exist.
    """
    signature_engine = SignatureEngine()
    quarantine_manager = QuarantineManager()
    results: list[dict[str, Any]] = []

    for file_path in iter_files(path):
        try:
            file_hash = calculate_sha256(file_path)
            is_malware = signature_engine.is_malicious(file_hash)

            if is_malware:
                result = _handle_malware_file(file_path, file_hash, quarantine_manager)
            else:
                print(f"[SAFE] {file_path}")
                result = {
                    "file": str(file_path),
                    "hash": file_hash,
                    "status": "SAFE",
                    "quarantined": False,
                }
        except Exception as error:
            # A single unreadable file must not interrupt the full directory scan.
            print(f"[ERROR] {file_path}: {error}")
            result = {
                "file": str(file_path),
                "hash": "",
                "status": "ERROR",
                "quarantined": False,
                "error": str(error),
            }

        results.append(result)

    return results


def _handle_malware_file(
    file_path: Path,
    file_hash: str,
    quarantine_manager: QuarantineManager,
) -> dict[str, Any]:
    """Quarantine a malicious file and return its structured scan result."""
    print(f"[MALWARE DETECTED] {file_path}")

    result: dict[str, Any] = {
        "file": str(file_path),
        "hash": file_hash,
        "status": "MALWARE",
        "quarantined": False,
    }

    try:
        quarantine_manager.quarantine_file(file_path, file_hash)
        result["quarantined"] = True
        print(f"[QUARANTINED] {file_path}")
    except Exception as error:
        # Keep scanning even if the file cannot be moved into quarantine.
        result["error"] = str(error)
        print(f"[QUARANTINE FAILED] {file_path}: {error}")

    return result
