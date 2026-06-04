"""Signature engine for CyberShield.

This module loads known malware signatures from a JSON database and checks
whether a SHA-256 hash is listed as malicious.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any


class SignatureEngine:
    """Load malware signatures and check hashes against them.

    The default database path is ``CyberShield/database/malware_signatures.json``.
    The JSON file can contain either:

    - a list of hash strings;
    - a dictionary with a ``signatures``, ``hashes`` or ``malware_hashes`` list;
    - a dictionary where each key is directly a malware hash.
    """

    DEFAULT_DATABASE_PATH = (
        Path(__file__).resolve().parent.parent / "database" / "malware_signatures.json"
    )

    def __init__(self, database_path: Path | str | None = None) -> None:
        """Initialize the signature engine and load the signature database.

        Args:
            database_path: Optional custom path to the JSON signature database.
        """
        self.database_path = Path(database_path) if database_path else self.DEFAULT_DATABASE_PATH
        self.signatures: set[str] = set()
        self.load_signatures()

    def load_signatures(self) -> None:
        """Load malware hashes from the JSON database into memory.

        Raises:
            FileNotFoundError: If the signature database does not exist.
            ValueError: If the JSON structure is not supported.
            json.JSONDecodeError: If the JSON file is malformed.
        """
        if not self.database_path.is_file():
            raise FileNotFoundError(
                f"La base de signatures '{self.database_path}' est introuvable."
            )

        with self.database_path.open("r", encoding="utf-8") as database_file:
            data = json.load(database_file)

        self.signatures = self._extract_signatures(data)

    def is_malicious(self, file_hash: str) -> bool:
        """Return True if the given hash is present in the malware database.

        Args:
            file_hash: Hash string to check.

        Returns:
            True if the hash is known as malicious, False otherwise.
        """
        # Hashes are normalized to lowercase so comparisons stay consistent.
        normalized_hash = file_hash.strip().lower()
        return normalized_hash in self.signatures

    def _extract_signatures(self, data: Any) -> set[str]:
        """Extract a normalized set of hashes from supported JSON structures."""
        if isinstance(data, list):
            return self._normalize_hashes(data)

        if isinstance(data, dict):
            # Prefer explicit list fields when the database uses metadata.
            for key in ("signatures", "hashes", "malware_hashes"):
                if key in data:
                    return self._normalize_hashes(data[key])

            # If no known field exists, treat dictionary keys as signatures.
            return self._normalize_hashes(data.keys())

        raise ValueError("Format de base de signatures non supporte.")

    def _normalize_hashes(self, hashes: Any) -> set[str]:
        """Normalize raw hash values into a lowercase set."""
        if isinstance(hashes, str) or not isinstance(hashes, Iterable):
            raise ValueError("La liste de signatures doit contenir des hashes.")

        # Empty values are ignored to avoid false matches.
        return {str(signature).strip().lower() for signature in hashes if str(signature).strip()}
