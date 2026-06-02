"""hash_engine.py

Utilities for computing file hashes used by CyberShield.
"""
from pathlib import Path
import hashlib


def calculate_sha256(file_path: Path | str) -> str:
    """Calculate the SHA-256 digest of a file.

    Args:
        file_path: Path or string pointing to the file to hash.

    Returns:
        Hexadecimal SHA-256 digest string.

    Raises:
        FileNotFoundError: If the file does not exist.
        OSError: If an I/O error occurs while reading the file.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Le fichier '{file_path}' n'existe pas ou n'est pas un fichier.")

    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
