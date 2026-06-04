"""Realtime monitoring engine for CyberShield.

This module starts directory surveillance from a user-selected path and keeps
the watcher running until the user stops the program.
"""
from __future__ import annotations

import logging
from pathlib import Path

from realtime.file_watcher import watch_directory


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class RealtimeEngine:
    """Coordinate realtime folder monitoring for CyberShield."""

    def start(self, directory_path: str | Path | None = None) -> None:
        """Start realtime monitoring for a directory.

        Args:
            directory_path: Optional directory to watch. If omitted, the user is
                prompted to enter a path.
        """
        target_path = Path(directory_path) if directory_path else self._ask_directory_path()
        logger.info("Demarrage de la surveillance temps reel: %s", target_path)

        try:
            watch_directory(target_path)
        except (FileNotFoundError, NotADirectoryError) as error:
            logger.error("Surveillance impossible: %s", error)
            print(f"[REALTIME ERROR] {error}")
        except KeyboardInterrupt:
            logger.info("Surveillance arretee par l'utilisateur.")
            print("\n[STOPPED] Surveillance arretee.")
        except Exception as error:
            logger.exception("Erreur inattendue pendant la surveillance temps reel.")
            print(f"[REALTIME ERROR] {error}")
        finally:
            logger.info("Fin du moteur de surveillance temps reel.")

    def _ask_directory_path(self) -> Path:
        """Ask the user which directory should be monitored."""
        directory_path = input("Entrez le dossier a surveiller : ").strip()
        return Path(directory_path)


def start_realtime_monitoring(directory_path: str | Path | None = None) -> None:
    """Start the realtime monitoring engine."""
    engine = RealtimeEngine()
    engine.start(directory_path)
