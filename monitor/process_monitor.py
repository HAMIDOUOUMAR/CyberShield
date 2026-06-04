"""Process monitoring utilities for CyberShield.

This module exposes a small wrapper around ``psutil`` to collect basic runtime
information about active processes.
"""
from __future__ import annotations

from typing import Any

import psutil


class ProcessMonitor:
    """Collect information about active operating system processes."""

    def get_active_processes(self) -> list[dict[str, Any]]:
        """Return a list of active processes with CPU and memory usage.

        Returns:
            A list of dictionaries containing ``pid``, ``name``, ``cpu`` and
            ``memory`` keys.
        """
        processes: list[dict[str, Any]] = []

        for process in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
            try:
                info = process.info
                processes.append(
                    {
                        "pid": info.get("pid"),
                        "name": info.get("name") or "unknown",
                        "cpu": float(info.get("cpu_percent") or 0.0),
                        "memory": float(info.get("memory_percent") or 0.0),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Some processes can disappear or become protected while scanning.
                continue

        return processes
