"""Process name/PID resolution utilities."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("tlslibhunter.utils.process_resolver")


def resolve_target(target: str) -> int | str:
    """Parse target as PID (int) or process name (str).

    Args:
        target: User-provided target string

    Returns:
        int if target is a PID, str otherwise
    """
    try:
        return int(target)
    except ValueError:
        return target


def find_process(
    backend: Any,
    device: Any,
    target: int | str,
) -> dict[str, Any] | None:
    """Find a process on the device by PID or name.

    Args:
        backend: Backend instance
        device: Device handle
        target: PID (int) or process name (str)

    Returns:
        Dict with 'name' and 'pid', or None if not found
    """
    procs = backend.enumerate_processes(device)

    if isinstance(target, int):
        for p in procs:
            if p["pid"] == target:
                return p
        return None

    target_lower = target.lower()

    # Exact match first
    for p in procs:
        if p["name"].lower() == target_lower:
            return p

    # Substring match
    for p in procs:
        name_lower = p["name"].lower()
        if target_lower in name_lower or name_lower in target_lower:
            return p

    return None
