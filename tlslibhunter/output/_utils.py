"""Shared utilities for output formatters."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tlslibhunter.scanner.results import ScanResult


def attached_label(result: ScanResult, *, quote_name: bool = False) -> str | None:
    """Identify the process actually instrumented, or None if unknown.

    Shared by every formatter so the identity is worded one way: name-based
    targeting can land on a process the caller never named, and two formatters
    deriving that string separately drifted apart once already.

    Args:
        result: The scan result to describe.
        quote_name: Wrap the process name in single quotes (table headings do).

    Returns:
        e.g. "'Finder' (PID 673)", or "PID 673" when the name is unresolved,
        or None when the backend could not identify the process at all.
    """
    if result.attached_process is None and result.attached_pid is None:
        return None
    if result.attached_process is None:
        # Name unresolved -- the PID is still the honest identifier.
        return f"PID {result.attached_pid}"
    name = f"'{result.attached_process}'" if quote_name else result.attached_process
    if result.attached_pid is None:
        return name
    return f"{name} (PID {result.attached_pid})"


def human_size(n: int) -> str:
    """Format a byte count as a human-readable size string.

    Args:
        n: Size in bytes.

    Returns:
        Formatted string like "1.5 MiB".
    """
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024.0 or unit == "GiB":
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} B"
