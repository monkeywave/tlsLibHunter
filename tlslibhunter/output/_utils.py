"""Shared utilities for output formatters."""


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
