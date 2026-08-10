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


def is_exact_name(candidate: str, target: str) -> bool:
    """True when *candidate* is the requested name, ignoring case."""
    return candidate.lower() == target.lower()


def name_matches(candidate: str, target: str) -> bool:
    """True when either name contains the other, ignoring case.

    Deliberately loose so partial targets ("chrome") resolve. Callers must treat
    a match as *weaker* than an exact one: this is what let "finder" match
    "QLMarkdown Preview Extension (Finder)". The single definition lives here so
    the resolver and the Frida attach path cannot drift apart.
    """
    candidate_lower, target_lower = candidate.lower(), target.lower()
    return target_lower in candidate_lower or candidate_lower in target_lower


def find_process(
    backend: Any,
    device: Any,
    target: int | str,
) -> dict[str, Any] | None:
    """Find a process on the device by PID or name.

    Exact names win over substring matches. Note this returns the *first*
    plausible process; the Frida attach path applies a stricter policy on top
    (it refuses to substitute a process when the exactly-named one exists but
    cannot be instrumented, and refuses ambiguous names outright).

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

    # Exact match first
    for p in procs:
        if is_exact_name(p["name"], target):
            return p

    # Substring match
    for p in procs:
        if name_matches(p["name"], target):
            return p

    return None
