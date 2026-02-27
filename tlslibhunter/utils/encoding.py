"""Hex pattern encoding utilities for TLS string scanning."""

from __future__ import annotations


def ascii_to_hex(s: str) -> str:
    """Convert ASCII string to space-separated hex pattern.

    Example: "SSL" -> "53 53 4c"
    """
    return " ".join(f"{ord(c):02x}" for c in s)


def utf16le_to_hex(s: str) -> str:
    """Convert string to UTF-16LE hex pattern (each char followed by 00).

    Example: "SSL" -> "53 00 53 00 4c 00"
    """
    return " ".join(f"{ord(c):02x} 00" for c in s)


def build_scan_patterns(target: str) -> list[str]:
    """Build hex pattern variants for a TLS string to maximize detection.

    Generates ASCII and UTF-16LE encodings. UTF-16LE is common in
    Windows DLLs where strings are stored as wide chars.

    Args:
        target: The string to encode (e.g., "CLIENT_RANDOM")

    Returns:
        List of unique hex pattern strings for Frida Memory.scanSync()
    """
    patterns = []

    # ASCII encoding (most common)
    patterns.append(ascii_to_hex(target))

    # UTF-16LE encoding (Windows DLLs)
    patterns.append(utf16le_to_hex(target))

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique
