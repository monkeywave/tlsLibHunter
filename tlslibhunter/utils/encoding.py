"""Hex pattern encoding utilities for TLS string scanning."""

from __future__ import annotations

import base64


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


def reversed_chunks_to_hex(s: str, chunk_size: int = 8) -> list[str]:
    """Generate reversed chunk hex patterns for stack string detection.

    Compilers often load string constants as 64-bit immediates via mov
    instructions. In little-endian memory, these appear as reversed
    8-byte chunks.

    E.g., "master s" → bytes for "s retsam" → "73 20 72 65 74 73 61 6d"

    Args:
        s: The string to encode
        chunk_size: Chunk size in bytes (default 8 for 64-bit immediates)

    Returns:
        List of hex patterns for reversed chunks (only chunks >= 6 chars)
    """
    patterns = []
    for i in range(0, len(s), chunk_size):
        chunk = s[i : i + chunk_size]
        if len(chunk) >= 6:
            reversed_chunk = chunk[::-1]
            patterns.append(ascii_to_hex(reversed_chunk))
    return patterns


def build_scan_patterns(target: str) -> list[str]:
    """Build hex pattern variants for a TLS string to maximize detection.

    Generates ASCII, UTF-16LE, and reversed chunk encodings.
    - ASCII: standard string encoding
    - UTF-16LE: common in Windows DLLs (wide chars)
    - Reversed chunks: stack strings constructed via mov immediates

    Args:
        target: The string to encode (e.g., "CLIENT_RANDOM")

    Returns:
        List of hex pattern strings for Frida Memory.scanSync()
    """
    patterns = [
        ascii_to_hex(target),
        utf16le_to_hex(target),
    ]
    patterns.extend(reversed_chunks_to_hex(target))
    return patterns


def split_constant_pairs(s: str, min_length: int = 4) -> list[tuple[str, str]]:
    """Split string at underscores and at midpoint into (left, right) pairs.

    For strings with underscores, splits at each underscore position where
    both halves meet the minimum length requirement. For strings without
    underscores, splits at the midpoint.

    Args:
        s: The string to split (e.g., "CLIENT_RANDOM")
        min_length: Minimum length for each half (default 4)

    Returns:
        List of (left, right) tuples where both halves >= min_length chars
    """
    pairs: list[tuple[str, str]] = []

    if "_" in s:
        for i, ch in enumerate(s):
            if ch == "_":
                left = s[: i + 1]
                right = s[i + 1 :]
                if len(left) >= min_length and len(right) >= min_length:
                    pairs.append((left, right))
    else:
        mid = len(s) // 2
        left = s[:mid]
        right = s[mid:]
        if len(left) >= min_length and len(right) >= min_length:
            pairs.append((left, right))

    return pairs


def split_constants_to_hex(
    s: str,
    min_length: int = 4,
) -> list[tuple[str, str, str, str]]:
    """Split string into pairs and convert each half to hex.

    Args:
        s: The string to split
        min_length: Minimum length for each half (default 4)

    Returns:
        List of (left_hex, right_hex, left_str, right_str) tuples
    """
    return [
        (ascii_to_hex(left), ascii_to_hex(right), left, right) for left, right in split_constant_pairs(s, min_length)
    ]


def xor_encode_to_hex(s: str, key: int) -> str:
    """XOR each byte of the ASCII string with key, return space-separated hex.

    Args:
        s: The string to encode
        key: The XOR key (single byte, 0x00-0xFF)

    Returns:
        Space-separated hex string of XOR-encoded bytes
    """
    return " ".join(f"{ord(c) ^ key:02x}" for c in s)


def build_xor_patterns(
    target: str,
    keys: list[int] | None = None,
) -> list[tuple[str, int]]:
    """Build XOR-encoded hex patterns for a target string.

    Args:
        target: The string to encode
        keys: List of XOR keys to use. Defaults to a common set.
              Key 0x00 (identity) is always skipped.

    Returns:
        List of (hex_pattern, xor_key) tuples
    """
    if keys is None:
        keys = [0x01, 0x20, 0x41, 0x55, 0x80, 0xAA, 0xCC, 0xF0, 0xFF]

    return [(xor_encode_to_hex(target, key), key) for key in keys if key != 0x00]


def base64_encode_to_hex(s: str) -> str:
    """Base64 encode the string, then convert the result to hex.

    Args:
        s: The string to encode

    Returns:
        Space-separated hex representation of the base64-encoded string
    """
    b64 = base64.b64encode(s.encode("ascii")).decode("ascii")
    return ascii_to_hex(b64)
