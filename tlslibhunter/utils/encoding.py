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


def utf16be_to_hex(s: str) -> str:
    """Convert string to UTF-16BE hex pattern (each char prefixed with 00).

    Example: "SSL" -> "00 53 00 53 00 4c"
    Used for big-endian platforms (PowerPC, some MIPS) and certain Windows
    resource sections.
    """
    return " ".join(f"00 {ord(c):02x}" for c in s)


def ascii_null_terminated_to_hex(s: str) -> str:
    """Convert ASCII string to hex with trailing null byte.

    Example: "SSL" -> "53 53 4c 00"
    Matches C string literals stored inline (with their terminator).
    """
    return ascii_to_hex(s) + " 00"


def utf16le_null_terminated_to_hex(s: str) -> str:
    """Convert string to UTF-16LE hex with trailing 00 00 (wide-char null).

    Example: "SSL" -> "53 00 53 00 4c 00 00 00"
    """
    return utf16le_to_hex(s) + " 00 00"


def ascii_space_padded_to_hex(s: str, pad_to: int = 8) -> str:
    """Convert ASCII string to hex padded with 0x20 to pad_to bytes.

    Used to match the TLS 1.3 HKDF label style where short labels like
    "tls13 " are stored in fixed-size buffers (TLSKeyHunter.java compatibility).

    Example: "tls13 " (6 chars), pad_to=8 -> "74 6c 73 31 33 20 20 20"
    """
    if len(s) >= pad_to:
        return ascii_to_hex(s)
    padding = " ".join(["20"] * (pad_to - len(s)))
    return ascii_to_hex(s) + " " + padding


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
        List of hex patterns for reversed chunks. The per-chunk minimum
        length is 6 for the default chunk_size=8 (to avoid false positives);
        chunk_size=4 lowers the floor to 4 chars per chunk.
    """
    patterns = []
    min_chunk_len = max(4, min(chunk_size, 6))
    for i in range(0, len(s), chunk_size):
        chunk = s[i : i + chunk_size]
        if len(chunk) >= min_chunk_len:
            reversed_chunk = chunk[::-1]
            patterns.append(ascii_to_hex(reversed_chunk))
    return patterns


def iter_encodings(target: str):
    """Yield (hex_pattern, encoding_type) for every encoding variant of `target`.

    Single source of truth for the encoding set so `build_scan_patterns`
    (hex-only) and `_build_hex_pattern_map` (hex + reverse-lookup) stay
    in sync. UTF-16BE is gated to strings >= 6 chars to avoid FPs.

    Note: `ascii_space_padded_to_hex` is intentionally opt-in (call sites
    request it explicitly because it can produce false positives), so it
    is NOT yielded here.
    """
    yield ascii_to_hex(target), "ascii"
    yield ascii_null_terminated_to_hex(target), "ascii_nt"
    yield utf16le_to_hex(target), "utf16le"
    yield utf16le_null_terminated_to_hex(target), "utf16le_nt"
    if len(target) >= 6:
        yield utf16be_to_hex(target), "utf16be"
    for rev_hex in reversed_chunks_to_hex(target):
        yield rev_hex, "reversed_chunk_8"
    for rev_hex in reversed_chunks_to_hex(target, chunk_size=4):
        yield rev_hex, "reversed_chunk_4"


def build_scan_patterns(target: str) -> list[str]:
    """Build hex pattern variants for a TLS string to maximize detection.

    Generates ASCII, UTF-16LE (and their null-terminated variants), UTF-16BE
    (for strings >= 6 chars to avoid FPs), and reversed 8-byte + 4-byte stack chunks.

    Args:
        target: The string to encode (e.g., "CLIENT_RANDOM")

    Returns:
        Deduplicated list of hex pattern strings for Frida Memory.scanSync()
    """
    seen: set[str] = set()
    out: list[str] = []
    for hex_pat, _enc in iter_encodings(target):
        if hex_pat and hex_pat not in seen:
            seen.add(hex_pat)
            out.append(hex_pat)
    return out


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
