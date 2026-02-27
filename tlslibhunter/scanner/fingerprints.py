"""TLS library fingerprint data and string-based identification."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class LibraryFingerprint:
    """Fingerprint definition for a TLS library.

    Only includes strings that survive in stripped binaries (.rodata section),
    NOT function/symbol names which are stripped from static binaries.
    """

    library_type: str  # e.g., "boringssl"
    display_name: str  # e.g., "BoringSSL"
    fingerprint_strings: list[str] = field(default_factory=list)  # Strings that survive in .rodata
    version_patterns: list[str] = field(default_factory=list)  # Regex patterns to extract version


# Ordered by detection priority — most-specific first.
# BoringSSL and LibreSSL MUST come before OpenSSL since they also contain "OpenSSL" strings.
LIBRARY_FINGERPRINTS: list[LibraryFingerprint] = [
    LibraryFingerprint(
        library_type="boringssl",
        display_name="BoringSSL",
        fingerprint_strings=[
            "BoringSSL",
            "OpenSSL 1.1.0 (compatible; BoringSSL)",
        ],
        version_patterns=[],  # BoringSSL has no version strings by design
    ),
    LibraryFingerprint(
        library_type="libressl",
        display_name="LibreSSL",
        fingerprint_strings=[
            "LibreSSL",
        ],
        version_patterns=[
            r"LibreSSL\s+(\d+\.\d+\.\d+)",
        ],
    ),
    LibraryFingerprint(
        library_type="openssl",
        display_name="OpenSSL",
        fingerprint_strings=[
            "OpenSSL 3.",
            "OpenSSL 1.1.",
            "OpenSSL 1.0.",
        ],
        version_patterns=[
            r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)",
        ],
    ),
    LibraryFingerprint(
        library_type="gnutls",
        display_name="GnuTLS",
        fingerprint_strings=[
            "GnuTLS",
            "NORMAL:-VERS-ALL:+VERS-TLS",
        ],
        version_patterns=[
            r"GnuTLS\s+(\d+\.\d+\.\d+)",
        ],
    ),
    LibraryFingerprint(
        library_type="wolfssl",
        display_name="wolfSSL",
        fingerprint_strings=[
            "wolfSSL",
            "LIBWOLFSSL_VERSION_STRING",
        ],
        version_patterns=[
            r"wolfSSL\s+(\d+\.\d+\.\d+)",
        ],
    ),
    LibraryFingerprint(
        library_type="mbedtls",
        display_name="Mbed TLS",
        fingerprint_strings=[
            "Mbed TLS",
        ],
        version_patterns=[
            r"Mbed TLS\s+(\d+\.\d+\.\d+)",
        ],
    ),
    LibraryFingerprint(
        library_type="nss",
        display_name="NSS",
        fingerprint_strings=[
            "NSS_GetVersion",
            "NSS_NoDB_Init",
        ],
        version_patterns=[
            r"NSS\s+(\d+\.\d+)",
        ],
    ),
    LibraryFingerprint(
        library_type="s2n",
        display_name="s2n-tls",
        fingerprint_strings=[
            "s2n_negotiate",
            "default_tls13",
            "20170210",
        ],
        version_patterns=[],
    ),
    LibraryFingerprint(
        library_type="matrixssl",
        display_name="MatrixSSL",
        fingerprint_strings=[
            "matrixssl",
            "YNYYYNNNNYYNY",
        ],
        version_patterns=[],
    ),
    LibraryFingerprint(
        library_type="botan",
        display_name="Botan",
        fingerprint_strings=[
            "Botan::TLS::",
            "Botan",
        ],
        version_patterns=[
            r"Botan\s+(\d+\.\d+\.\d+)",
        ],
    ),
    LibraryFingerprint(
        library_type="gotls",
        display_name="Go crypto/tls",
        fingerprint_strings=[
            "crypto/tls",
        ],
        version_patterns=[],
    ),
    LibraryFingerprint(
        library_type="rustls",
        display_name="Rustls",
        fingerprint_strings=[
            "rustls",
        ],
        version_patterns=[],
    ),
]


def fingerprint_library(found_strings: list[str]) -> tuple[str, str]:
    """Identify a TLS library from strings found in its binary.

    Uses priority-based cascading: checks most-specific libraries first.
    BoringSSL/LibreSSL are checked before OpenSSL to avoid misidentification.

    Args:
        found_strings: Strings found in the binary's readable memory.

    Returns:
        Tuple of (library_type, detected_version). Version is empty string
        if not detected or not applicable.
    """
    if not found_strings:
        return ("unknown", "")

    for fp in LIBRARY_FINGERPRINTS:
        # Check if ANY fingerprint string is a substring of any found string
        if any(fs in s for s in found_strings for fs in fp.fingerprint_strings):
            # Try to extract version
            version = _extract_version(found_strings, fp.version_patterns)
            return (fp.library_type, version)

    return ("unknown", "")


def _extract_version(found_strings: list[str], patterns: list[str]) -> str:
    """Extract version string using regex patterns.

    Args:
        found_strings: Strings found in the binary.
        patterns: Regex patterns with a capture group for the version.

    Returns:
        Version string or empty string if no match.
    """
    for pattern in patterns:
        compiled = re.compile(pattern)
        for s in found_strings:
            m = compiled.search(s)
            if m:
                return m.group(1)
    return ""


def get_all_fingerprint_strings() -> list[str]:
    """Return all unique fingerprint strings across all libraries.

    Used to build hex scan patterns for Frida memory scanning.

    Returns:
        Deduplicated list of all fingerprint strings.
    """
    seen: set[str] = set()
    result: list[str] = []
    for fp in LIBRARY_FINGERPRINTS:
        for s in fp.fingerprint_strings:
            if s not in seen:
                seen.add(s)
                result.append(s)
    return result
