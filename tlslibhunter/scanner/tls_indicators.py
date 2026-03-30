"""TLS/SSL detection patterns and known library indicators."""

from __future__ import annotations

import re

# TLS keylog format strings (SSLKEYLOGFILE / NSS key log)
_TLS_KEYLOG_PATTERNS: list[str] = [
    "CLIENT_RANDOM",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_TRAFFIC_SECRET_0",
    "CLIENT_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
    "EARLY_EXPORTER_SECRET",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "SSLKEYLOGFILE",
]

# RFC 8446 TLS 1.3 HKDF-Expand-Label values
TLS13_HKDF_LABELS: list[str] = [
    "c hs traffic",
    "s hs traffic",
    "c ap traffic",
    "s ap traffic",
    "exp master",
    "res master",
    "c e traffic",
    "e exp master",
]

# RFC 5246 TLS 1.2 PRF labels
TLS12_PRF_LABELS: list[str] = [
    "key expansion",
    "master secret",
    "extended master secret",
]

# Combined: all RFC TLS derivation labels (for raw label scan mode)
TLS_DERIVATION_LABELS: list[str] = TLS13_HKDF_LABELS + TLS12_PRF_LABELS

# All TLS string patterns scanned in memory (keylog + derivation labels)
TLS_STRING_PATTERNS: list[str] = _TLS_KEYLOG_PATTERNS + TLS_DERIVATION_LABELS

# Known TLS library export symbols for library type detection
TLS_EXPORT_SYMBOLS: dict[str, str] = {
    # OpenSSL / BoringSSL / LibreSSL
    "SSL_CTX_set_keylog_callback": "openssl",
    "SSL_connect": "openssl",
    "SSL_read": "openssl",
    "SSL_write": "openssl",
    "SSL_new": "openssl",
    "SSL_CTX_new": "openssl",
    "SSL_set_fd": "openssl",
    "SSL_get_error": "openssl",
    "OPENSSL_init_ssl": "openssl",
    # GnuTLS
    "gnutls_init": "gnutls",
    "gnutls_handshake": "gnutls",
    "gnutls_record_send": "gnutls",
    "gnutls_record_recv": "gnutls",
    "gnutls_certificate_allocate_credentials": "gnutls",
    # wolfSSL
    "wolfSSL_new": "wolfssl",
    "wolfSSL_connect": "wolfssl",
    "wolfSSL_read": "wolfssl",
    "wolfSSL_write": "wolfssl",
    "wolfSSL_CTX_new": "wolfssl",
    # mbedTLS
    "mbedtls_ssl_init": "mbedtls",
    "mbedtls_ssl_handshake": "mbedtls",
    "mbedtls_ssl_read": "mbedtls",
    "mbedtls_ssl_write": "mbedtls",
    # NSS
    "NSS_Init": "nss",
    "SSL_ImportFD": "nss",
    "PR_Read": "nss",
    "PR_Write": "nss",
    # Apple SecureTransport
    "SSLHandshake": "securetransport",
    "SSLRead": "securetransport",
    "SSLWrite": "securetransport",
    "SSLCreateContext": "securetransport",
    # SChannel (Windows)
    "InitializeSecurityContextW": "schannel",
    "AcquireCredentialsHandleW": "schannel",
    # s2n-tls
    "s2n_negotiate": "s2n",
    "s2n_connection_new": "s2n",
    # BearSSL
    "br_ssl_client_init_full": "bearssl",
    # Botan
    "botan_tls_client_init": "botan",
    # Rustls
    "rustls_client_config_builder_new": "rustls",
}

# Known TLS library stems -> library type (matched by exact stem after stripping extensions/versions)
KNOWN_TLS_LIBRARY_STEMS: dict[str, str] = {
    # OpenSSL (libssl only - libcrypto is crypto primitives, not TLS protocol)
    "libssl": "openssl",
    "ssleay32": "openssl",
    "libeay32": "openssl",
    # BoringSSL
    "libboringssl": "boringssl",
    "boringssl": "boringssl",
    # Conscrypt (Android BoringSSL wrapper)
    "libconscrypt_jni": "boringssl",
    # Cronet (Chromium network stack, uses BoringSSL)
    "cronet": "boringssl",
    "libcronet": "boringssl",
    # GnuTLS
    "libgnutls": "gnutls",
    # wolfSSL
    "libwolfssl": "wolfssl",
    # mbedTLS (only the TLS library, not crypto/x509 support libs)
    "libmbedtls": "mbedtls",
    # NSS
    "libnss3": "nss",
    "nss3": "nss",
    # SChannel (Windows only)
    "schannel": "schannel",
    "ncrypt": "schannel",
    # LibreSSL
    "libressl": "libressl",
    # Apple CoreTLS (internal TLS implementation)
    "libcoretls": "securetransport",
    # BearSSL
    "libbearssl": "bearssl",
    # s2n-tls
    "libs2n": "s2n",
    # MatrixSSL
    "libmatrixssl": "matrixssl",
    # Botan
    "libbotan": "botan",
    # Rustls
    "librustls": "rustls",
    # picotls
    "libpicotls": "picotls",
    # AWS-LC (LibCrypto)
    "libaws_lc": "aws-lc",
    "aws-lc": "aws-lc",
}

# Known TLS framework names -> library type (matched by exact name, no substring)
KNOWN_TLS_LIBRARY_EXACT: dict[str, str] = {
    # Apple SecureTransport / Network.framework
    "security": "securetransport",
    "network": "securetransport",
    "cfnetwork": "securetransport",
}

# Pre-compute lowered stem lookups for O(1) matching
_STEM_LOOKUP: dict[str, str] = {k.lower(): v for k, v in KNOWN_TLS_LIBRARY_STEMS.items()}
_EXACT_LOOKUP: dict[str, str] = {k.lower(): v for k, v in KNOWN_TLS_LIBRARY_EXACT.items()}

_VERSION_SUFFIX_RE = re.compile(r"(\.\d+)+$")
_SO_EXT_RE = re.compile(r"\.so(\.\d+)*$")


def _extract_stem(filename: str) -> str:
    """Extract library stem: strip extension(s) and version numbers.

    Examples:
        'libssl.48.dylib' -> 'libssl'
        'libssl.so.3' -> 'libssl'
        'libgnutls.so.30' -> 'libgnutls'
        'nss3.dll' -> 'nss3'
        'libcronet.132.0.6779.0.so' -> 'libcronet'
        'Security' -> 'security'
    """
    name = filename.lower()
    # Strip trailing extension
    for ext in (".dylib", ".dll", ".framework"):
        if name.endswith(ext):
            name = name[: -len(ext)]
            break
    # Handle .so with optional version suffix (libssl.so, libssl.so.3, libgnutls.so.30)
    so_match = _SO_EXT_RE.search(name)
    if so_match:
        name = name[: so_match.start()]
    # Strip trailing version numbers (e.g., .48, .3, .132.0.6779.0)
    name = _VERSION_SUFFIX_RE.sub("", name)
    return name


def _match_known_library(name: str) -> str | None:
    """Match a module name against known TLS library filename patterns.

    Uses exact stem matching (no substring matching) to avoid false positives.

    Args:
        name: Library filename (e.g., "libboringssl.dylib")

    Returns:
        Library type string if matched, None otherwise.
    """
    stem = _extract_stem(name)
    return _EXACT_LOOKUP.get(stem) or _STEM_LOOKUP.get(stem)


def identify_library_type(
    name: str,
    matched_exports: list[str] | None = None,
    fingerprint_type: str | None = None,
) -> str:
    """Identify TLS library type from name, fingerprint, and/or matched exports.

    Priority: 1) filename, 2) fingerprint (if provided and not "unknown"),
    3) export voting, 4) "unknown".

    Args:
        name: Library filename (e.g., "libssl.so.3")
        matched_exports: List of matched export symbol names
        fingerprint_type: Library type from fingerprint scanning (optional)

    Returns:
        Library type string (openssl, boringssl, gnutls, etc.) or "unknown"
    """
    # Check filename patterns (highest priority)
    lib_type = _match_known_library(name)
    if lib_type is not None:
        return lib_type

    # Check fingerprint result (from string-based identification)
    if fingerprint_type and fingerprint_type != "unknown":
        return fingerprint_type

    # Check matched exports
    if matched_exports:
        type_votes: dict[str, int] = {}
        for export in matched_exports:
            if export in TLS_EXPORT_SYMBOLS:
                etype = TLS_EXPORT_SYMBOLS[export]
                type_votes[etype] = type_votes.get(etype, 0) + 1
        if type_votes:
            return max(type_votes, key=type_votes.get)

    return "unknown"


def is_known_tls_library(name: str) -> bool:
    """Check if a module name matches a known TLS library filename pattern.

    Args:
        name: Library filename (e.g., "libboringssl.dylib")

    Returns:
        True if the name contains a known TLS library pattern.
    """
    return _match_known_library(name) is not None
