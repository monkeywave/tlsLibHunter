"""TLS/SSL detection patterns and known library indicators."""

from __future__ import annotations

# TLS keylog string patterns scanned in memory
# From scanner.js + findSSLLibsOnWindows.py
TLS_STRING_PATTERNS: list[str] = [
    "CLIENT_RANDOM",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_TRAFFIC_SECRET_0",
    "CLIENT_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
    "EARLY_EXPORTER_SECRET",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "SSLKEYLOGFILE",
    "c hs traffic",
    "master secret",
]

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

# Known TLS library file name patterns -> library type
# Map of substring/regex patterns in library names to TLS implementation type
KNOWN_TLS_LIBRARIES: dict[str, str] = {
    # OpenSSL
    "libssl": "openssl",
    "libcrypto": "openssl",
    "ssleay32": "openssl",
    "libeay32": "openssl",
    # BoringSSL
    "libboringssl": "boringssl",
    "boringssl": "boringssl",
    # Conscrypt (Android BoringSSL wrapper)
    "libconscrypt_jni": "boringssl",
    # Cronet (Chromium network stack, uses BoringSSL)
    "cronet": "boringssl",
    # GnuTLS
    "libgnutls": "gnutls",
    # wolfSSL
    "libwolfssl": "wolfssl",
    # mbedTLS
    "libmbedtls": "mbedtls",
    "libmbedcrypto": "mbedtls",
    "libmbedx509": "mbedtls",
    # NSS
    "libnss3": "nss",
    "nss3": "nss",
    # SChannel
    "schannel": "schannel",
    "ncrypt": "schannel",
    # Apple SecureTransport / Network.framework
    "Security": "securetransport",
    "Network": "securetransport",
    # LibreSSL
    "libressl": "libressl",
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


def identify_library_type(
    name: str,
    matched_exports: list[str] = None,
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
    name_lower = name.lower()

    # Check filename patterns (highest priority)
    for pattern, lib_type in KNOWN_TLS_LIBRARIES.items():
        if pattern.lower() in name_lower:
            return lib_type

    # Check fingerprint result (from string-based identification)
    if fingerprint_type and fingerprint_type != "unknown":
        return fingerprint_type

    # Check matched exports
    if matched_exports:
        type_votes: dict[str, int] = {}
        for export in matched_exports:
            if export in TLS_EXPORT_SYMBOLS:
                lib_type = TLS_EXPORT_SYMBOLS[export]
                type_votes[lib_type] = type_votes.get(lib_type, 0) + 1
        if type_votes:
            return max(type_votes, key=type_votes.get)

    return "unknown"
