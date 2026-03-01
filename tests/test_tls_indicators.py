"""Tests for TLS indicator patterns and library type identification."""

from tlslibhunter.scanner.tls_indicators import (
    TLS_EXPORT_SYMBOLS,
    TLS_STRING_PATTERNS,
    identify_library_type,
)


class TestTLSStringPatterns:
    def test_contains_client_random(self):
        assert "CLIENT_RANDOM" in TLS_STRING_PATTERNS

    def test_contains_tls13_secrets(self):
        assert "SERVER_HANDSHAKE_TRAFFIC_SECRET" in TLS_STRING_PATTERNS
        assert "CLIENT_HANDSHAKE_TRAFFIC_SECRET" in TLS_STRING_PATTERNS
        assert "SERVER_TRAFFIC_SECRET_0" in TLS_STRING_PATTERNS
        assert "CLIENT_TRAFFIC_SECRET_0" in TLS_STRING_PATTERNS

    def test_contains_sslkeylogfile(self):
        assert "SSLKEYLOGFILE" in TLS_STRING_PATTERNS

    def test_contains_exporter_secrets(self):
        assert "EXPORTER_SECRET" in TLS_STRING_PATTERNS
        assert "EARLY_EXPORTER_SECRET" in TLS_STRING_PATTERNS

    def test_contains_internal_tls_labels(self):
        assert "c hs traffic" in TLS_STRING_PATTERNS
        assert "master secret" in TLS_STRING_PATTERNS

    def test_no_duplicates(self):
        assert len(TLS_STRING_PATTERNS) == len(set(TLS_STRING_PATTERNS))


class TestExportSymbols:
    def test_openssl_symbols(self):
        assert TLS_EXPORT_SYMBOLS["SSL_connect"] == "openssl"
        assert TLS_EXPORT_SYMBOLS["SSL_read"] == "openssl"

    def test_gnutls_symbols(self):
        assert TLS_EXPORT_SYMBOLS["gnutls_init"] == "gnutls"

    def test_wolfssl_symbols(self):
        assert TLS_EXPORT_SYMBOLS["wolfSSL_new"] == "wolfssl"

    def test_mbedtls_symbols(self):
        assert TLS_EXPORT_SYMBOLS["mbedtls_ssl_init"] == "mbedtls"

    def test_nss_symbols(self):
        assert TLS_EXPORT_SYMBOLS["NSS_Init"] == "nss"


class TestIdentifyLibraryType:
    def test_openssl_by_name(self):
        assert identify_library_type("libssl.so.3") == "openssl"
        assert identify_library_type("libcrypto.so.1.1") == "openssl"

    def test_boringssl_by_name(self):
        assert identify_library_type("libboringssl.dylib") == "boringssl"
        assert identify_library_type("libconscrypt_jni.so") == "boringssl"

    def test_cronet_detected_as_boringssl(self):
        assert identify_library_type("libcronet.132.0.6779.0.so") == "boringssl"

    def test_gnutls_by_name(self):
        assert identify_library_type("libgnutls.so.30") == "gnutls"

    def test_wolfssl_by_name(self):
        assert identify_library_type("libwolfssl.so") == "wolfssl"

    def test_mbedtls_by_name(self):
        assert identify_library_type("libmbedtls.so") == "mbedtls"

    def test_nss_by_name(self):
        assert identify_library_type("nss3.dll") == "nss"
        assert identify_library_type("libnss3.so") == "nss"

    def test_schannel_by_name(self):
        assert identify_library_type("schannel.dll") == "schannel"

    def test_unknown_library(self):
        assert identify_library_type("libfoo.so") == "unknown"

    def test_identify_by_exports(self):
        assert identify_library_type("custom_ssl.so", ["SSL_connect", "SSL_read"]) == "openssl"
        assert identify_library_type("custom.so", ["gnutls_init"]) == "gnutls"

    def test_exports_override_when_name_unknown(self):
        result = identify_library_type("libcustom.so", ["wolfSSL_new", "wolfSSL_connect"])
        assert result == "wolfssl"

    def test_name_takes_priority_over_no_exports(self):
        assert identify_library_type("libssl.so") == "openssl"
