"""Tests for TLS indicator patterns and library type identification."""

from tlslibhunter.scanner.tls_indicators import (
    TLS12_PRF_LABELS,
    TLS13_HKDF_LABELS,
    TLS_DERIVATION_LABELS,
    TLS_EXPORT_SYMBOLS,
    TLS_STRING_PATTERNS,
    identify_library_type,
    is_known_tls_library,
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

    def test_contains_tls13_hkdf_labels(self):
        assert "s hs traffic" in TLS_STRING_PATTERNS
        assert "c ap traffic" in TLS_STRING_PATTERNS
        assert "s ap traffic" in TLS_STRING_PATTERNS
        assert "exp master" in TLS_STRING_PATTERNS
        assert "res master" in TLS_STRING_PATTERNS

    def test_contains_tls12_prf_labels(self):
        assert "key expansion" in TLS_STRING_PATTERNS
        assert "extended master secret" in TLS_STRING_PATTERNS

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


class TestIsKnownTlsLibrary:
    def test_libboringssl(self):
        assert is_known_tls_library("libboringssl.dylib")

    def test_libssl_versioned(self):
        assert is_known_tls_library("libssl.48.dylib")

    def test_libcrypto_not_known(self):
        assert not is_known_tls_library("libcrypto.44.dylib")

    def test_case_insensitive(self):
        assert is_known_tls_library("LibSSL.so.3")

    def test_nss(self):
        assert is_known_tls_library("libnss3.dylib")

    def test_unknown_not_known(self):
        assert not is_known_tls_library("libfoo.so")

    def test_libc_not_known(self):
        assert not is_known_tls_library("libc.so")

    def test_libz_not_known(self):
        assert not is_known_tls_library("libz.dylib")


class TestFalsePositiveExclusion:
    """Ensure known non-TLS libraries are NOT matched as known TLS libraries."""

    def test_security_hi_not_matched(self):
        assert not is_known_tls_library("SecurityHI")

    def test_security_foundation_not_matched(self):
        assert not is_known_tls_library("SecurityFoundation")

    def test_security_interface_not_matched(self):
        assert not is_known_tls_library("SecurityInterface")

    def test_network_extension_not_matched(self):
        assert not is_known_tls_library("NetworkExtension")

    def test_network_service_proxy_not_matched(self):
        assert not is_known_tls_library("NetworkServiceProxy")

    def test_mps_neural_network_not_matched(self):
        assert not is_known_tls_library("MPSNeuralNetwork")

    def test_location_log_encryption_not_matched(self):
        assert not is_known_tls_library("LocationLogEncryption")

    def test_libcommon_crypto_not_matched(self):
        assert not is_known_tls_library("libcommonCrypto.dylib")

    def test_libbnns_not_matched(self):
        assert not is_known_tls_library("libBNNS.dylib")

    def test_captive_network_not_matched(self):
        assert not is_known_tls_library("CaptiveNetwork")

    def test_message_security_not_matched(self):
        assert not is_known_tls_library("MessageSecurity")

    def test_endpoint_security_not_matched(self):
        assert not is_known_tls_library("libEndpointSecuritySystem.dylib")

    def test_interpreter_security_not_matched(self):
        assert not is_known_tls_library("libInterpreterSecurity.dylib")

    def test_launch_services_not_matched(self):
        assert not is_known_tls_library("LaunchServices")

    # Positive controls - these SHOULD still match
    def test_security_framework_still_matches(self):
        assert is_known_tls_library("Security")

    def test_network_framework_still_matches(self):
        assert is_known_tls_library("Network")

    def test_cfnetwork_still_matches(self):
        assert is_known_tls_library("CFNetwork")


class TestTLSDerivationLabels:
    """Tests for TLS derivation label constants."""

    def test_tls13_hkdf_labels_non_empty(self):
        assert len(TLS13_HKDF_LABELS) > 0

    def test_tls12_prf_labels_non_empty(self):
        assert len(TLS12_PRF_LABELS) > 0

    def test_derivation_labels_is_combined(self):
        assert TLS_DERIVATION_LABELS == TLS13_HKDF_LABELS + TLS12_PRF_LABELS

    def test_contains_key_tls13_labels(self):
        assert "c hs traffic" in TLS13_HKDF_LABELS
        assert "s ap traffic" in TLS13_HKDF_LABELS
        assert "exp master" in TLS13_HKDF_LABELS

    def test_contains_key_tls12_labels(self):
        assert "key expansion" in TLS12_PRF_LABELS
        assert "master secret" not in TLS12_PRF_LABELS  # master secret is in TLS 1.3

    def test_all_labels_are_in_string_patterns(self):
        for label in TLS_DERIVATION_LABELS:
            assert label in TLS_STRING_PATTERNS, f"{label} not in TLS_STRING_PATTERNS"


class TestLibcoretlsRecognized:
    def test_libcoretls_is_known(self):
        assert is_known_tls_library("libcoretls.dylib")

    def test_libcoretls_identified_as_securetransport(self):
        assert identify_library_type("libcoretls.dylib") == "securetransport"
