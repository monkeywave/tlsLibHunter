"""Tests for TLS indicator patterns and library type identification."""

from tlslibhunter.scanner.tls_indicators import (
    TLS12_PRF_LABELS,
    TLS13_HKDF_LABELS,
    TLS_DERIVATION_LABELS,
    TLS_EXPORT_SYMBOLS,
    TLS_STRING_PATTERNS,
    identify_library_type,
    is_known_false_positive,
    is_known_tls_library,
)


class TestKnownFalsePositive:
    """Crypto-primitive / JNI-wrapper libs are not hookable TLS stacks."""

    def test_libcrypto_is_false_positive(self):
        assert is_known_false_positive("libcrypto.so") is True

    def test_versioned_libcrypto_is_false_positive(self):
        assert is_known_false_positive("libcrypto.so.3") is True

    def test_cronet_libcrypto_is_false_positive(self):
        """The stable_cronet_ prefix must still match libcrypto."""
        assert is_known_false_positive("stable_cronet_libcrypto.so") is True

    def test_libjavacrypto_is_false_positive(self):
        assert is_known_false_positive("libjavacrypto.so") is True

    def test_libssl_is_not_false_positive(self):
        assert is_known_false_positive("libssl.so") is False

    def test_libcronet_is_not_false_positive(self):
        assert is_known_false_positive("libcronet.148.0.7778.120.so") is False

    def test_cronet_libssl_is_not_false_positive(self):
        assert is_known_false_positive("stable_cronet_libssl.so") is False

    def test_libmainlinecronet_is_not_false_positive(self):
        assert is_known_false_positive("libmainlinecronet.141.0.7340.3.so") is False


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
        from tlslibhunter.scanner.tls_indicators import OPENSSL_HKDF_HELPERS

        assert TLS_DERIVATION_LABELS == (TLS13_HKDF_LABELS + TLS12_PRF_LABELS + OPENSSL_HKDF_HELPERS)

    def test_contains_key_tls13_labels(self):
        assert "c hs traffic" in TLS13_HKDF_LABELS
        assert "s ap traffic" in TLS13_HKDF_LABELS
        assert "exp master" in TLS13_HKDF_LABELS

    def test_contains_key_tls12_labels(self):
        # RFC 5246 §5: TLS 1.2 PRF labels include "master secret", "key expansion",
        # "client finished", "server finished". TLS 1.3 (RFC 8446 §7.1) uses
        # HKDF-Expand-Label with different strings — "master secret" is not a
        # TLS 1.3 label.
        assert "key expansion" in TLS12_PRF_LABELS
        assert "master secret" in TLS12_PRF_LABELS

    def test_all_labels_are_in_string_patterns(self):
        for label in TLS_DERIVATION_LABELS:
            assert label in TLS_STRING_PATTERNS, f"{label} not in TLS_STRING_PATTERNS"


class TestLibcoretlsRecognized:
    def test_libcoretls_is_known(self):
        assert is_known_tls_library("libcoretls.dylib")

    def test_libcoretls_identified_as_securetransport(self):
        assert identify_library_type("libcoretls.dylib") == "securetransport"


# --- HKDF helper / PSK binder / Go-runtime symbol additions ---


def test_tls13_hkdf_labels_includes_new_additions():
    """TLS 1.3 HKDF labels list contains the new parity additions."""
    from tlslibhunter.scanner.tls_indicators import TLS13_HKDF_LABELS

    for label in ("tls13 ", "res binder", "ext binder", "derived", "finished"):
        assert label in TLS13_HKDF_LABELS, f"{label!r} missing from TLS13_HKDF_LABELS"


def test_tls13_label_with_trailing_space_preserved():
    """The 'tls13 ' label MUST retain its trailing space — it's part of the
    BoringSSL HKDF info encoding per RFC 8446 §7.1."""
    from tlslibhunter.scanner.tls_indicators import TLS13_HKDF_LABELS

    matches = [s for s in TLS13_HKDF_LABELS if s.startswith("tls13")]
    assert "tls13 " in matches
    # Confirm the literal trailing-space form is the one stored.
    assert any(s == "tls13 " for s in TLS13_HKDF_LABELS)


def test_tls12_prf_labels_includes_finished_variants():
    from tlslibhunter.scanner.tls_indicators import TLS12_PRF_LABELS

    assert "client finished" in TLS12_PRF_LABELS
    assert "server finished" in TLS12_PRF_LABELS


def test_openssl_hkdf_helpers_constant_exists():
    from tlslibhunter.scanner.tls_indicators import OPENSSL_HKDF_HELPERS

    assert "tls13_hkdf_expand" in OPENSSL_HKDF_HELPERS
    assert "derive_secret" in OPENSSL_HKDF_HELPERS


def test_tls_derivation_labels_includes_helpers():
    from tlslibhunter.scanner.tls_indicators import TLS_DERIVATION_LABELS

    assert "tls13_hkdf_expand" in TLS_DERIVATION_LABELS
    assert "derive_secret" in TLS_DERIVATION_LABELS


def test_tls_string_patterns_strict_excludes_short_gated_labels():
    from tlslibhunter.scanner.tls_indicators import TLS_STRING_PATTERNS_STRICT

    for label in ("tls13 ", "derived", "finished", "derive_secret"):
        assert label not in TLS_STRING_PATTERNS_STRICT, f"{label!r} must NOT appear in the strict-mode patterns"


def test_tls_string_patterns_strict_keeps_long_unique_labels():
    """Strict mode keeps the keylog labels and unambiguous derivation labels."""
    from tlslibhunter.scanner.tls_indicators import TLS_STRING_PATTERNS_STRICT

    assert "CLIENT_RANDOM" in TLS_STRING_PATTERNS_STRICT
    assert "SSLKEYLOGFILE" in TLS_STRING_PATTERNS_STRICT
    assert "key expansion" in TLS_STRING_PATTERNS_STRICT
    assert "client finished" in TLS_STRING_PATTERNS_STRICT
    assert "res binder" in TLS_STRING_PATTERNS_STRICT
    assert "tls13_hkdf_expand" in TLS_STRING_PATTERNS_STRICT


def test_go_runtime_symbols_constant():
    from tlslibhunter.scanner.tls_indicators import GO_RUNTIME_SYMBOLS

    assert GO_RUNTIME_SYMBOLS["crypto_tls_prf10"] == "gotls"
    assert GO_RUNTIME_SYMBOLS["crypto_tls_pHash"] == "gotls"


def test_go_runtime_symbols_not_in_export_table():
    """Go runtime symbols must not pollute TLS_EXPORT_SYMBOLS — they are
    not dynamic-linker exports and should not vote in identify_library_type."""
    from tlslibhunter.scanner.tls_indicators import TLS_EXPORT_SYMBOLS

    assert "crypto_tls_prf10" not in TLS_EXPORT_SYMBOLS
    assert "crypto_tls_pHash" not in TLS_EXPORT_SYMBOLS
