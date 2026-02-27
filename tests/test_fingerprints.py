"""Tests for TLS library fingerprint identification."""

from tlslibhunter.scanner.fingerprints import (
    LIBRARY_FINGERPRINTS,
    fingerprint_library,
    get_all_fingerprint_strings,
)


class TestFingerprintLibrary:
    def test_boringssl_identified(self):
        lib_type, _ = fingerprint_library(["BoringSSL"])
        assert lib_type == "boringssl"

    def test_boringssl_over_openssl(self):
        """BoringSSL should win even when OpenSSL strings are present."""
        lib_type, _ = fingerprint_library(["BoringSSL", "OpenSSL 3."])
        assert lib_type == "boringssl"

    def test_libressl_over_openssl(self):
        """LibreSSL should win even when OpenSSL strings are present."""
        lib_type, _ = fingerprint_library(["LibreSSL", "OpenSSL 1.1."])
        assert lib_type == "libressl"

    def test_openssl_alone(self):
        lib_type, _ = fingerprint_library(["OpenSSL 3.0.12"])
        assert lib_type == "openssl"

    def test_gnutls(self):
        lib_type, _ = fingerprint_library(["GnuTLS"])
        assert lib_type == "gnutls"

    def test_wolfssl(self):
        lib_type, _ = fingerprint_library(["wolfSSL"])
        assert lib_type == "wolfssl"

    def test_mbedtls(self):
        lib_type, _ = fingerprint_library(["Mbed TLS"])
        assert lib_type == "mbedtls"

    def test_nss(self):
        lib_type, _ = fingerprint_library(["NSS_GetVersion"])
        assert lib_type == "nss"

    def test_s2n(self):
        lib_type, _ = fingerprint_library(["s2n_negotiate"])
        assert lib_type == "s2n"

    def test_matrixssl(self):
        lib_type, _ = fingerprint_library(["matrixssl"])
        assert lib_type == "matrixssl"

    def test_botan(self):
        lib_type, _ = fingerprint_library(["Botan"])
        assert lib_type == "botan"

    def test_gotls(self):
        lib_type, _ = fingerprint_library(["crypto/tls"])
        assert lib_type == "gotls"

    def test_rustls(self):
        lib_type, _ = fingerprint_library(["rustls"])
        assert lib_type == "rustls"

    def test_unknown_on_no_match(self):
        lib_type, _ = fingerprint_library(["random"])
        assert lib_type == "unknown"

    def test_empty_input(self):
        lib_type, version = fingerprint_library([])
        assert lib_type == "unknown"
        assert version == ""


class TestVersionExtraction:
    def test_openssl_version(self):
        _, version = fingerprint_library(["OpenSSL 3.1.4"])
        assert version == "3.1.4"

    def test_openssl_version_with_letter(self):
        _, version = fingerprint_library(["OpenSSL 1.0.2k"])
        assert version == "1.0.2k"

    def test_libressl_version(self):
        _, version = fingerprint_library(["LibreSSL 3.8.1"])
        assert version == "3.8.1"

    def test_gnutls_version(self):
        _, version = fingerprint_library(["GnuTLS 3.7.9"])
        assert version == "3.7.9"

    def test_wolfssl_version(self):
        _, version = fingerprint_library(["wolfSSL 5.6.3"])
        assert version == "5.6.3"

    def test_mbedtls_version(self):
        _, version = fingerprint_library(["Mbed TLS 3.6.0"])
        assert version == "3.6.0"

    def test_boringssl_no_version(self):
        """BoringSSL has no version strings by design."""
        _, version = fingerprint_library(["BoringSSL"])
        assert version == ""

    def test_no_version_when_unknown(self):
        _, version = fingerprint_library(["random_string"])
        assert version == ""


class TestFingerprintDataIntegrity:
    def test_all_fingerprint_strings_unique(self):
        all_strings = get_all_fingerprint_strings()
        assert len(all_strings) == len(set(all_strings))

    def test_each_fingerprint_has_strings(self):
        for fp in LIBRARY_FINGERPRINTS:
            assert len(fp.fingerprint_strings) > 0, (
                f"{fp.library_type} has no fingerprint strings"
            )

    def test_each_fingerprint_has_library_type(self):
        for fp in LIBRARY_FINGERPRINTS:
            assert fp.library_type, f"Missing library_type for {fp.display_name}"

    def test_each_fingerprint_has_display_name(self):
        for fp in LIBRARY_FINGERPRINTS:
            assert fp.display_name, f"Missing display_name for {fp.library_type}"

    def test_boringssl_before_openssl(self):
        """BoringSSL must be checked before OpenSSL in priority order."""
        types = [fp.library_type for fp in LIBRARY_FINGERPRINTS]
        assert types.index("boringssl") < types.index("openssl")

    def test_libressl_before_openssl(self):
        """LibreSSL must be checked before OpenSSL in priority order."""
        types = [fp.library_type for fp in LIBRARY_FINGERPRINTS]
        assert types.index("libressl") < types.index("openssl")
