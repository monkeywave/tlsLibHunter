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
            assert len(fp.fingerprint_strings) > 0, f"{fp.library_type} has no fingerprint strings"

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


# --- gotls section markers + rust-binary fingerprint additions ---

def test_gotls_fingerprint_includes_section_names():
    """gotls entry must include .gopclntab and .go.buildinfo section markers."""
    from tlslibhunter.scanner.fingerprints import LIBRARY_FINGERPRINTS
    gotls = next(fp for fp in LIBRARY_FINGERPRINTS if fp.library_type == "gotls")
    assert ".gopclntab" in gotls.fingerprint_strings
    assert ".go.buildinfo" in gotls.fingerprint_strings
    assert "crypto/tls" in gotls.fingerprint_strings  # existing entry preserved


def test_rust_binary_fingerprint_exists():
    """New rust-binary entry must exist with the 5 Rust runtime markers."""
    from tlslibhunter.scanner.fingerprints import LIBRARY_FINGERPRINTS
    rust_bin = next(
        (fp for fp in LIBRARY_FINGERPRINTS if fp.library_type == "rust-binary"),
        None,
    )
    assert rust_bin is not None, "rust-binary fingerprint missing"
    assert rust_bin.display_name == "Rust runtime"
    expected = {
        "rust_eh_personality",
        "core::panicking::panic_fmt",
        "std::rt::lang_start",
        "_ZN3std2rt10lang_start",
        "DW.ref.rust_eh_personality",
    }
    assert expected.issubset(set(rust_bin.fingerprint_strings))


def test_rust_binary_placed_after_rustls_in_priority():
    """rust-binary must come AFTER rustls so that rustls wins for actual rustls libs."""
    from tlslibhunter.scanner.fingerprints import LIBRARY_FINGERPRINTS
    types = [fp.library_type for fp in LIBRARY_FINGERPRINTS]
    assert "rustls" in types and "rust-binary" in types
    assert types.index("rustls") < types.index("rust-binary")


def test_priority_boringssl_beats_rust_runtime():
    """A binary with BOTH BoringSSL and Rust runtime strings classifies as boringssl."""
    from tlslibhunter.scanner.fingerprints import fingerprint_library
    lib_type, _ = fingerprint_library(["BoringSSL 5.0", "rust_eh_personality"])
    assert lib_type == "boringssl"


def test_priority_rustls_beats_rust_runtime():
    """A rustls binary still classifies as rustls (not generic rust-binary)."""
    from tlslibhunter.scanner.fingerprints import fingerprint_library
    lib_type, _ = fingerprint_library(["rustls 0.21.0", "rust_eh_personality"])
    assert lib_type == "rustls"


def test_rust_only_binary_classifies_as_rust_binary():
    """A Rust binary with NO TLS library strings classifies as rust-binary."""
    from tlslibhunter.scanner.fingerprints import fingerprint_library
    lib_type, _ = fingerprint_library(["rust_eh_personality", "std::rt::lang_start"])
    assert lib_type == "rust-binary"


def test_tls13_hkdf_expand_string_in_openssl_or_boringssl():
    """OpenSSL or BoringSSL fingerprints must include tls13_hkdf_expand marker."""
    from tlslibhunter.scanner.fingerprints import get_all_fingerprint_strings
    all_strings = get_all_fingerprint_strings()
    assert "tls13_hkdf_expand" in all_strings


def test_get_all_fingerprint_strings_includes_new_additions():
    """The full fingerprint string union includes the new additions."""
    from tlslibhunter.scanner.fingerprints import get_all_fingerprint_strings
    all_strings = get_all_fingerprint_strings()
    for s in (".gopclntab", ".go.buildinfo", "rust_eh_personality"):
        assert s in all_strings, f"{s!r} missing from get_all_fingerprint_strings()"
