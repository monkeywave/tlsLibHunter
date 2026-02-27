"""Tests for platform-specific TLS library type overrides."""

from tlslibhunter.scanner.classifier import ModuleClassifier


class TestAndroidPlatformOverrides:
    def setup_method(self):
        self.clf = ModuleClassifier("android", package_name="com.example.app")

    def test_system_libssl_is_boringssl(self):
        """Android system libssl should be identified as BoringSSL."""
        info = self.clf.classify_module("libssl.so", "/system/lib64/libssl.so")
        assert info["library_type"] == "boringssl"

    def test_system_libcrypto_is_boringssl(self):
        """Android system libcrypto should be identified as BoringSSL."""
        info = self.clf.classify_module("libcrypto.so", "/system/lib64/libcrypto.so")
        assert info["library_type"] == "boringssl"

    def test_vendor_libssl_is_boringssl(self):
        """Android vendor libssl should be identified as BoringSSL."""
        info = self.clf.classify_module("libssl.so", "/vendor/lib64/libssl.so")
        assert info["library_type"] == "boringssl"

    def test_apex_libssl_is_boringssl(self):
        """Android APEX libssl should be identified as BoringSSL."""
        info = self.clf.classify_module(
            "libssl.so", "/apex/com.android.conscrypt/lib64/libssl.so"
        )
        assert info["library_type"] == "boringssl"

    def test_app_libssl_stays_openssl(self):
        """App-bundled libssl should stay as openssl, not overridden."""
        info = self.clf.classify_module(
            "libssl.so",
            "/data/app/~~abc==/com.example.app-xyz==/lib/arm64/libssl.so",
        )
        assert info["library_type"] == "openssl"

    def test_gnutls_not_overridden(self):
        """GnuTLS should not be overridden even on system path."""
        info = self.clf.classify_module(
            "libgnutls.so", "/system/lib64/libgnutls.so"
        )
        assert info["library_type"] == "gnutls"


class TestMacOSPlatformOverrides:
    def setup_method(self):
        self.clf = ModuleClassifier("macos")

    def test_system_libcrypto_is_libressl(self):
        """macOS system libcrypto should be identified as LibreSSL."""
        info = self.clf.classify_module(
            "libcrypto.44.dylib", "/usr/lib/libcrypto.44.dylib"
        )
        assert info["library_type"] == "libressl"

    def test_system_libssl_is_libressl(self):
        """macOS system libssl should be identified as LibreSSL."""
        info = self.clf.classify_module(
            "libssl.48.dylib", "/usr/lib/libssl.48.dylib"
        )
        assert info["library_type"] == "libressl"

    def test_homebrew_stays_openssl(self):
        """Homebrew-installed OpenSSL should stay as openssl."""
        info = self.clf.classify_module(
            "libssl.3.dylib", "/opt/homebrew/lib/libssl.3.dylib"
        )
        assert info["library_type"] == "openssl"

    def test_macports_stays_openssl(self):
        """MacPorts-installed OpenSSL should stay as openssl."""
        info = self.clf.classify_module(
            "libssl.3.dylib", "/opt/local/lib/libssl.3.dylib"
        )
        assert info["library_type"] == "openssl"


class TestChromiumOverrides:
    def test_libmonochrome_is_boringssl_android(self):
        clf = ModuleClassifier("android", package_name="com.chrome.browser")
        info = clf.classify_module(
            "libmonochrome.so",
            "/data/app/com.chrome.browser/lib/arm64/libmonochrome.so",
        )
        assert info["library_type"] == "boringssl"

    def test_libchrome_is_boringssl_linux(self):
        clf = ModuleClassifier("linux")
        info = clf.classify_module(
            "libchrome.so", "/opt/google/chrome/libchrome.so"
        )
        assert info["library_type"] == "boringssl"

    def test_libwebview_is_boringssl(self):
        clf = ModuleClassifier("android", package_name="com.example.app")
        info = clf.classify_module(
            "libwebview.so",
            "/data/app/com.example.app/lib/arm64/libwebview.so",
        )
        assert info["library_type"] == "boringssl"


class TestNonOpenSSLNotOverridden:
    def test_gnutls_stays_on_android(self):
        clf = ModuleClassifier("android", package_name="com.example.app")
        info = clf.classify_module("libgnutls.so", "/system/lib64/libgnutls.so")
        assert info["library_type"] == "gnutls"

    def test_wolfssl_stays_on_macos(self):
        clf = ModuleClassifier("macos")
        info = clf.classify_module("libwolfssl.dylib", "/usr/lib/libwolfssl.dylib")
        assert info["library_type"] == "wolfssl"

    def test_mbedtls_stays_on_linux(self):
        clf = ModuleClassifier("linux")
        info = clf.classify_module("libmbedtls.so", "/usr/lib/libmbedtls.so")
        assert info["library_type"] == "mbedtls"

    def test_nss_stays_on_windows(self):
        clf = ModuleClassifier("windows")
        info = clf.classify_module("nss3.dll", "C:\\Windows\\System32\\nss3.dll")
        assert info["library_type"] == "nss"
