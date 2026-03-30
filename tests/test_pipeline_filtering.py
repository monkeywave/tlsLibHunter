"""Tests for the multi-stage filtering pipeline."""

import pytest
from tlslibhunter.scanner.classifier import ModuleClassifier


class TestMacosTlsCandidateFiltering:
    """Test is_tls_candidate aggressively filters macOS system frameworks."""

    @pytest.fixture
    def classifier(self):
        return ModuleClassifier("macos")

    # System frameworks that should be SKIPPED
    def test_skips_appkit(self, classifier):
        assert not classifier.is_tls_candidate(
            "AppKit", "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit"
        )

    def test_skips_coregraphics(self, classifier):
        assert not classifier.is_tls_candidate(
            "CoreGraphics", "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics"
        )

    def test_skips_metal(self, classifier):
        assert not classifier.is_tls_candidate(
            "Metal", "/System/Library/Frameworks/Metal.framework/Versions/A/Metal"
        )

    def test_skips_avfoundation(self, classifier):
        assert not classifier.is_tls_candidate(
            "AVFoundation", "/System/Library/Frameworks/AVFoundation.framework/Versions/A/AVFoundation"
        )

    def test_skips_iokit(self, classifier):
        assert not classifier.is_tls_candidate(
            "IOKit", "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
        )

    def test_skips_private_framework(self, classifier):
        assert not classifier.is_tls_candidate(
            "SpeechRecognitionCore",
            "/System/Library/PrivateFrameworks/SpeechRecognitionCore.framework/Versions/A/SpeechRecognitionCore"
        )

    # System TLS libraries that should be KEPT
    def test_keeps_security_framework(self, classifier):
        assert classifier.is_tls_candidate(
            "Security", "/System/Library/Frameworks/Security.framework/Versions/A/Security"
        )

    def test_keeps_network_framework(self, classifier):
        assert classifier.is_tls_candidate(
            "Network", "/System/Library/Frameworks/Network.framework/Versions/A/Network"
        )

    def test_keeps_cfnetwork(self, classifier):
        assert classifier.is_tls_candidate(
            "CFNetwork", "/System/Library/Frameworks/CFNetwork.framework/Versions/A/CFNetwork"
        )

    def test_keeps_libssl(self, classifier):
        assert classifier.is_tls_candidate(
            "libssl.48.dylib", "/usr/lib/libssl.48.dylib"
        )

    def test_keeps_libboringssl(self, classifier):
        assert classifier.is_tls_candidate(
            "libboringssl.dylib", "/usr/lib/libboringssl.dylib"
        )

    def test_keeps_libcoretls(self, classifier):
        assert classifier.is_tls_candidate(
            "libcoretls.dylib", "/usr/lib/libcoretls.dylib"
        )

    # App-bundled libraries should ALWAYS pass
    def test_keeps_app_bundled_lib(self, classifier):
        assert classifier.is_tls_candidate(
            "libnss3.dylib", "/Applications/Firefox.app/Contents/MacOS/libnss3.dylib"
        )

    def test_keeps_homebrew_lib(self, classifier):
        assert classifier.is_tls_candidate(
            "libssl.3.dylib", "/opt/homebrew/opt/openssl/lib/libssl.3.dylib"
        )

    def test_keeps_user_installed_lib(self, classifier):
        assert classifier.is_tls_candidate(
            "libgnutls.so.30", "/usr/local/lib/libgnutls.so.30"
        )


class TestNonMacosPlatformsUnchanged:
    """Verify is_tls_candidate doesn't break other platforms."""

    def test_linux_passes_all_scan_worthy(self):
        classifier = ModuleClassifier("linux")
        # Linux modules that are scan-worthy should pass is_tls_candidate
        assert classifier.is_tls_candidate(
            "libfoo.so", "/usr/lib/x86_64-linux-gnu/libfoo.so"
        )

    def test_android_still_filters_libc(self):
        classifier = ModuleClassifier("android")
        assert not classifier.is_tls_candidate("libc.so", "/system/lib64/libc.so")

    def test_android_keeps_libssl(self):
        classifier = ModuleClassifier("android")
        assert classifier.is_tls_candidate("libssl.so", "/system/lib64/libssl.so")


class TestPipelineStats:
    """Test that ScanResult.pipeline_stats is populated."""

    def test_pipeline_stats_default_empty(self):
        from tlslibhunter.scanner.results import ScanResult
        result = ScanResult(target="test", platform="macos")
        assert result.pipeline_stats == {}

    def test_pipeline_stats_in_to_dict(self):
        from tlslibhunter.scanner.results import ScanResult
        result = ScanResult(target="test", platform="macos")
        result.pipeline_stats = {"total_modules": 100, "after_name_filter": 10}
        d = result.to_dict()
        assert d["pipeline_stats"]["total_modules"] == 100
        assert d["pipeline_stats"]["after_name_filter"] == 10
