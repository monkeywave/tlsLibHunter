"""Tests for the /proc/<pid>/maps TLS-library confirmation (fixture from a Pixel 5, Android 14)."""

import pytest

from tlslibhunter.discovery import tls_libs

# bard (4377): zygote-preloaded Conscrypt + HttpEngine (tethering APEX), both weak.
# webview host (5000): WebView loaded. 6000: only preloaded libs. 7000: no maps (process gone).
MAPS_LISTING = """PID 4377
75f3ac2000-75f3fd5000 r-xp 000b4000 fd:0d 80  /apex/com.android.tethering/lib64/libhttpengine.so
75f3ac0000-75f3ac2000 r--p 00000000 fd:0d 80  /apex/com.android.tethering/lib64/libhttpengine.so
75f549c000-75f54d3000 r-xp 00095000 fd:0d 76  /apex/com.android.tethering/lib64/libcrypto_httpengine.so
763f577000-763f578000 r-xp 00001000 fd:00 2509  /system/lib64/libwebviewchromium_loader.so
7647c90000-7647cc6000 r-xp 00088000 fd:26 159  /apex/com.android.conscrypt/lib64/libcrypto.so
7648a7b000-7648a9c000 r-xp 00018000 fd:26 160  /apex/com.android.conscrypt/lib64/libjavacrypto.so
7648c5e000-7648cb0000 r-xp 00028000 fd:26 161  /apex/com.android.conscrypt/lib64/libssl.so
7655a27000-7655a29000 r-xp 00002000 fd:00 2510  /system/lib64/libwebviewchromium_plat_support.so
7655b00000-7655b10000 r-xp 00000000 00:00 0  [anon:dalvik-jit-code-cache]
PID 5000
70a0000000-70a4000000 r-xp 00400000 fd:21 77  /data/app/~~x/webview-y/lib/arm64/libwebviewchromium.so
7648c5e000-7648cb0000 r-xp 00028000 fd:26 161  /apex/com.android.conscrypt/lib64/libssl.so
PID 6000
7648c5e000-7648cb0000 r-xp 00028000 fd:26 161  /apex/com.android.conscrypt/lib64/libssl.so
PID 7000
"""


class TestParseMapsTlsLibs:
    def test_labels_per_pid(self):
        assert tls_libs.parse_maps_tls_libs(MAPS_LISTING) == {
            4377: ["conscrypt/libssl.so", "tethering/libhttpengine.so"],
            5000: ["conscrypt/libssl.so", "libwebviewchromium.so"],
            6000: ["conscrypt/libssl.so"],
            7000: [],
        }

    def test_non_executable_mapping_is_ignored(self):
        text = "PID 1\n7000-8000 r--p 00000000 fd:00 1 /data/app/x/lib/arm64/libflutter.so\n"
        assert tls_libs.parse_maps_tls_libs(text) == {1: []}

    def test_lines_before_pid_header_are_ignored(self):
        text = "7000-8000 r-xp 00000000 fd:00 1 /system/lib64/libssl.so\n"
        assert tls_libs.parse_maps_tls_libs(text) == {}

    def test_empty(self):
        assert tls_libs.parse_maps_tls_libs("") == {}


class TestLibraryNames:
    @pytest.mark.parametrize(
        "name",
        [
            "libssl.so",
            "libhttpengine.so",
            "libcronet.132.0.6779.0.so",
            "libwebviewchromium.so",
            "libmonochrome_64.so",
            "libflutter.so",
            "libconscrypt_jni.so",
            "libnss3.so",
            "libgnutls.so.30",
            "libmbedtls.so",
            "libwolfssl.so",
            "stable_cronet_libssl.so",
        ],
    )
    def test_tls_libraries(self, name):
        assert tls_libs.is_tls_library_name(name)

    @pytest.mark.parametrize(
        "name",
        [
            "libcrypto.so",
            "libjavacrypto.so",
            "libcrypto_httpengine.so",
            "libwebviewchromium_loader.so",
            "libwebviewchromium_plat_support.so",
            "libc.so",
        ],
    )
    def test_non_tls_libraries(self, name):
        assert not tls_libs.is_tls_library_name(name)

    def test_conscrypt_label_keeps_origin(self):
        assert tls_libs.tls_lib_label("/apex/com.android.conscrypt/lib64/libssl.so") == "conscrypt/libssl.so"
        assert tls_libs.tls_lib_label("/apex/com.android.tethering/lib64/libhttpengine.so") == (
            "tethering/libhttpengine.so"
        )
        assert tls_libs.tls_lib_label("/system/lib64/libssl.so") == "libssl.so"


class TestScanScript:
    def test_pids_are_int_coerced(self):
        assert tls_libs.build_maps_scan_script([12, "34"]) == (
            'for p in 12 34; do echo "PID $p"; grep r-xp /proc/$p/maps 2>/dev/null; done'
        )

    def test_rejects_injection(self):
        with pytest.raises(ValueError):
            tls_libs.build_maps_scan_script(["1; reboot"])

    def test_has_no_single_quotes(self):
        assert "'" not in tls_libs.build_maps_scan_script([1])


class TestIsTlsConfirmed:
    @pytest.mark.parametrize(
        ("evidence", "expected"),
        [
            (["tls_lib:libwebviewchromium.so"], True),
            (["tls_lib:tethering/libhttpengine.so"], False),
            (["tls_lib:tethering/libhttpengine.so", "net:udp-connected:443"], True),
            (["tls_lib:conscrypt/libssl.so"], False),
            (["tls_lib:conscrypt/libssl.so", "net:tcp:443"], True),
            (["net:udp-connected:443"], False),
            (["foreground_host", "tls_lib:conscrypt/libssl.so"], False),
            ([], False),
        ],
    )
    def test_rule(self, evidence, expected):
        assert tls_libs.is_tls_confirmed(evidence) is expected

    def test_evidence_tags(self):
        assert tls_libs.tls_lib_evidence(["libssl.so"]) == ["tls_lib:libssl.so"]
