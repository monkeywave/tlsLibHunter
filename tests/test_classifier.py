"""Tests for module classifier."""

from tlslibhunter.scanner.classifier import ModuleClassifier


class TestAndroidClassifier:
    def setup_method(self):
        self.clf = ModuleClassifier("android", package_name="com.example.app")

    def test_system_library(self):
        info = self.clf.classify_module("libssl.so", "/system/lib64/libssl.so")
        assert info["classification"] == "system"

    def test_app_library_data_app(self):
        info = self.clf.classify_module(
            "libcustom.so",
            "/data/app/~~abc==/com.example.app-xyz==/lib/arm64/libcustom.so",
        )
        assert info["classification"] == "app"

    def test_apk_inner_is_app(self):
        info = self.clf.classify_module(
            "libcronet.so",
            "/data/app/~~abc==/com.example.app-xyz==/base.apk!/lib/arm64-v8a/libcronet.so",
        )
        assert info["classification"] == "app"

    def test_scan_worthy_skips_libc(self):
        assert not self.clf.is_scan_worthy("libc.so", "/system/lib64/libc.so")

    def test_scan_worthy_skips_odex(self):
        assert not self.clf.is_scan_worthy("base.odex", "/data/app/base.odex")

    def test_scan_worthy_allows_libssl(self):
        assert self.clf.is_scan_worthy("libssl.so", "/system/lib64/libssl.so")


class TestWindowsClassifier:
    def setup_method(self):
        self.clf = ModuleClassifier("windows")

    def test_system_dll(self):
        info = self.clf.classify_module("kernel32.dll", "C:\\Windows\\System32\\kernel32.dll")
        assert info["classification"] == "system"

    def test_app_dll(self):
        info = self.clf.classify_module("myapp.dll", "C:\\Program Files\\MyApp\\myapp.dll")
        assert info["classification"] == "app"

    def test_scan_worthy_skips_ntdll(self):
        assert not self.clf.is_scan_worthy("ntdll.dll", "C:\\Windows\\System32\\ntdll.dll")


class TestLinuxClassifier:
    def setup_method(self):
        self.clf = ModuleClassifier("linux")

    def test_system_library(self):
        info = self.clf.classify_module("libssl.so.3", "/usr/lib/x86_64-linux-gnu/libssl.so.3")
        assert info["classification"] == "system"
        assert info["library_type"] == "openssl"

    def test_app_library(self):
        info = self.clf.classify_module("libcustom.so", "/opt/myapp/lib/libcustom.so")
        assert info["classification"] == "app"
