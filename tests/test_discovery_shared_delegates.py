"""Tests for the shared system delegate list."""

import pytest

from tlslibhunter.discovery import shared_delegates as sd


class TestSharedDelegates:
    def test_loads_frozenset(self):
        assert isinstance(sd.load_shared_delegates(), frozenset)

    @pytest.mark.parametrize(
        "package",
        [
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.android.providers.downloads",
            "com.android.providers.media.module",
            "com.google.android.as.oss",
            "com.android.chrome",
            "com.android.vending",
            "netd",
        ],
    )
    def test_listed(self, package):
        assert sd.is_shared_delegate(package)

    @pytest.mark.parametrize("package", ["com.google.android.webview", "com.example.app", ""])
    def test_not_listed(self, package):
        assert not sd.is_shared_delegate(package)

    def test_json_file_ships_next_to_module(self):
        assert sd.SHARED_DELEGATES_FILE.is_file()
