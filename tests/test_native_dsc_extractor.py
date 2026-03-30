"""Tests for the native dsc_extractor-based dyld cache extraction."""

import json
import os
from unittest import mock

import pytest

from tlslibhunter.scanner.results import DetectedLibrary, ExtractionResult


@pytest.fixture
def system_library():
    return DetectedLibrary(
        name="libboringssl.dylib",
        path="/usr/lib/libboringssl.dylib",
        base_address="0x19bd00000",
        size=872032,
    )


@pytest.fixture
def app_library():
    return DetectedLibrary(
        name="libnss3.dylib",
        path="/Applications/Firefox.app/Contents/MacOS/libnss3.dylib",
        base_address="0x127e00000",
        size=5466128,
    )


@pytest.fixture
def extractor():
    from tlslibhunter.extractor.native_dsc_extractor import NativeDscExtractor
    return NativeDscExtractor()


class TestCanExtract:
    def test_rejects_non_macos(self, extractor, system_library):
        assert extractor.can_extract(system_library, "android") is False
        assert extractor.can_extract(system_library, "ios") is False
        assert extractor.can_extract(system_library, "linux") is False

    def test_rejects_app_library(self, extractor, app_library):
        assert extractor.can_extract(app_library, "macos") is False

    def test_rejects_empty_path(self, extractor):
        lib = DetectedLibrary(name="foo.dylib", path="")
        assert extractor.can_extract(lib, "macos") is False

    @mock.patch("os.path.isfile", return_value=True)
    def test_rejects_library_on_disk(self, mock_isfile, extractor, system_library):
        assert extractor.can_extract(system_library, "macos") is False

    @mock.patch("os.path.isfile", return_value=False)
    @mock.patch(
        "tlslibhunter.extractor.native_dsc_extractor._load_dsc_extractor",
        return_value=None,
    )
    def test_rejects_no_bundle(self, mock_load, mock_isfile, extractor, system_library):
        assert extractor.can_extract(system_library, "macos") is False

    @mock.patch("os.path.isfile", return_value=False)
    @mock.patch(
        "tlslibhunter.extractor.native_dsc_extractor._load_dsc_extractor",
        return_value=mock.MagicMock(),
    )
    @mock.patch(
        "tlslibhunter.extractor.native_dsc_extractor._find_dyld_cache",
        return_value="/System/Library/dyld/dyld_shared_cache_arm64e",
    )
    def test_accepts_system_library(
        self, mock_cache, mock_load, mock_isfile, extractor, system_library
    ):
        assert extractor.can_extract(system_library, "macos") is True

    def test_accepts_system_prefixes(self, extractor):
        paths = [
            "/System/Library/Frameworks/Security.framework/Versions/A/Security",
            "/usr/lib/libssl.48.dylib",
            "/Library/Apple/usr/lib/libfoo.dylib",
        ]
        for path in paths:
            lib = DetectedLibrary(name="test.dylib", path=path)
            with mock.patch("os.path.isfile", return_value=False), \
                 mock.patch(
                     "tlslibhunter.extractor.native_dsc_extractor._load_dsc_extractor",
                     return_value=mock.MagicMock(),
                 ), \
                 mock.patch(
                     "tlslibhunter.extractor.native_dsc_extractor._find_dyld_cache",
                     return_value="/some/cache",
                 ):
                assert extractor.can_extract(lib, "macos") is True, f"Failed for {path}"


class TestCacheValidation:
    def test_invalid_when_no_meta(self, tmp_path):
        from tlslibhunter.extractor.native_dsc_extractor import _is_cache_valid
        assert _is_cache_valid(str(tmp_path), "/some/path") is False

    def test_valid_when_mtime_matches(self, tmp_path):
        from tlslibhunter.extractor.native_dsc_extractor import (
            _is_cache_valid,
            _write_cache_meta,
        )
        # Create a fake dyld cache file
        fake_cache = tmp_path / "dyld_cache"
        fake_cache.write_bytes(b"fake")

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        _write_cache_meta(str(cache_dir), str(fake_cache))
        assert _is_cache_valid(str(cache_dir), str(fake_cache)) is True

    def test_invalid_when_mtime_differs(self, tmp_path):
        from tlslibhunter.extractor.native_dsc_extractor import (
            _is_cache_valid,
            _META_FILE,
        )
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        meta_path = cache_dir / _META_FILE
        meta_path.write_text(json.dumps({"dyld_cache_mtime": 0}))

        fake_cache = tmp_path / "dyld_cache"
        fake_cache.write_bytes(b"fake")

        assert _is_cache_valid(str(cache_dir), str(fake_cache)) is False


class TestFindExtractedDylib:
    def test_finds_extracted_file(self, tmp_path):
        from tlslibhunter.extractor.native_dsc_extractor import _find_extracted_dylib

        # Simulate dsc_extractor output structure
        lib_dir = tmp_path / "usr" / "lib"
        lib_dir.mkdir(parents=True)
        dylib = lib_dir / "libboringssl.dylib"
        dylib.write_bytes(b"\xcf\xfa\xed\xfe")  # Mach-O magic

        result = _find_extracted_dylib(str(tmp_path), "/usr/lib/libboringssl.dylib")
        assert result == str(dylib)

    def test_returns_none_for_missing(self, tmp_path):
        from tlslibhunter.extractor.native_dsc_extractor import _find_extracted_dylib

        result = _find_extracted_dylib(str(tmp_path), "/usr/lib/nonexistent.dylib")
        assert result is None


class TestMethodName:
    def test_method_name(self, extractor):
        assert extractor.method_name == "dsc_native"


class TestMacOSExtractionOrder:
    def test_dsc_native_before_dyld_cache(self):
        from tlslibhunter.platforms.macos import MacOSHandler
        handler = MacOSHandler()
        order = handler.get_extraction_order()
        assert "dsc_native" in order
        assert "dyld_cache" in order
        assert order.index("dsc_native") < order.index("dyld_cache")

    def test_disk_copy_first(self):
        from tlslibhunter.platforms.macos import MacOSHandler
        handler = MacOSHandler()
        order = handler.get_extraction_order()
        assert order[0] == "disk_copy"
