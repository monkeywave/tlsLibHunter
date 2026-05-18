"""Tests verifying that --serial is threaded through to all adb invocations."""

from __future__ import annotations

from unittest.mock import Mock, patch

from tlslibhunter.extractor.android_extractor import AdbPullExtractor, ApkInnerExtractor
from tlslibhunter.scanner.results import DetectedLibrary


def _make_library(path: str = "/data/lib/libfoo.so", name: str = "libfoo.so") -> DetectedLibrary:
    """Build a minimal DetectedLibrary. Fields beyond name/path may be added if required."""
    # DetectedLibrary may have required positional args; inspect on first failure.
    return DetectedLibrary(name=name, path=path)


def test_adb_pull_extractor_threads_serial():
    with patch("tlslibhunter.utils.adb.check_adb", return_value=True), patch(
        "tlslibhunter.utils.adb.run_cmd", return_value=(0, "1 file pulled")
    ) as mock_run:
        ext = AdbPullExtractor(serial="ABC123")
        lib = _make_library()
        ext.extract(lib, "/tmp/libfoo.so")
        # The first positional arg of run_cmd is the argv list.
        argv = mock_run.call_args[0][0]
        assert "-s" in argv
        assert "ABC123" in argv
        assert argv.index("-s") + 1 == argv.index("ABC123")  # -s immediately before serial


def test_adb_pull_extractor_no_serial_omits_s_flag():
    with patch("tlslibhunter.utils.adb.check_adb", return_value=True), patch(
        "tlslibhunter.utils.adb.run_cmd", return_value=(0, "1 file pulled")
    ) as mock_run:
        ext = AdbPullExtractor()
        lib = _make_library()
        ext.extract(lib, "/tmp/libfoo.so")
        argv = mock_run.call_args[0][0]
        assert "-s" not in argv


def test_apk_inner_extractor_threads_serial(tmp_path):
    """ApkInnerExtractor pulls an APK from the device. Verify serial flows through."""
    # apk_inner needs a path with '!' separator. The pull happens, then APK unzip.
    # We mock adb_pull to fail so we never reach the unzip — we only care about the call args.
    # adb_pull / check_adb are imported lazily inside extract(), so patch them at the source module.
    with patch("tlslibhunter.utils.adb.adb_pull") as mock_pull, patch(
        "tlslibhunter.utils.adb.check_adb", return_value=True
    ):
        mock_pull.return_value = (False, "mocked failure")
        ext = ApkInnerExtractor(serial="DEV2")
        lib = _make_library(path="/data/base.apk!lib/arm64-v8a/libfoo.so")
        ext.extract(lib, str(tmp_path / "libfoo.so"))
        # adb_pull was called; assert serial kwarg was passed.
        call = mock_pull.call_args
        assert call.kwargs.get("serial") == "DEV2" or (len(call.args) >= 3 and call.args[2] == "DEV2")


def test_apk_inner_extractor_no_serial():
    with patch("tlslibhunter.utils.adb.adb_pull") as mock_pull, patch(
        "tlslibhunter.utils.adb.check_adb", return_value=True
    ):
        mock_pull.return_value = (False, "mocked failure")
        ext = ApkInnerExtractor()
        lib = _make_library(path="/data/base.apk!lib/arm64-v8a/libfoo.so")
        ext.extract(lib, "/tmp/libfoo.so")
        call = mock_pull.call_args
        # Either serial kwarg is None, or no third positional was supplied.
        assert call.kwargs.get("serial") is None


def test_extraction_strategy_propagates_serial_to_android_extractors():
    from tlslibhunter.extractor.strategy import ExtractionStrategy

    backend = Mock()
    session = Mock()
    strat = ExtractionStrategy(
        backend=backend,
        session=session,
        platform="android",
        output_dir="/tmp",
        serial="XYZ",
    )
    # All adb-using extractors must have _serial set.
    from tlslibhunter.extractor.android_extractor import AdbPullExtractor, ApkInnerExtractor

    for ext in strat._extractors:
        if isinstance(ext, (AdbPullExtractor, ApkInnerExtractor)):
            assert ext._serial == "XYZ"


def test_extraction_strategy_serial_default_none():
    from tlslibhunter.extractor.strategy import ExtractionStrategy

    strat = ExtractionStrategy(
        backend=Mock(),
        session=Mock(),
        platform="android",
        output_dir="/tmp",
    )
    from tlslibhunter.extractor.android_extractor import AdbPullExtractor, ApkInnerExtractor

    for ext in strat._extractors:
        if isinstance(ext, (AdbPullExtractor, ApkInnerExtractor)):
            assert ext._serial is None


def test_extraction_strategy_non_android_unaffected():
    """For platform='ios', adb-based extractors aren't in the order, so passing serial is a no-op."""
    from tlslibhunter.extractor.strategy import ExtractionStrategy

    strat = ExtractionStrategy(
        backend=Mock(),
        session=Mock(),
        platform="ios",
        output_dir="/tmp",
        serial="X",
    )
    # Just verify construction doesn't crash and strategy._serial is recorded.
    assert strat._serial == "X"
