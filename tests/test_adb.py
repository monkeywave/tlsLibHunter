"""Tests for tlslibhunter.utils.adb error enrichment and serial parsing."""

from __future__ import annotations

from unittest.mock import patch

from tlslibhunter.utils import adb

ADB_DEVICES_OUT = (
    "List of devices attached\n"
    "09011FDD4007DJ\tdevice\n"
    "emulator-5554\tdevice\n"
    "deadbeef\toffline\n"
    "unauth01\tunauthorized\n"
)


def _reset_cache() -> None:
    adb._serial_cache["ts"] = 0.0
    adb._serial_cache["serials"] = []


def test_list_adb_serials_parses_only_device_state():
    _reset_cache()
    with patch("tlslibhunter.utils.adb.check_adb", return_value=True), patch(
        "tlslibhunter.utils.adb.run_cmd", return_value=(0, ADB_DEVICES_OUT)
    ):
        assert adb.list_adb_serials() == ["09011FDD4007DJ", "emulator-5554"]


def test_list_adb_serials_returns_empty_when_adb_unavailable():
    _reset_cache()
    with patch("tlslibhunter.utils.adb.check_adb", return_value=False):
        assert adb.list_adb_serials() == []


def test_list_adb_serials_returns_empty_on_command_failure():
    _reset_cache()
    with patch("tlslibhunter.utils.adb.check_adb", return_value=True), patch(
        "tlslibhunter.utils.adb.run_cmd", return_value=(1, "cannot connect")
    ):
        assert adb.list_adb_serials() == []


def test_enrich_adb_error_multi_device_appends_hint():
    _reset_cache()
    with patch("tlslibhunter.utils.adb._cached_serials", return_value=["DEV1", "DEV2"]):
        out = adb._enrich_adb_error("adb: error: failed to get feature set: more than one device/emulator")
        assert "Available serials" in out
        assert "DEV1" in out
        assert "DEV2" in out
        assert "Use --serial" in out


def test_enrich_adb_error_device_not_found_appends_hint():
    _reset_cache()
    with patch("tlslibhunter.utils.adb._cached_serials", return_value=["DEV1"]):
        out = adb._enrich_adb_error("error: device 'WRONG' not found")
        assert "not connected" in out
        assert "WRONG" in out
        assert "DEV1" in out


def test_enrich_adb_error_passthrough_for_unrelated_error():
    _reset_cache()
    msg = "adb: connection refused"
    out = adb._enrich_adb_error(msg)
    assert out == msg


def test_adb_pull_enriches_failure_message():
    _reset_cache()

    def fake_run(args, timeout=60):
        if args[:2] == ["adb", "devices"]:
            return 0, ADB_DEVICES_OUT
        return 1, "adb: error: failed to get feature set: more than one device/emulator"

    with patch("tlslibhunter.utils.adb.check_adb", return_value=True), patch(
        "tlslibhunter.utils.adb.run_cmd", side_effect=fake_run
    ):
        ok, msg = adb.adb_pull("/data/x", "/tmp/x")
        assert not ok
        assert "Available serials" in msg
        assert "09011FDD4007DJ" in msg


def test_adb_pull_success_returns_clean_message():
    _reset_cache()
    with patch("tlslibhunter.utils.adb.check_adb", return_value=True), patch(
        "tlslibhunter.utils.adb.run_cmd", return_value=(0, "1 file pulled")
    ):
        ok, msg = adb.adb_pull("/data/x", "/tmp/x")
        assert ok
        assert msg == "1 file pulled"


def test_adb_pull_serial_argument_threaded_into_command():
    _reset_cache()
    captured: dict = {}

    def fake_run(args, timeout=60):
        captured["args"] = args
        return 0, ""

    with patch("tlslibhunter.utils.adb.check_adb", return_value=True), patch(
        "tlslibhunter.utils.adb.run_cmd", side_effect=fake_run
    ):
        adb.adb_pull("/data/x", "/tmp/x", serial="ABC123")
        assert captured["args"][:4] == ["adb", "-s", "ABC123", "pull"]


def test_adb_pull_no_serial_omits_s_flag():
    _reset_cache()
    captured: dict = {}

    def fake_run(args, timeout=60):
        captured["args"] = args
        return 0, ""

    with patch("tlslibhunter.utils.adb.check_adb", return_value=True), patch(
        "tlslibhunter.utils.adb.run_cmd", side_effect=fake_run
    ):
        adb.adb_pull("/data/x", "/tmp/x")
        assert "-s" not in captured["args"]


def test_adb_shell_enriches_multi_device_error():
    """adb_shell must call _enrich_adb_error on failure, just like adb_pull."""
    _reset_cache()

    def fake_run(args, timeout=60):
        if args[:2] == ["adb", "devices"]:
            return 0, ADB_DEVICES_OUT
        return 1, "adb: error: failed to get feature set: more than one device/emulator"

    with patch("tlslibhunter.utils.adb.check_adb", return_value=True), patch(
        "tlslibhunter.utils.adb.run_cmd", side_effect=fake_run
    ):
        ret, msg = adb.adb_shell("pm path com.example")
        assert ret != 0
        assert "Available serials" in msg
        assert "09011FDD4007DJ" in msg
        assert "Use --serial" in msg


def test_adb_shell_success_path_no_enrichment():
    """Successful adb_shell must return the raw output unchanged."""
    _reset_cache()
    with patch("tlslibhunter.utils.adb.check_adb", return_value=True), patch(
        "tlslibhunter.utils.adb.run_cmd", return_value=(0, "package:/data/app/com.example/base.apk")
    ):
        ret, msg = adb.adb_shell("pm path com.example")
        assert ret == 0
        assert msg == "package:/data/app/com.example/base.apk"
