"""Tests for Android process state inspection (freezer / TracerPid)."""

import pytest

from tlslibhunter.utils import android_process as ap

MODULE_ADB = "tlslibhunter.utils.android_process.adb_shell"


class FakeAdb:
    """Records adb_shell calls and answers based on command substrings."""

    def __init__(self, responses):
        self.responses = responses  # list of (substring, (rc, out))
        self.calls = []

    def __call__(self, cmd, serial=None):
        self.calls.append((cmd, serial))
        for needle, result in self.responses:
            if needle in cmd:
                return result
        return 1, "unexpected"


def install(monkeypatch, responses):
    fake = FakeAdb(responses)
    monkeypatch.setattr(MODULE_ADB, fake)
    return fake


class TestReadFreezeState:
    @pytest.mark.parametrize(
        "rc,out,expected",
        [
            (0, "1\n", True),
            (0, "0\n", False),
            (0, "warning: something\n\n1\n  \n", True),
            (0, "garbage\n", None),
            (0, "", None),
            (1, "1\n", None),
            (1, "su: not found", None),
        ],
    )
    def test_parse(self, monkeypatch, rc, out, expected):
        install(monkeypatch, [("cgroup.freeze", (rc, out))])
        assert ap.read_freeze_state(5431, None) is expected

    def test_command_and_serial(self, monkeypatch):
        fake = install(monkeypatch, [("cgroup.freeze", (0, "1"))])
        ap.read_freeze_state(5431, "SER123")
        assert fake.calls == [("su -c 'cat /sys/fs/cgroup/uid_*/pid_5431/cgroup.freeze'", "SER123")]


class TestReadTracerPid:
    @pytest.mark.parametrize(
        "rc,out,expected",
        [
            (0, "TracerPid:\t0\n", 0),
            (0, "TracerPid:\t1234\n", 1234),
            (0, "TracerPid:   77  \n", 77),
            (0, "TracerPid:\tabc\n", None),
            (0, "nothing here\n", None),
            (1, "No such file or directory", None),
        ],
    )
    def test_parse(self, monkeypatch, rc, out, expected):
        install(monkeypatch, [("TracerPid", (rc, out))])
        assert ap.read_tracer_pid(42, None) == expected

    def test_command_and_serial(self, monkeypatch):
        fake = install(monkeypatch, [("TracerPid", (0, "TracerPid:\t0"))])
        ap.read_tracer_pid(42, "emulator-5554")
        assert fake.calls == [("su -c 'grep TracerPid /proc/42/status'", "emulator-5554")]


class TestUnfreeze:
    def test_success(self, monkeypatch):
        fake = install(monkeypatch, [("echo 0", (0, "")), ("cat", (0, "0\n"))])
        assert ap.unfreeze(5431, "SER") is True
        assert fake.calls[0] == (
            "su -c 'for f in /sys/fs/cgroup/uid_*/pid_5431/cgroup.freeze; do echo 0 > \"$f\"; done'",
            "SER",
        )
        assert all(serial == "SER" for _, serial in fake.calls)

    def test_still_frozen(self, monkeypatch):
        install(monkeypatch, [("echo 0", (0, "")), ("cat", (0, "1\n"))])
        assert ap.unfreeze(5431, None) is False

    def test_no_root(self, monkeypatch):
        install(monkeypatch, [("echo 0", (1, "su: not found")), ("cat", (1, "su: not found"))])
        assert ap.unfreeze(5431, None) is False


class TestDiagnoseAttachTimeout:
    def test_frozen(self, monkeypatch):
        install(monkeypatch, [("cgroup.freeze", (0, "1")), ("TracerPid", (0, "TracerPid:\t0"))])
        hint = ap.diagnose_attach_timeout(5431, None)
        assert "PID 5431 is frozen" in hint
        assert "--unfreeze" in hint
        assert "cached_apps_freezer disabled" in hint

    def test_traced(self, monkeypatch):
        install(monkeypatch, [("cgroup.freeze", (0, "0")), ("TracerPid", (0, "TracerPid:\t999"))])
        hint = ap.diagnose_attach_timeout(5431, None)
        assert "ptraced by PID 999" in hint
        assert "-s" in hint

    def test_traced_with_unknown_freeze(self, monkeypatch):
        install(monkeypatch, [("cgroup.freeze", (1, "")), ("TracerPid", (0, "TracerPid:\t999"))])
        assert "ptraced by PID 999" in ap.diagnose_attach_timeout(5431, None)

    def test_neither_cause(self, monkeypatch):
        install(monkeypatch, [("cgroup.freeze", (0, "0")), ("TracerPid", (0, "TracerPid:\t0"))])
        hint = ap.diagnose_attach_timeout(5431, None)
        assert "neither frozen" in hint
        assert "frida-server" in hint
        assert "versions match" in hint

    def test_unknown(self, monkeypatch):
        install(monkeypatch, [("cgroup.freeze", (1, "su: not found")), ("TracerPid", (1, "su: not found"))])
        hint = ap.diagnose_attach_timeout(5431, None)
        assert "adb shell su -c 'cat /sys/fs/cgroup/uid_*/pid_5431/cgroup.freeze'" in hint
        assert "adb shell su -c 'grep TracerPid /proc/5431/status'" in hint
        assert "freezer" in hint and "anti-debugging" in hint

    def test_partial_unknown_not_frozen_tracer_unknown(self, monkeypatch):
        install(monkeypatch, [("cgroup.freeze", (0, "0")), ("TracerPid", (1, ""))])
        assert "Possible causes" in ap.diagnose_attach_timeout(5431, None)

    def test_serial_passed_through(self, monkeypatch):
        fake = install(monkeypatch, [("cgroup.freeze", (0, "0")), ("TracerPid", (0, "TracerPid:\t0"))])
        ap.diagnose_attach_timeout(5431, "SER9")
        assert len(fake.calls) == 2
        assert all(serial == "SER9" for _, serial in fake.calls)

    def test_pid_coerced_to_int(self, monkeypatch):
        fake = install(monkeypatch, [("cgroup.freeze", (0, "0")), ("TracerPid", (0, "TracerPid:\t0"))])
        ap.diagnose_attach_timeout("5431", None)
        assert "pid_5431/" in fake.calls[0][0]

    def test_non_numeric_pid_rejected(self):
        with pytest.raises(ValueError):
            ap.diagnose_attach_timeout("1; rm -rf /", None)
