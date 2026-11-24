"""Tests for Android attach-timeout recovery in TLSLibHunter (--unfreeze).

A process frozen by Android's cached-apps freezer cannot handle the ptrace stop
Frida waits for, so the attach times out. ``TLSLibHunter`` then either unfreezes
it and retries once (``unfreeze=True``) or re-raises with a diagnosis.
"""

import pytest

from tlslibhunter.backends.base import AttachTimeoutError
from tlslibhunter.config import HunterConfig
from tlslibhunter.hunter import TLSLibHunter
from tlslibhunter.utils import android_process

FROZEN_PID = 6818
DIAGNOSIS = "PID 6818 is frozen by Android's cached-apps freezer"


class FakeDevice:
    id = "emulator-5554"


class FakeBackend:
    """Backend whose first attach() raises the given error; later ones succeed."""

    def __init__(self, platform="android", first_error=None):
        self.platform = platform
        self.first_error = first_error
        self.device = FakeDevice()
        self.session = object()
        self.attach_calls = []

    def get_device(self, **kwargs):
        return self.device

    def get_device_platform(self, device):
        return self.platform

    def attach(self, device, target, timeout=10):
        self.attach_calls.append(target)
        if len(self.attach_calls) == 1 and self.first_error is not None:
            raise self.first_error
        return self.session

    def describe_session(self, device, session):
        return {"pid": FROZEN_PID, "name": "Gemini"}


class FakeAndroidProcess:
    """Records calls to the android_process helpers the hunter relies on."""

    def __init__(self, frozen=True, unfreeze_ok=True):
        self.frozen = frozen
        self.unfreeze_ok = unfreeze_ok
        self.calls = []

    def read_freeze_state(self, pid, serial=None):
        self.calls.append(("read_freeze_state", pid, serial))
        return self.frozen

    def unfreeze(self, pid, serial=None):
        self.calls.append(("unfreeze", pid, serial))
        return self.unfreeze_ok

    def diagnose_attach_timeout(self, pid, serial=None):
        self.calls.append(("diagnose_attach_timeout", pid, serial))
        return DIAGNOSIS

    def names(self):
        return [name for name, *_ in self.calls]


def _timeout_error(pid=FROZEN_PID):
    return AttachTimeoutError("Frida timed out attaching to 'Gemini'", pid=pid, target="Gemini")


@pytest.fixture
def fake_ap(monkeypatch):
    fake = FakeAndroidProcess()
    monkeypatch.setattr(android_process, "read_freeze_state", fake.read_freeze_state)
    monkeypatch.setattr(android_process, "unfreeze", fake.unfreeze)
    monkeypatch.setattr(android_process, "diagnose_attach_timeout", fake.diagnose_attach_timeout)
    return fake


def _hunter(monkeypatch, backend, unfreeze=True, serial=None):
    monkeypatch.setattr("tlslibhunter.backends.get_backend", lambda name: backend)
    config = HunterConfig(target="Gemini", mobile=True, serial=serial, unfreeze=unfreeze)
    return TLSLibHunter.from_config(config)


def test_frozen_process_is_unfrozen_and_attach_retried_by_pid(monkeypatch, fake_ap):
    backend = FakeBackend(first_error=_timeout_error())
    hunter = _hunter(monkeypatch, backend, unfreeze=True)

    hunter._initialize()

    assert backend.attach_calls == ["Gemini", FROZEN_PID]
    assert hunter._session is backend.session
    assert hunter._initialized is True
    assert fake_ap.names() == ["read_freeze_state", "unfreeze"]


def test_explicit_serial_is_used_for_adb_calls(monkeypatch, fake_ap):
    backend = FakeBackend(first_error=_timeout_error())
    hunter = _hunter(monkeypatch, backend, unfreeze=True, serial="SER123")

    hunter._initialize()

    assert all(serial == "SER123" for _, _, serial in fake_ap.calls)


def test_device_id_is_used_when_no_serial_given(monkeypatch, fake_ap):
    backend = FakeBackend(first_error=_timeout_error())
    hunter = _hunter(monkeypatch, backend, unfreeze=True)

    hunter._initialize()

    assert all(serial == "emulator-5554" for _, _, serial in fake_ap.calls)


def test_without_unfreeze_raises_with_diagnosis(monkeypatch, fake_ap):
    original = _timeout_error()
    backend = FakeBackend(first_error=original)
    hunter = _hunter(monkeypatch, backend, unfreeze=False)

    with pytest.raises(AttachTimeoutError) as excinfo:
        hunter._initialize()

    err = excinfo.value
    assert DIAGNOSIS in str(err)
    assert str(original) in str(err)
    assert err.pid == FROZEN_PID
    assert err.target == "Gemini"
    assert err.__cause__ is original
    assert backend.attach_calls == ["Gemini"]  # no retry
    assert "unfreeze" not in fake_ap.names()
    assert "read_freeze_state" not in fake_ap.names()


def test_failed_unfreeze_raises_with_diagnosis(monkeypatch, fake_ap):
    fake_ap.unfreeze_ok = False
    backend = FakeBackend(first_error=_timeout_error())
    hunter = _hunter(monkeypatch, backend, unfreeze=True)

    with pytest.raises(AttachTimeoutError) as excinfo:
        hunter._initialize()

    assert DIAGNOSIS in str(excinfo.value)
    assert backend.attach_calls == ["Gemini"]  # no retry
    assert fake_ap.names() == ["read_freeze_state", "unfreeze", "diagnose_attach_timeout"]


def test_not_frozen_skips_unfreeze_and_diagnoses(monkeypatch, fake_ap):
    fake_ap.frozen = False
    backend = FakeBackend(first_error=_timeout_error())
    hunter = _hunter(monkeypatch, backend, unfreeze=True)

    with pytest.raises(AttachTimeoutError) as excinfo:
        hunter._initialize()

    assert DIAGNOSIS in str(excinfo.value)
    assert fake_ap.names() == ["read_freeze_state", "diagnose_attach_timeout"]


@pytest.mark.parametrize("platform", ["macos", "ios", "linux", "windows"])
def test_non_android_reraises_original_unchanged(monkeypatch, fake_ap, platform):
    original = _timeout_error()
    backend = FakeBackend(platform=platform, first_error=original)
    hunter = _hunter(monkeypatch, backend, unfreeze=True)

    with pytest.raises(AttachTimeoutError) as excinfo:
        hunter._initialize()

    assert excinfo.value is original
    assert fake_ap.calls == []
    assert backend.attach_calls == ["Gemini"]


def test_unknown_pid_reraises_original_unchanged(monkeypatch, fake_ap):
    original = _timeout_error(pid=None)
    backend = FakeBackend(first_error=original)
    hunter = _hunter(monkeypatch, backend, unfreeze=True)

    with pytest.raises(AttachTimeoutError) as excinfo:
        hunter._initialize()

    assert excinfo.value is original
    assert fake_ap.calls == []
    assert backend.attach_calls == ["Gemini"]


def test_successful_attach_never_touches_android_process(monkeypatch, fake_ap):
    backend = FakeBackend(first_error=None)
    hunter = _hunter(monkeypatch, backend, unfreeze=True)

    hunter._initialize()

    assert hunter._session is backend.session
    assert backend.attach_calls == ["Gemini"]
    assert fake_ap.calls == []
