"""Shared pytest fixtures."""

import pytest

from tlslibhunter.backends import frida_backend


@pytest.fixture
def backend():
    """A real FridaBackend with no device attached.

    Safe to build without frida running: the constructor only initialises
    per-instance bookkeeping. Tests that need frida itself monkeypatch
    ``frida_backend._import_frida``.
    """
    return frida_backend.FridaBackend()


@pytest.fixture(autouse=True)
def _no_real_adb_for_related_process_hint(monkeypatch):
    """Keep the post-attach related-process hint from calling a real device.

    ``TLSLibHunter._initialize`` looks up related Android processes via adb;
    tests that drive it with fake backends must not reach real hardware.
    Tests of the lookup itself override this with their own fake.
    """
    monkeypatch.setattr("tlslibhunter.utils.android_related.adb_shell", lambda cmd, serial=None: (1, "no adb in tests"))
