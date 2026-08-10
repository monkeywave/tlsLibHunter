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
