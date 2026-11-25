"""Shared pytest fixtures."""

from pathlib import Path

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


DISCOVERY_FIXTURES = Path(__file__).parent / "fixtures" / "discovery"

# Command prefix -> recorded output from a Pixel 5 (Android 14) Gemini session.
# ps.txt was recorded with an extra PPID column (dropped here) and grep-filtered;
# the Cloudflare WARP row (pid 2267, uid 10274) is taken from dumpsys_oom.txt.
_DISCOVERY_COMMANDS = {
    "ps -A": "ps.txt",
    "pm list packages": "pm_packages.txt",
    "dumpsys activity oom": "dumpsys_oom.txt",
    "dumpsys activity activities": "dumpsys_activities_resumed.txt",
    "su -c 'for p in": "fd_sockets.txt",
}


def read_discovery_fixture(name: str) -> str:
    return (DISCOVERY_FIXTURES / name).read_text(encoding="utf-8")


def _proc_net_fixture(cmd: str) -> str | None:
    for protocol in ("tcp6", "udp6", "tcp", "udp"):
        if cmd.rstrip("'").endswith(f"/proc/net/{protocol}"):
            return f"proc_net_{protocol}.txt"
    return None


class FixtureRunner:
    """Fake discovery runner answering from the recorded device fixtures; logs every command."""

    def __init__(self, overrides: dict | None = None, root: bool = True):
        self.commands: list[str] = []
        self.overrides = overrides or {}
        self.root = root

    def _fixture_name(self, cmd: str) -> str | None:
        prefix = next((p for p in _DISCOVERY_COMMANDS if cmd.startswith(p)), None)
        return _DISCOVERY_COMMANDS[prefix] if prefix else _proc_net_fixture(cmd)

    def __call__(self, cmd: str) -> str:
        self.commands.append(cmd)
        override = next((out for prefix, out in self.overrides.items() if cmd.startswith(prefix)), None)
        if override is not None:
            return override
        if cmd == "su -c id":
            return "uid=0(root) gid=0(root)" if self.root else ""
        name = self._fixture_name(cmd)
        return read_discovery_fixture(name) if name else ""


@pytest.fixture
def fixture_runner():
    return FixtureRunner
