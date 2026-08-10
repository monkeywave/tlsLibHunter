"""Tests for resource release on failure paths.

Each of these leaked something when the *unhappy* path ran -- which is exactly
the path least likely to be exercised by hand:

* ``spawn()`` left a SUSPENDED process behind if attach/resume failed;
* ``create_script()`` left a created-but-unloaded script resident;
* the extractors unloaded inside the ``try``, after the exports call, so a
  raising dump/read RPC skipped it;
* ``hunter.close()`` never released the backend or device;
* the ``--host`` path registered a remote device and never removed it.
"""

import logging
from unittest.mock import Mock

import pytest

from tlslibhunter.backends import frida_backend
from tlslibhunter.backends.base import Backend, ProcessNotFoundError, ScriptError
from tlslibhunter.hunter import TLSLibHunter
from tlslibhunter.utils.process_resolver import is_exact_name, name_matches


@pytest.fixture
def backend():
    return frida_backend.FridaBackend()


# ---------------------------------------------------------------------------
# spawn(): a suspended target must never be abandoned
# ---------------------------------------------------------------------------


def test_spawn_kills_the_target_when_attach_fails(backend):
    device = Mock()
    device.spawn.return_value = 4242
    device.attach.side_effect = RuntimeError("attach denied")

    with pytest.raises(ProcessNotFoundError):
        backend.spawn(device, "app")

    # device.spawn() returns a SUSPENDED process; without this it never runs
    # and is never reaped.
    device.kill.assert_called_once_with(4242)


def test_spawn_kills_the_target_when_resume_fails(backend):
    device = Mock()
    device.spawn.return_value = 4242
    device.resume.side_effect = RuntimeError("resume failed")
    session = device.attach.return_value

    with pytest.raises(ProcessNotFoundError):
        backend.spawn(device, "app")

    device.kill.assert_called_once_with(4242)
    session.detach.assert_called_once()  # the session opened before the failure


def test_spawn_does_not_kill_when_spawn_itself_failed(backend):
    device = Mock()
    device.spawn.side_effect = RuntimeError("no such executable")

    with pytest.raises(ProcessNotFoundError):
        backend.spawn(device, "app")

    # Nothing was created, so there is no PID -- kill(None) would be a bug.
    device.kill.assert_not_called()


def test_spawn_survives_a_kill_that_fails(backend, caplog):
    device = Mock()
    device.spawn.return_value = 4242
    device.attach.side_effect = RuntimeError("attach denied")
    device.kill.side_effect = RuntimeError("already gone")

    caplog.set_level(logging.WARNING, logger="tlslibhunter.backends.frida")
    with pytest.raises(ProcessNotFoundError):  # original error, not the kill's
        backend.spawn(device, "app")

    assert "Could not kill orphaned spawn" in caplog.text


# ---------------------------------------------------------------------------
# create_script(): a script that failed to load is still resident
# ---------------------------------------------------------------------------


def test_create_script_unloads_when_load_fails(backend):
    script = Mock()
    script.load.side_effect = RuntimeError("syntax error in agent")
    session = Mock()
    session.create_script.return_value = script

    with pytest.raises(ScriptError):
        backend.create_script(session, "// bad")

    script.unload.assert_called_once()


def test_create_script_tolerates_failure_before_the_script_exists(backend):
    session = Mock()
    session.create_script.side_effect = RuntimeError("session dead")

    with pytest.raises(ScriptError):
        backend.create_script(session, "// agent")  # must not raise TypeError on None


def test_unload_script_is_safe_on_none_and_on_a_dead_script(backend):
    backend.unload_script(None)  # no-op, no exception

    script = Mock()
    script.unload.side_effect = RuntimeError("script already destroyed")
    backend.unload_script(script)  # swallowed: must never mask the real error


# ---------------------------------------------------------------------------
# Extractors: unload belongs in a finally
# ---------------------------------------------------------------------------


def _library(tmp_path):
    from tlslibhunter.scanner.results import DetectedLibrary

    return DetectedLibrary(
        name="libssl.dylib",
        path=str(tmp_path / "libssl.dylib"),
        size=1024,
        library_type="openssl",
        classification="system",
    )


@pytest.mark.parametrize(
    ("module_path", "cls_name", "rpc"),
    [
        ("tlslibhunter.extractor.memory_extractor", "MemoryExtractor", "dump_module_chunks"),
        ("tlslibhunter.extractor.ios_extractor", "IOSExtractor", "read_file_chunks"),
    ],
)
def test_extractor_unloads_the_script_when_the_rpc_raises(module_path, cls_name, rpc, tmp_path):
    import importlib

    module = importlib.import_module(module_path)
    extractor = getattr(module, cls_name)()

    script = Mock()
    setattr(script.exports_sync, rpc, Mock(side_effect=RuntimeError("agent died")))
    backend = Mock()
    backend.create_script.return_value = script

    result = extractor.extract(_library(tmp_path), str(tmp_path / "out.bin"), backend, Mock())

    assert result.success is False
    # The leak: this used to be skipped whenever the exports call raised.
    backend.unload_script.assert_called_once_with(script)


# ---------------------------------------------------------------------------
# hunter.close(): release the backend and device, and stay re-openable
# ---------------------------------------------------------------------------


def test_close_releases_backend_and_device():
    hunter = TLSLibHunter("app")
    backend, session = Mock(), Mock()
    hunter._backend, hunter._session, hunter._device = backend, session, Mock()
    hunter._attached = {"pid": 1, "name": "app"}
    hunter._initialized = True

    hunter.close()

    backend.detach.assert_called_once_with(session)
    backend.close.assert_called_once()
    assert hunter._session is None
    assert hunter._backend is None
    assert hunter._device is None
    assert hunter._attached is None
    assert hunter._initialized is False


def test_close_is_idempotent():
    hunter = TLSLibHunter("app")
    backend = Mock()
    hunter._backend, hunter._session, hunter._device = backend, Mock(), Mock()
    hunter._initialized = True

    hunter.close()
    hunter.close()  # must not raise on the now-empty state

    backend.close.assert_called_once()


def test_close_still_releases_the_backend_without_a_session():
    hunter = TLSLibHunter("app")
    backend = Mock()
    hunter._backend, hunter._session = backend, None

    hunter.close()

    backend.detach.assert_not_called()
    backend.close.assert_called_once()


# ---------------------------------------------------------------------------
# Remote devices: remove only what we added
# ---------------------------------------------------------------------------


def test_close_removes_a_remote_device_we_added(backend, monkeypatch):
    manager = Mock()
    fake_frida = Mock()
    fake_frida.get_device_manager.return_value = manager
    monkeypatch.setattr(frida_backend, "_import_frida", lambda: fake_frida)

    backend.get_device(host="10.0.0.1:27042")
    backend.close()

    manager.remove_remote_device.assert_called_once_with("10.0.0.1:27042")


def test_close_leaves_a_remote_device_we_did_not_add(backend, monkeypatch):
    """add_remote_device failing means someone else owns it -- do not remove it."""
    manager = Mock()
    manager.add_remote_device.side_effect = RuntimeError("already registered")
    fake_frida = Mock()
    fake_frida.get_device_manager.return_value = manager
    monkeypatch.setattr(frida_backend, "_import_frida", lambda: fake_frida)

    backend.get_device(host="10.0.0.1:27042")
    backend.close()

    manager.remove_remote_device.assert_not_called()


def test_close_is_a_noop_for_a_local_backend(backend):
    backend.close()
    backend.close()  # idempotent, nothing registered


def test_abc_defaults_keep_other_backends_working():
    assert Backend.close(object()) is None
    assert Backend.unload_script(object(), None) is None


# ---------------------------------------------------------------------------
# The name-matching rule now has a single definition
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "target", "exact", "loose"),
    [
        ("Finder", "Finder", True, True),
        ("Finder", "finder", True, True),
        ("QLMarkdown Preview Extension (Finder)", "Finder", False, True),
        ("Google Chrome Helper", "chrome", False, True),
        ("systemd", "Finder", False, False),
    ],
)
def test_shared_name_matching_rules(candidate, target, exact, loose):
    assert is_exact_name(candidate, target) is exact
    assert name_matches(candidate, target) is loose
