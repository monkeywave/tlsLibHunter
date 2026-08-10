"""Tests for session ownership across crash recovery, and agent-log routing.

Two defects covered:

* ``ModuleScanner._reattach()`` re-spawns the target and replaces ``_session``,
  but ``TLSLibHunter._session`` kept pointing at the dead original. Because
  ``extract()`` short-circuits on ``_initialized``, extraction after a recovery
  ran against a corpse and every library failed -- silently.
* Agent ``console.log`` output reached **stdout** through frida's default log
  handler, corrupting ``--format json``.
"""

import logging
from unittest.mock import Mock

import pytest

from tlslibhunter.backends import frida_backend
from tlslibhunter.hunter import TLSLibHunter
from tlslibhunter.scanner.results import ScanResult


class StubScanner:
    """Scanner whose scan() optionally swaps its session, mimicking _reattach."""

    def __init__(self, session, new_session=None, raises=None):
        self._session = session
        self._new_session = new_session
        self._raises = raises
        self.cleanup_calls = 0

    @property
    def session(self):
        return self._session

    def scan(self, target):
        if self._new_session is not None:
            self._session = self._new_session  # a recovery happened mid-scan
        if self._raises is not None:
            raise self._raises
        return ScanResult(target=target, platform="macos")

    def cleanup(self):
        self.cleanup_calls += 1


def _hunter(session, backend=None):
    hunter = TLSLibHunter("target-app")
    hunter._backend = backend or Mock()
    hunter._device = Mock()
    hunter._session = session
    hunter._platform = "macos"
    hunter._attached = {"pid": 1, "name": "original"}
    hunter._initialized = True
    return hunter


def _run_scan(hunter, scanner, monkeypatch):
    monkeypatch.setattr("tlslibhunter.scanner.module_scanner.ModuleScanner", lambda **kw: scanner)
    return hunter.scan()


# ---------------------------------------------------------------------------
# Session adoption
# ---------------------------------------------------------------------------


def test_scan_adopts_the_recovered_session(monkeypatch):
    original, recovered = Mock(name="dead"), Mock(name="recovered")
    backend = Mock()
    backend.describe_session.return_value = {"pid": 222, "name": "respawned"}
    hunter = _hunter(original, backend)

    _run_scan(hunter, StubScanner(original, new_session=recovered), monkeypatch)

    # Without this, extract() would keep using the dead original.
    assert hunter._session is recovered
    assert hunter._attached == {"pid": 222, "name": "respawned"}


def test_scan_adopts_even_when_the_scan_raises(monkeypatch):
    original, recovered = Mock(name="dead"), Mock(name="recovered")
    hunter = _hunter(original)
    scanner = StubScanner(original, new_session=recovered, raises=RuntimeError("boom"))

    with pytest.raises(RuntimeError):
        _run_scan(hunter, scanner, monkeypatch)

    assert hunter._session is recovered
    assert scanner.cleanup_calls == 1


def test_failed_respawn_leaves_no_session_and_warns(monkeypatch, caplog):
    """A failed recovery must surface as None, not as a corpse extract() would use."""
    original = Mock(name="dead")
    hunter = _hunter(original)

    with caplog.at_level(logging.WARNING, logger="tlslibhunter"):
        _run_scan(hunter, StubScanner(original, new_session=None), monkeypatch)

    # StubScanner did not swap, so the session is unchanged and no warning fires.
    assert hunter._session is original

    scanner = StubScanner(original)
    scanner._session = None  # recovery failed
    with caplog.at_level(logging.WARNING, logger="tlslibhunter"):
        _run_scan(hunter, scanner, monkeypatch)

    assert hunter._session is None
    assert hunter._attached is None
    assert "could not be recovered" in caplog.text


def test_unchanged_session_keeps_the_original_label(monkeypatch):
    session = Mock()
    backend = Mock()
    hunter = _hunter(session, backend)

    _run_scan(hunter, StubScanner(session), monkeypatch)

    assert hunter._session is session
    assert hunter._attached == {"pid": 1, "name": "original"}
    # No pointless re-describe when nothing moved.
    backend.describe_session.assert_not_called()


def test_scanner_cleanup_still_runs(monkeypatch):
    session = Mock()
    scanner = StubScanner(session)

    _run_scan(_hunter(session), scanner, monkeypatch)

    assert scanner.cleanup_calls == 1


# ---------------------------------------------------------------------------
# _reattach itself: the replaced session must be released, not abandoned
# ---------------------------------------------------------------------------


def _recovery_scanner(backend, session):
    from tlslibhunter.scanner.module_scanner import ModuleScanner

    scanner = ModuleScanner(
        backend=backend,
        session=session,
        platform="macos",
        device=Mock(),
        respawn_target="target-app",
        spawn_mode=True,
    )
    scanner._ensure_script = lambda: None  # no real frida script in a unit test
    return scanner


def test_reattach_detaches_the_replaced_session():
    dead, fresh = Mock(name="dead"), Mock(name="fresh")
    backend = Mock()
    backend.spawn.return_value = fresh
    scanner = _recovery_scanner(backend, dead)

    assert scanner._reattach() is True

    backend.detach.assert_called_once_with(dead)
    assert scanner.session is fresh


def test_reattach_clears_the_session_when_respawn_fails():
    dead = Mock(name="dead")
    backend = Mock()
    backend.spawn.side_effect = RuntimeError("respawn failed")
    scanner = _recovery_scanner(backend, dead)

    assert scanner._reattach() is False

    backend.detach.assert_called_once_with(dead)
    # An honest None beats a corpse the caller would go on using.
    assert scanner.session is None


# ---------------------------------------------------------------------------
# Agent log routing (stdout pollution)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        ("debug", logging.DEBUG),
        ("info", logging.INFO),
        ("warning", logging.WARNING),
        ("error", logging.ERROR),
        ("something-new", logging.INFO),  # unknown levels must not be dropped
    ],
)
def test_agent_log_is_forwarded_to_logging(level, expected, caplog):
    with caplog.at_level(logging.DEBUG, logger="tlslibhunter.agent"):
        frida_backend._forward_agent_log(level, "[tlslibhunter] skipped a range")

    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == expected
    assert "skipped a range" in caplog.text


def test_create_script_installs_the_log_handler():
    """Frida's default handler prints info logs to stdout, which corrupted JSON output."""
    script = Mock()
    session = Mock()
    session.create_script.return_value = script

    frida_backend.FridaBackend().create_script(session, "// agent")

    script.set_log_handler.assert_called_once_with(frida_backend._forward_agent_log)
    # Must be installed before load(), or startup logs still escape to stdout.
    order = [c[0] for c in script.method_calls]
    assert order.index("set_log_handler") < order.index("load")
