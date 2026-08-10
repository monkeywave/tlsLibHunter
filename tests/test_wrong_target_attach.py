"""Tests for target resolution honesty.

Regression cover for the defect where ``tlslibhunter Finder`` attached to
"QLMarkdown Preview Extension (Finder)" (PID 16891) instead of Finder (PID 673)
and titled the results "TLS Libraries in 'Finder'".

Three independent failures had to line up:
  1. a permission failure on the exactly-named process was treated as
     "not found", so the fuzzy fallback ran at all;
  2. the fallback had no exact-name preference and took the first substring hit;
  3. the result was labelled with the *requested* target, hiding both.

Frida is never imported here -- ``_import_frida`` is monkeypatched to a stub
carrying the one exception class the discrimination depends on.
"""

import logging

import pytest

from tlslibhunter.backends import frida_backend
from tlslibhunter.backends.base import AttachmentError, ProcessNotFoundError
from tlslibhunter.output._utils import attached_label
from tlslibhunter.output.plain_formatter import PlainFormatter
from tlslibhunter.output.table_formatter import result_title
from tlslibhunter.scanner.results import ScanResult


class FridaProcessNotFoundError(Exception):
    """Stand-in for frida.ProcessNotFoundError (also raised for ambiguous names)."""


class FakeNotSupportedError(Exception):
    """Stand-in for frida.NotSupportedError -- what a hardened binary raises."""


class FakePermissionDeniedError(Exception):
    """Stand-in for frida.PermissionDeniedError."""


class FakeServerNotRunningError(Exception):
    """Stand-in for frida.ServerNotRunningError -- a LINK failure, not a target one."""


class FakeFrida:
    """Minimal stub of the frida module surface attach() touches.

    The three exception classes are distinct types on purpose: attach() decides
    whether the target exists-but-is-locked (raise a 'hardened' diagnosis) or
    the link is broken (report verbatim) purely by exception type.
    """

    ProcessNotFoundError = FridaProcessNotFoundError
    NotSupportedError = FakeNotSupportedError
    PermissionDeniedError = FakePermissionDeniedError


class FakeProcess:
    def __init__(self, name, pid):
        self.name = name
        self.pid = pid


class FakeSession:
    def __init__(self, pid):
        self.pid = pid


class WrapperSession:
    """Mimics frida.core.Session, which does NOT proxy .pid to the native object.

    Kept as an explicit class rather than a Mock: the whole point is the shape
    (pid reachable only through ``_impl``), and a Mock auto-vivifies ``.pid`` and
    would pass even if the production code stopped looking at ``_impl``.
    """

    def __init__(self, pid):
        self._impl = FakeSession(pid)


class FakeDevice:
    """Device whose attach() behaviour is scripted per target.

    ``by_target`` maps a name/PID to either an exception instance to raise or a
    FakeSession to return. ``enumerated`` backs enumerate_processes().
    """

    def __init__(self, by_target=None, enumerated=None):
        self._by_target = by_target or {}
        self._enumerated = enumerated or []
        self.attach_calls = []
        self.enumerate_calls = 0

    def attach(self, target):
        self.attach_calls.append(target)
        outcome = self._by_target.get(target)
        if outcome is None:
            raise FridaProcessNotFoundError(f"unable to find process with name '{target}'")
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def enumerate_processes(self, pids=None, scope=None):
        self.enumerate_calls += 1
        if pids is not None:
            return [p for p in self._enumerated if p.pid in pids]
        return list(self._enumerated)


@pytest.fixture(autouse=True)
def _stub_frida(monkeypatch):
    monkeypatch.setattr(frida_backend, "_import_frida", lambda: FakeFrida)


# ---------------------------------------------------------------------------
# Defect 1 -- a permission failure must never cause a retarget
# ---------------------------------------------------------------------------


def test_hardened_target_raises_instead_of_retargeting(backend):
    """The exact Finder repro: the named process exists but cannot be injected."""
    device = FakeDevice(
        by_target={
            # What frida really raised: NotSupportedError, which is NOT a
            # subclass of ProcessNotFoundError.
            "Finder": FakeNotSupportedError(
                "unexpected error while starting thread (thread_create returned '(os/kern) protection failure')"
            )
        },
        enumerated=[
            FakeProcess("Finder", 673),
            FakeProcess("QLMarkdown Preview Extension (Finder)", 16891),
        ],
    )

    with pytest.raises(AttachmentError) as excinfo:
        backend.attach(device, "Finder")

    assert "could not attach" in str(excinfo.value)
    # The critical assertion: the QLMarkdown plugin was never touched.
    assert device.attach_calls == ["Finder"]
    assert 16891 not in device.attach_calls
    # And we did not even go looking for a substitute.
    assert device.enumerate_calls == 0


def test_link_failure_is_not_blamed_on_the_target(backend):
    """A dead frida-server surfaces from attach() too, because frida resolves the
    name over the device link first. Reporting that as 'hardened or
    SIP-protected' sends the user down the wrong path entirely."""
    device = FakeDevice(
        by_target={"com.example.app": FakeServerNotRunningError("unable to connect to remote frida-server")},
        enumerated=[FakeProcess("com.example.app.helper", 900)],
    )

    with pytest.raises(AttachmentError) as excinfo:
        backend.attach(device, "com.example.app")

    msg = str(excinfo.value)
    assert "unable to connect to remote frida-server" in msg
    assert "SIP-protected" not in msg and "hardened" not in msg
    # Still must not retarget on a flaky link.
    assert device.enumerate_calls == 0


def test_describe_session_rejects_a_backend_that_ignores_the_pid_filter(backend):
    """Trusting matches[0] would stamp an unrelated process onto the result."""

    class IgnoresPidsFilter(FakeDevice):
        def enumerate_processes(self, pids=None, scope=None):
            self.enumerate_calls += 1
            return list(self._enumerated)  # filter ignored -- full list

    device = IgnoresPidsFilter(enumerated=[FakeProcess("some-unrelated-process", 111), FakeProcess("Finder", 673)])

    assert backend.describe_session(device, FakeSession(673)) == {"pid": 673, "name": "Finder"}


def test_pid_target_never_falls_back(backend):
    device = FakeDevice(
        by_target={673: RuntimeError("permission denied")},
        enumerated=[FakeProcess("QLMarkdown Preview Extension (Finder)", 16891)],
    )

    with pytest.raises(AttachmentError):
        backend.attach(device, 673)

    assert device.attach_calls == [673]
    assert device.enumerate_calls == 0


# ---------------------------------------------------------------------------
# Defect 2 -- the fallback stays available, but only when the name truly is absent
# ---------------------------------------------------------------------------


def test_name_match_fallback_still_works_and_warns(backend, caplog):
    """A genuinely absent name may still resolve by substring -- loudly."""
    session = FakeSession(4242)
    device = FakeDevice(
        by_target={4242: session},
        enumerated=[FakeProcess("Google Chrome Helper", 4242)],
    )

    with caplog.at_level(logging.WARNING, logger="tlslibhunter.backends.frida"):
        assert backend.attach(device, "chrome") is session

    assert "attached to 'Google Chrome Helper' (PID 4242) by name match" in caplog.text
    assert "Results describe THAT process" in caplog.text


def test_ambiguous_exact_names_refuse_to_guess(backend):
    device = FakeDevice(
        enumerated=[FakeProcess("python", 10), FakeProcess("python", 11)],
    )

    with pytest.raises(AttachmentError) as excinfo:
        backend.attach(device, "python")

    msg = str(excinfo.value)
    assert "ambiguous" in msg
    assert "PID 10" in msg and "PID 11" in msg
    # Neither was attached -- an arbitrary pick would be irreproducible.
    assert device.attach_calls == ["python"]


def test_no_candidates_lists_running_processes(backend):
    device = FakeDevice(enumerated=[FakeProcess("systemd", 1), FakeProcess("kthreadd", 2)])

    with pytest.raises(ProcessNotFoundError) as excinfo:
        backend.attach(device, "nonexistent-xyz")

    assert "Available processes" in str(excinfo.value)
    assert "systemd (PID 1)" in str(excinfo.value)


def test_exact_name_attaches_without_enumerating(backend):
    session = FakeSession(673)
    device = FakeDevice(by_target={"Finder": session}, enumerated=[FakeProcess("Finder", 673)])

    assert backend.attach(device, "Finder") is session
    assert device.enumerate_calls == 0


# ---------------------------------------------------------------------------
# Defect 3 -- results must name the process actually instrumented
# ---------------------------------------------------------------------------


def test_describe_session_reports_pid_and_name(backend):
    device = FakeDevice(enumerated=[FakeProcess("Finder", 673)])

    assert backend.describe_session(device, FakeSession(673)) == {"pid": 673, "name": "Finder"}


def test_describe_session_returns_none_without_a_pid(backend):
    assert backend.describe_session(FakeDevice(), object()) is None


def test_describe_session_reads_pid_through_impl(backend):
    """frida.core.Session hides pid behind _impl -- reading only .pid found nothing
    and silently dropped the label, which is how the mismatch stayed invisible."""
    device = FakeDevice(enumerated=[FakeProcess("Finder", 673)])

    assert backend.describe_session(device, WrapperSession(673)) == {"pid": 673, "name": "Finder"}


def test_describe_session_tolerates_unknown_pid(backend):
    device = FakeDevice(enumerated=[])

    assert backend.describe_session(device, FakeSession(99999)) == {"pid": 99999, "name": None}


def test_describe_session_falls_back_when_pids_filter_is_ignored(backend):
    class IgnoresPidsFilter(FakeDevice):
        def enumerate_processes(self, pids=None, scope=None):
            self.enumerate_calls += 1
            return list(self._enumerated)  # filter ignored

    device = IgnoresPidsFilter(enumerated=[FakeProcess("Finder", 673), FakeProcess("other", 99)])

    assert backend.describe_session(device, FakeSession(673)) == {"pid": 673, "name": "Finder"}


def test_unresolved_name_still_reports_the_pid():
    """A missing name must not erase the identity -- the PID is still the truth."""
    result = ScanResult(target="Finder", platform="macos", attached_process=None, attached_pid=16891)

    assert "PID 16891" in result_title(result)


@pytest.mark.parametrize(
    ("target", "attached_process", "attached_pid", "expected"),
    [
        ("Finder", "Finder", 673, False),
        ("finder", "Finder", 673, False),  # case-insensitive
        ("Finder", "QLMarkdown Preview Extension (Finder)", 16891, True),
        ("16891", "QLMarkdown Preview Extension (Finder)", 16891, False),  # asked by PID
        ("Finder", None, None, False),  # backend could not tell
    ],
)
def test_target_mismatch(target, attached_process, attached_pid, expected):
    result = ScanResult(
        target=target,
        platform="macos",
        attached_process=attached_process,
        attached_pid=attached_pid,
    )

    assert result.target_mismatch is expected


def test_title_flags_a_mismatch():
    result = ScanResult(
        target="Finder",
        platform="macos",
        attached_process="QLMarkdown Preview Extension (Finder)",
        attached_pid=16891,
    )

    title = result_title(result)
    assert "QLMarkdown Preview Extension (Finder)" in title
    assert "PID 16891" in title
    assert "REQUESTED 'Finder'" in title


def test_title_is_quiet_when_the_target_matches():
    result = ScanResult(target="Finder", platform="macos", attached_process="Finder", attached_pid=673)

    title = result_title(result)
    assert title == "TLS Libraries in 'Finder' (PID 673) (macos)"
    assert "REQUESTED" not in title


@pytest.mark.parametrize(
    ("attached_process", "attached_pid", "plain", "quoted"),
    [
        ("Finder", 673, "Finder (PID 673)", "'Finder' (PID 673)"),
        ("Finder", None, "Finder", "'Finder'"),
        (None, 673, "PID 673", "PID 673"),  # name unresolved, PID still honest
        (None, None, None, None),  # backend could not identify it at all
    ],
)
def test_attached_label_covers_every_identity_case(attached_process, attached_pid, plain, quoted):
    """One helper, so the table and plain formatters cannot word this differently."""
    result = ScanResult(
        target="Finder",
        platform="macos",
        attached_process=attached_process,
        attached_pid=attached_pid,
    )

    assert attached_label(result) == plain
    assert attached_label(result, quote_name=True) == quoted


def test_plain_formatter_reports_the_attached_process_and_flags_a_mismatch():
    """The plain formatter had no coverage at all before this."""
    result = ScanResult(
        target="Finder",
        platform="macos",
        attached_process="QLMarkdown Preview Extension (Finder)",
        attached_pid=16891,
    )

    out = PlainFormatter().format_scan(result)

    assert "Attached to: QLMarkdown Preview Extension (Finder) (PID 16891)" in out
    assert "WARNING" in out and "NOT the process scanned" in out


def test_plain_formatter_is_quiet_when_the_target_matches():
    result = ScanResult(target="Finder", platform="macos", attached_process="Finder", attached_pid=673)

    out = PlainFormatter().format_scan(result)

    assert "Attached to: Finder (PID 673)" in out
    assert "WARNING" not in out


def test_to_dict_exposes_the_attached_process():
    result = ScanResult(
        target="Finder",
        platform="macos",
        attached_process="QLMarkdown Preview Extension (Finder)",
        attached_pid=16891,
    )

    payload = result.to_dict()
    assert payload["attached_process"] == "QLMarkdown Preview Extension (Finder)"
    assert payload["attached_pid"] == 16891
    assert payload["target_mismatch"] is True
    # `target` keeps recording the request, so existing consumers are unaffected.
    assert payload["target"] == "Finder"
