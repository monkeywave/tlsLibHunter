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
from tlslibhunter.backends.base import AttachmentError, AttachTimeoutError, ProcessNotFoundError
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


class FakeTimedOutError(Exception):
    """Stand-in for frida.TimedOutError -- ptrace could not stop a frozen process."""


class FakeTransportError(Exception):
    """Stand-in for frida.TransportError -- frida 17.26+ also reports a frozen process this way."""


class FakeFrida:
    """Minimal stub of the frida module surface attach() touches.

    The three exception classes are distinct types on purpose: attach() decides
    whether the target exists-but-is-locked (raise a 'hardened' diagnosis) or
    the link is broken (report verbatim) purely by exception type.
    """

    ProcessNotFoundError = FridaProcessNotFoundError
    NotSupportedError = FakeNotSupportedError
    PermissionDeniedError = FakePermissionDeniedError
    TimedOutError = FakeTimedOutError
    TransportError = FakeTransportError


class FakeProcess:
    def __init__(self, name, pid):
        self.name = name
        self.pid = pid


class FakeApp:
    """Stand-in for frida.Application: pid is 0 when the app is not running."""

    def __init__(self, identifier, name, pid=0):
        self.identifier = identifier
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
    ``apps`` backs enumerate_applications(); pass an exception instance to make
    app enumeration fail. ``spawn_pid`` is what spawn() returns.
    """

    def __init__(self, by_target=None, enumerated=None, apps=None, spawn_pid=5000):
        self._by_target = by_target or {}
        self._enumerated = enumerated or []
        self._apps = apps if apps is not None else []
        self._spawn_pid = spawn_pid
        self.attach_calls = []
        self.enumerate_calls = 0
        self.spawn_calls = []
        self.resumed = []
        self.killed = []

    def enumerate_applications(self, identifiers=None, scope=None):
        if isinstance(self._apps, BaseException):
            raise self._apps
        return list(self._apps)

    def spawn(self, argv):
        self.spawn_calls.append(list(argv))
        return self._spawn_pid

    def resume(self, pid):
        self.resumed.append(pid)

    def kill(self, pid):
        self.killed.append(pid)

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

    msg = str(excinfo.value)
    assert "Available processes" not in msg
    assert "systemd (PID 1)" not in msg
    assert "no installed app matches" in msg
    assert "frida-ps" in msg


def test_no_candidates_lists_running_apps(backend):
    """The user still learns what IS running -- the apps, not init/logd/vold."""
    device = FakeDevice(
        enumerated=[FakeProcess("init", 1), FakeProcess("logd", 2)],
        apps=[
            FakeApp("com.android.chrome", "Chrome", pid=3100),
            FakeApp("com.google.android.youtube", "YouTube", pid=0),
        ],
    )

    with pytest.raises(ProcessNotFoundError) as excinfo:
        backend.attach(device, "nonexistent-xyz")

    msg = str(excinfo.value)
    assert "Running apps:" in msg
    assert "Chrome (com.android.chrome, PID 3100)" in msg
    assert "YouTube" not in msg  # installed but not running
    assert "init (PID 1)" not in msg
    assert "frida-ps -Uai" in msg


# ---------------------------------------------------------------------------
# Mobile apps -- labels and identifiers are not process names
# ---------------------------------------------------------------------------

GEMINI = "com.google.android.apps.bard"


def test_installed_but_not_running_app_says_so(backend):
    """The Gemini repro: label given, app installed, no process running."""
    device = FakeDevice(
        enumerated=[FakeProcess("init", 1), FakeProcess("logd", 2), FakeProcess("vold", 3)],
        apps=[FakeApp(GEMINI, "Gemini", pid=0), FakeApp("com.android.chrome", "Chrome", pid=3100)],
    )

    with pytest.raises(ProcessNotFoundError) as excinfo:
        backend.attach(device, "Gemini")

    msg = str(excinfo.value)
    assert "installed" in msg and "not running" in msg
    assert GEMINI in msg
    assert "-s" in msg and f"tlsLibHunter -m -s {GEMINI}" in msg
    assert "init" not in msg and "logd" not in msg
    assert device.attach_calls == ["Gemini"]


def test_several_installed_apps_are_all_listed(backend):
    device = FakeDevice(
        apps=[FakeApp("com.example.notes", "Notes"), FakeApp("com.other.notes", "Notes")],
    )

    with pytest.raises(ProcessNotFoundError) as excinfo:
        backend.attach(device, "Notes")

    msg = str(excinfo.value)
    assert "com.example.notes" in msg and "com.other.notes" in msg


def test_identifier_attaches_to_running_app_and_warns(backend, caplog):
    """The process is named differently from the identifier the user typed."""
    session = FakeSession(4321)
    device = FakeDevice(
        by_target={4321: session},
        enumerated=[FakeProcess("Gemini", 4321)],
        apps=[FakeApp(GEMINI, "Gemini", pid=4321)],
    )

    with caplog.at_level(logging.WARNING, logger="tlslibhunter.backends.frida"):
        assert backend.attach(device, GEMINI) is session

    assert device.attach_calls == [GEMINI, 4321]
    assert f"attached to app 'Gemini' ({GEMINI}, PID 4321)" in caplog.text
    assert "Results describe THAT process" in caplog.text


def test_running_app_attach_failure_raises_attachment_error(backend):
    device = FakeDevice(
        by_target={4321: RuntimeError("access denied")},
        apps=[FakeApp(GEMINI, "Gemini", pid=4321)],
    )

    with pytest.raises(AttachmentError) as excinfo:
        backend.attach(device, GEMINI)

    assert "access denied" in str(excinfo.value)


def test_app_enumeration_failure_still_reports_not_found(backend):
    device = FakeDevice(apps=RuntimeError("not supported"))

    with pytest.raises(ProcessNotFoundError) as excinfo:
        backend.attach(device, "nonexistent-xyz")

    assert "frida-ps" in str(excinfo.value)


def test_spawn_resolves_label_to_identifier(backend):
    session = FakeSession(5000)
    device = FakeDevice(by_target={5000: session}, apps=[FakeApp(GEMINI, "Gemini")])

    assert backend.spawn(device, "Gemini") is session

    assert device.spawn_calls == [[GEMINI]]
    assert device.resumed == [5000]


def test_spawn_keeps_identifier_unchanged(backend):
    session = FakeSession(5000)
    device = FakeDevice(by_target={5000: session}, apps=[FakeApp(GEMINI, "Gemini")])

    assert backend.spawn(device, GEMINI) is session

    assert device.spawn_calls == [[GEMINI]]


def test_spawn_uses_raw_target_when_app_enumeration_fails(backend):
    """Desktop devices cannot enumerate apps -- spawn the binary as given."""
    session = FakeSession(5000)
    device = FakeDevice(by_target={5000: session}, apps=RuntimeError("not supported"))

    assert backend.spawn(device, "/usr/bin/curl") is session

    assert device.spawn_calls == [["/usr/bin/curl"]]


def test_spawn_refuses_ambiguous_label(backend):
    device = FakeDevice(apps=[FakeApp("com.example.notes", "Notes"), FakeApp("com.other.notes", "Notes")])

    with pytest.raises(ProcessNotFoundError) as excinfo:
        backend.spawn(device, "Notes")

    assert "ambiguous" in str(excinfo.value)
    assert device.spawn_calls == []


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


# ---------------------------------------------------------------------------
# Frida attach timeouts are reported as Frida-level failures
# ---------------------------------------------------------------------------

FROZEN_TIMEOUT = "unexpectedly timed out while waiting for stop from process with PID 3934"


class IdentifiedDevice(FakeDevice):
    """FakeDevice that carries a frida-style ``id`` and supports get_process()."""

    id = "emulator-5554"

    def get_process(self, name):
        for proc in self._enumerated:
            if proc.name == name:
                return proc
        raise FridaProcessNotFoundError(f"unable to find process with name '{name}'")


def test_pid_target_timeout_raises_attach_timeout_error(backend):
    device = FakeDevice(by_target={3934: FakeTimedOutError(FROZEN_TIMEOUT)})

    with pytest.raises(AttachTimeoutError) as excinfo:
        backend.attach(device, 3934)

    err = excinfo.value
    assert isinstance(err, AttachmentError)
    assert err.pid == 3934
    assert err.target == 3934
    assert "Frida" in str(err)
    assert "not a tlsLibHunter bug" in str(err)
    assert "-D" not in str(err)  # FakeDevice has no id


def test_exact_name_timeout_resolves_pid_via_get_process(backend):
    device = IdentifiedDevice(
        by_target={"Gemini": FakeTimedOutError("unexpectedly timed out")},
        enumerated=[FakeProcess("Gemini", 3934)],
    )

    with pytest.raises(AttachTimeoutError) as excinfo:
        backend.attach(device, "Gemini")

    err = excinfo.value
    assert err.pid == 3934
    assert err.target == "Gemini"
    assert "(PID 3934)" in str(err)
    assert "frida -D emulator-5554 Gemini" in str(err)
    # A timeout must not trigger the loose name-match fallback.
    assert device.attach_calls == ["Gemini"]


def test_exact_name_timeout_parses_pid_from_frida_message(backend):
    device = FakeDevice(by_target={"Gemini": FakeTimedOutError(FROZEN_TIMEOUT)})

    with pytest.raises(AttachTimeoutError) as excinfo:
        backend.attach(device, "Gemini")

    assert excinfo.value.pid == 3934
    assert "Frida" in str(excinfo.value)


def test_exact_name_timeout_without_pid_omits_it(backend):
    device = FakeDevice(by_target={"Gemini": FakeTimedOutError("unexpectedly timed out")})

    with pytest.raises(AttachTimeoutError) as excinfo:
        backend.attach(device, "Gemini")

    assert excinfo.value.pid is None
    assert "(PID" not in str(excinfo.value)


def test_app_path_timeout_raises_attach_timeout_error_with_app_pid(backend):
    device = FakeDevice(
        by_target={4321: FakeTimedOutError("unexpectedly timed out")},
        apps=[FakeApp(GEMINI, "Gemini", pid=4321)],
    )

    with pytest.raises(AttachTimeoutError) as excinfo:
        backend.attach(device, GEMINI)

    err = excinfo.value
    assert isinstance(err, AttachmentError)
    assert err.pid == 4321
    assert "Frida" in str(err)


def test_timeout_class_missing_from_frida_falls_back_to_generic_error(backend, monkeypatch):
    class FridaWithoutTimedOut:
        ProcessNotFoundError = FridaProcessNotFoundError
        NotSupportedError = FakeNotSupportedError
        PermissionDeniedError = FakePermissionDeniedError

    monkeypatch.setattr(frida_backend, "_import_frida", lambda: FridaWithoutTimedOut)
    device = FakeDevice(by_target={3934: FakeTimedOutError(FROZEN_TIMEOUT)})

    with pytest.raises(AttachmentError) as excinfo:
        backend.attach(device, 3934)

    assert not isinstance(excinfo.value, AttachTimeoutError)


# frida 17.26+ reports a frozen process as ``TransportError: timeout was reached``.
TRANSPORT_TIMEOUT = "timeout was reached"


def test_pid_target_transport_timeout_raises_attach_timeout_error(backend):
    device = FakeDevice(by_target={6818: FakeTransportError(TRANSPORT_TIMEOUT)})

    with pytest.raises(AttachTimeoutError) as excinfo:
        backend.attach(device, 6818)

    assert excinfo.value.pid == 6818
    assert excinfo.value.target == 6818
    assert "Frida" in str(excinfo.value)


def test_exact_name_transport_timeout_raises_attach_timeout_error(backend):
    device = IdentifiedDevice(
        by_target={"Gemini": FakeTransportError(TRANSPORT_TIMEOUT)},
        enumerated=[FakeProcess("Gemini", 6818)],
    )

    with pytest.raises(AttachTimeoutError) as excinfo:
        backend.attach(device, "Gemini")

    assert excinfo.value.pid == 6818
    assert excinfo.value.target == "Gemini"
    # A timeout must not trigger the loose name-match fallback.
    assert device.attach_calls == ["Gemini"]


def test_app_path_transport_timeout_raises_attach_timeout_error(backend):
    device = FakeDevice(
        by_target={6818: FakeTransportError(TRANSPORT_TIMEOUT)},
        apps=[FakeApp(GEMINI, "Gemini", pid=6818)],
    )

    with pytest.raises(AttachTimeoutError) as excinfo:
        backend.attach(device, GEMINI)

    assert excinfo.value.pid == 6818


def test_pid_target_non_timeout_transport_error_is_plain_attachment_error(backend):
    device = FakeDevice(by_target={6818: FakeTransportError("connection closed")})

    with pytest.raises(AttachmentError) as excinfo:
        backend.attach(device, 6818)

    assert not isinstance(excinfo.value, AttachTimeoutError)
    assert "connection closed" in str(excinfo.value)


def test_exact_name_non_timeout_transport_error_is_plain_attachment_error(backend):
    device = FakeDevice(by_target={"Gemini": FakeTransportError("connection closed")})

    with pytest.raises(AttachmentError) as excinfo:
        backend.attach(device, "Gemini")

    assert not isinstance(excinfo.value, AttachTimeoutError)
    assert "connection closed" in str(excinfo.value)


def test_is_attach_timeout_classification():
    assert frida_backend._is_attach_timeout(FakeFrida, FakeTimedOutError("x"))
    assert frida_backend._is_attach_timeout(FakeFrida, FakeTransportError("Timeout was reached"))
    assert not frida_backend._is_attach_timeout(FakeFrida, FakeTransportError("connection closed"))
    assert not frida_backend._is_attach_timeout(FakeFrida, RuntimeError("timeout was reached"))
