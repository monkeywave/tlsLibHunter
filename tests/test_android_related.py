"""Tests for discovering Android processes related to the attached target.

Samples are taken from a real device where the Gemini app
(com.google.android.apps.bard) hands its UI to the Google app's :search process.
"""

import logging

import pytest

from tlslibhunter.config import HunterConfig
from tlslibhunter.hunter import TLSLibHunter
from tlslibhunter.utils import android_related as ar
from tlslibhunter.utils.android_related import ProcessEntry

MODULE_ADB = "tlslibhunter.utils.android_related.adb_shell"
BARD = "com.google.android.apps.bard"
GSA = "com.google.android.googlequicksearchbox"

PS_SAMPLE = """\
  PID   UID NAME
    1     0 init
  568 10156 com.google.android.googlequicksearchbox:search
 1031  1000 android.hardware.camera.provider@2.7-service-google
 5875 10156 com.google.android.googlequicksearchbox:interactor
 6818 10301 com.google.android.apps.bard
13022 99078 com.google.android.webview:sandboxed_process0:org.chromium.content.app.SandboxedProcessService0:0
18860 10208 com.google.android.apps.nexuslauncher
19016 10162 com.google.android.gms
26820 10156 com.google.android.googlequicksearchbox:googleapp
29254  1000 com.google.SSRestartDetector
"""

DUMPSYS_MODERN = """\
  RootWindowContainer:
    topResumedActivity=ActivityRecord{ca91732 u0 com.google.android.googlequicksearchbox/com.google.android.apps.search.assistant.surfaces.voice.robin.main.MainActivity t2241}
  ResumedActivity: ActivityRecord{ca91732 u0 com.google.android.googlequicksearchbox/com.google.android.apps.search.assistant.surfaces.voice.robin.main.MainActivity t2241}
"""  # noqa: E501 (verbatim device output)

DUMPSYS_LEGACY = """\
  Stack #1:
    mResumedActivity: ActivityRecord{4f2b1a u0 com.example.app/.MainActivity t12}
"""


def gsa_procs():
    return [
        ProcessEntry(568, 10156, f"{GSA}:search"),
        ProcessEntry(5875, 10156, f"{GSA}:interactor"),
        ProcessEntry(26820, 10156, f"{GSA}:googleapp"),
    ]


class FakeAdb:
    """Answers adb_shell calls by command substring and records them."""

    def __init__(self, responses):
        self.responses = responses
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


class TestParsePsOutput:
    def test_parses_rows_and_skips_header(self):
        procs = ar.parse_ps_output(PS_SAMPLE)
        assert procs[0] == ProcessEntry(1, 0, "init")
        assert ProcessEntry(568, 10156, f"{GSA}:search") in procs
        assert len(procs) == 10

    def test_keeps_names_with_colons(self):
        procs = ar.parse_ps_output(PS_SAMPLE)
        assert any(p.name.endswith("SandboxedProcessService0:0") for p in procs)

    @pytest.mark.parametrize("text", ["", "garbage", "  PID   UID NAME", "abc 10 x", "12"])
    def test_malformed_input_yields_nothing(self, text):
        assert ar.parse_ps_output(text) == []


class TestParseForegroundPackage:
    def test_modern_top_resumed_activity(self):
        assert ar.parse_foreground_package(DUMPSYS_MODERN) == GSA

    def test_legacy_m_resumed_activity(self):
        assert ar.parse_foreground_package(DUMPSYS_LEGACY) == "com.example.app"

    def test_top_resumed_wins_over_others(self):
        text = DUMPSYS_LEGACY + "topResumedActivity=ActivityRecord{1 u0 com.top.app/.A t1}\n"
        assert ar.parse_foreground_package(text) == "com.top.app"

    @pytest.mark.parametrize("text", ["", "topResumedActivity=null", "mResumedActivity: null"])
    def test_no_resumed_activity(self, text):
        assert ar.parse_foreground_package(text) is None


class TestPackageHelpers:
    @pytest.mark.parametrize(
        "name,expected",
        [(BARD, BARD), (f"{GSA}:search", GSA), ("init", "init")],
    )
    def test_package_of(self, name, expected):
        assert ar.package_of(name) == expected

    @pytest.mark.parametrize(
        "name,expected",
        [(GSA, True), (f"{GSA}:search", True), (f"{GSA}x", False), ("com.google.android", False)],
    )
    def test_belongs_to_package(self, name, expected):
        assert ar.belongs_to_package(name, GSA) is expected

    @pytest.mark.parametrize(
        "foreground,target,expected",
        [
            (GSA, BARD, True),
            (BARD, BARD, False),
            (None, BARD, False),
            (GSA, None, False),
            ("com.android.systemui", BARD, False),
            ("com.google.android.apps.nexuslauncher", BARD, False),
        ],
    )
    def test_is_plausible_delegate(self, foreground, target, expected):
        assert ar.is_plausible_delegate(foreground, target) is expected


class TestBuildRelatedProcesses:
    def test_gemini_trampoline_to_gsa(self):
        related = ar.build_related_processes(ar.parse_ps_output(PS_SAMPLE), 6818, None, GSA)
        assert related.target_package == BARD
        assert related.target_pid == 6818
        assert related.sibling_processes == []
        assert related.foreground_package == GSA
        assert related.delegate_processes == gsa_procs()
        assert related.has_delegate
        assert related.related_pids == [568, 5875, 26820]

    def test_siblings_by_package_and_uid(self):
        related = ar.build_related_processes(ar.parse_ps_output(PS_SAMPLE), 568, None, GSA)
        assert related.target_package == GSA
        assert [p.pid for p in related.sibling_processes] == [5875, 26820]
        assert not related.has_delegate

    def test_system_uid_is_not_used_for_siblings(self):
        related = ar.build_related_processes(ar.parse_ps_output(PS_SAMPLE), 29254, None, None)
        assert related.sibling_processes == []

    def test_falls_back_to_package_when_pid_unknown(self):
        related = ar.build_related_processes(ar.parse_ps_output(PS_SAMPLE), None, GSA, None)
        assert related.target_package == GSA
        assert [p.pid for p in related.sibling_processes] == [568, 5875, 26820]

    def test_unidentifiable_target(self):
        assert ar.build_related_processes(ar.parse_ps_output(PS_SAMPLE), 4242, None, GSA) is None

    def test_launcher_in_foreground_is_not_a_delegate(self):
        launcher = "com.google.android.apps.nexuslauncher"
        related = ar.build_related_processes(ar.parse_ps_output(PS_SAMPLE), 6818, None, launcher)
        assert related.delegate_processes == []


class TestFindRelatedProcesses:
    def test_queries_device_with_serial(self, monkeypatch):
        fake = install(monkeypatch, [("ps -A", (0, PS_SAMPLE)), ("dumpsys", (0, DUMPSYS_MODERN))])
        related = ar.find_related_processes("SER123", target_pid=6818)
        assert related.delegate_processes == gsa_procs()
        assert all(serial == "SER123" for _, serial in fake.calls)

    def test_ps_failure_returns_none(self, monkeypatch):
        install(monkeypatch, [("ps -A", (1, "error: device offline"))])
        assert ar.find_related_processes("SER123", target_pid=6818) is None

    def test_dumpsys_failure_keeps_siblings(self, monkeypatch):
        install(monkeypatch, [("ps -A", (0, PS_SAMPLE)), ("dumpsys", (1, "boom"))])
        related = ar.find_related_processes(None, target_pid=568)
        assert related.foreground_package is None
        assert [p.pid for p in related.sibling_processes] == [5875, 26820]


class TestFormatRelatedHint:
    def test_delegate_warning(self):
        related = ar.RelatedProcesses(BARD, 6818, [], GSA, gsa_procs())
        level, message = ar.format_related_hint(related)
        assert level == logging.WARNING
        assert message == (
            f"Foreground UI of '{BARD}' is hosted by '{GSA}' "
            "(PIDs 568 :search, 5875 :interactor, 26820 :googleapp). "
            "TLS traffic is likely there — scan those PIDs or use --all-processes."
        )

    def test_siblings_info(self):
        related = ar.RelatedProcesses(GSA, 568, gsa_procs()[1:])
        level, message = ar.format_related_hint(related)
        assert level == logging.INFO
        assert "PIDs 5875 :interactor, 26820 :googleapp" in message
        assert "--all-processes" in message

    def test_same_uid_sibling_with_other_name_is_labelled_in_full(self):
        related = ar.RelatedProcesses(
            "com.google.android.gms", 19016, [ProcessEntry(1, 10162, "com.google.process.gservices")]
        )
        _, message = ar.format_related_hint(related)
        assert "1 com.google.process.gservices" in message

    @pytest.mark.parametrize("related", [None, ar.RelatedProcesses(BARD, 6818)])
    def test_nothing_to_report(self, related):
        assert ar.format_related_hint(related) is None


class FakeDevice:
    id = "SER123"


class FakeBackend:
    def __init__(self, platform="android"):
        self.platform = platform

    def get_device(self, **kwargs):
        return FakeDevice()

    def get_device_platform(self, device):
        return self.platform

    def attach(self, device, target, timeout=10):
        return object()

    def describe_session(self, device, session):
        return {"pid": 6818, "name": "Gemini"}


def _initialize(monkeypatch, platform="android", target="Gemini"):
    monkeypatch.setattr("tlslibhunter.backends.get_backend", lambda name: FakeBackend(platform))
    hunter = TLSLibHunter.from_config(HunterConfig(target=target, mobile=True))
    hunter._initialize()
    return hunter


class TestHunterHint:
    def test_warns_about_delegate_after_attach(self, monkeypatch, caplog):
        fake = install(monkeypatch, [("ps -A", (0, PS_SAMPLE)), ("dumpsys", (0, DUMPSYS_MODERN))])
        with caplog.at_level(logging.INFO, logger="tlslibhunter"):
            hunter = _initialize(monkeypatch)
        assert hunter._initialized
        assert fake.calls[0][1] == "SER123"
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any(f"hosted by '{GSA}'" in w for w in warnings)

    def test_adb_errors_never_break_initialize(self, monkeypatch):
        def explode(cmd, serial=None):
            raise RuntimeError("adb exploded")

        monkeypatch.setattr(MODULE_ADB, explode)
        assert _initialize(monkeypatch)._initialized

    def test_non_android_platform_skips_lookup(self, monkeypatch):
        fake = install(monkeypatch, [])
        _initialize(monkeypatch, platform="linux", target="firefox")
        assert fake.calls == []
