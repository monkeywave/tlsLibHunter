"""Tests for --all-processes orchestration (target + related Android processes)."""

import json
import logging

from tlslibhunter.backends.base import AttachTimeoutError
from tlslibhunter.cli import build_parser, main
from tlslibhunter.config import HunterConfig
from tlslibhunter.multi_process import (
    ProcessScanOutcome,
    config_for_pid,
    related_pids_for,
    safe_scan,
    scan_all_processes,
    summary_rows,
)
from tlslibhunter.output import get_formatter
from tlslibhunter.scanner.results import DetectedLibrary, ScanResult
from tlslibhunter.utils.android_related import ProcessEntry, RelatedProcesses

BARD = "com.google.android.apps.bard"
GSA = "com.google.android.googlequicksearchbox"


def _result(name, pid, libs, platform="android"):
    return ScanResult(
        target=name,
        platform=platform,
        libraries=[DetectedLibrary(name=lib, path=f"/x/{lib}") for lib in libs],
        attached_process=name,
        attached_pid=pid,
    )


def _related(target_pid=6818):
    return RelatedProcesses(
        target_package=BARD,
        target_pid=target_pid,
        sibling_processes=[ProcessEntry(7000, 10301, f"{BARD}:remote")],
        foreground_package=GSA,
        delegate_processes=[ProcessEntry(568, 10156, f"{GSA}:search"), ProcessEntry(26820, 10156, f"{GSA}:googleapp")],
    )


def _fake_find_related(related):
    calls = []

    def find(serial, pid, package):
        calls.append((serial, pid, package))
        return related

    find.calls = calls
    return find


class TestConfigForPid:
    def test_attaches_by_pid_and_keeps_options(self):
        base = HunterConfig(target="Gemini", serial="S1", unfreeze=True, spawn=True, list_only=True, debug=True)
        cfg = config_for_pid(base, 568)
        assert cfg.target == "568"
        assert cfg.spawn is False
        assert (cfg.serial, cfg.unfreeze, cfg.list_only, cfg.debug) == ("S1", True, True, True)
        assert cfg.output_dir is None
        assert cfg.effective_output_dir == "./tls_libs_568"

    def test_output_dir_gets_per_pid_subdirectory(self, tmp_path):
        cfg = config_for_pid(HunterConfig(target="Gemini", output_dir=str(tmp_path)), 568)
        assert cfg.output_dir == str(tmp_path / "568")

    def test_does_not_mutate_original(self):
        base = HunterConfig(target="Gemini")
        config_for_pid(base, 1)
        assert base.target == "Gemini"


class TestRelatedPids:
    def test_delegates_first_then_siblings(self):
        outcome = ProcessScanOutcome(target="Gemini", result=_result(BARD, 6818, []))
        find = _fake_find_related(_related())
        pids = related_pids_for(outcome, HunterConfig(target="Gemini", serial="S1"), find)
        assert pids == [568, 26820, 7000]
        assert find.calls == [("S1", 6818, None)]

    def test_target_pid_is_excluded(self):
        related = _related()
        related.sibling_processes.append(ProcessEntry(6818, 10301, BARD))
        outcome = ProcessScanOutcome(target="Gemini", result=_result(BARD, 6818, []))
        assert 6818 not in related_pids_for(outcome, HunterConfig(target="Gemini"), _fake_find_related(related))

    def test_package_target_is_passed_for_lookup(self):
        find = _fake_find_related(None)
        outcome = ProcessScanOutcome(target=BARD, result=_result(BARD, 6818, []))
        assert related_pids_for(outcome, HunterConfig(target=BARD), find) == []
        assert find.calls == [(None, 6818, BARD)]

    def test_failed_target_uses_pid_from_error(self):
        find = _fake_find_related(_related())
        outcome = ProcessScanOutcome(target="Gemini", error="timeout", pid=6818)
        assert related_pids_for(outcome, HunterConfig(target="Gemini", mobile=True), find) == [568, 26820, 7000]

    def test_non_android_warns_and_returns_nothing(self, caplog):
        find = _fake_find_related(_related())
        outcome = ProcessScanOutcome(target="firefox", result=_result("firefox", 1, [], platform="linux"))
        with caplog.at_level(logging.WARNING, logger="tlslibhunter"):
            assert related_pids_for(outcome, HunterConfig(target="firefox"), find) == []
        assert "only supported on Android" in caplog.text
        assert find.calls == []

    def test_lookup_exception_is_contained(self):
        def boom(*_):
            raise RuntimeError("adb gone")

        outcome = ProcessScanOutcome(target="Gemini", result=_result(BARD, 6818, []))
        assert related_pids_for(outcome, HunterConfig(target="Gemini"), boom) == []


class TestFailureIsolation:
    def test_safe_scan_records_error_and_pid(self):
        def scan_one(cfg):
            raise AttachTimeoutError("timed out", target=cfg.target, pid=568)

        outcome = safe_scan(scan_one, HunterConfig(target="568"))
        assert not outcome.succeeded
        assert outcome.error == "timed out"
        assert outcome.pid == 568

    def test_one_failure_does_not_abort_remaining_scans(self):
        scanned = []

        def scan_one(cfg):
            scanned.append(cfg.target)
            if cfg.target == "568":
                raise PermissionError("isolated process")
            pid = 6818 if cfg.target == "Gemini" else int(cfg.target)
            return ProcessScanOutcome(target=cfg.target, result=_result(cfg.target, pid, ["libssl.so"]))

        outcomes = scan_all_processes(HunterConfig(target="Gemini"), scan_one, _fake_find_related(_related()))
        assert scanned == ["Gemini", "568", "26820", "7000"]
        assert [o.succeeded for o in outcomes] == [True, False, True, True]
        assert outcomes[1].error == "isolated process"

    def test_no_related_processes_scans_only_target(self):
        def scan_one(cfg):
            return ProcessScanOutcome(target=cfg.target, result=_result(BARD, 6818, []))

        outcomes = scan_all_processes(HunterConfig(target="Gemini"), scan_one, _fake_find_related(None))
        assert len(outcomes) == 1


class TestScanOneProcessKeepsPid:
    def test_failure_after_attach_reports_hunter_pid(self, monkeypatch):
        from tlslibhunter.cli import _scan_one_process
        from tlslibhunter.hunter import TLSLibHunter

        class _AttachedThenFails:
            attached_pid = 13895

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def scan(self):
                raise RuntimeError("the connection is closed")

        monkeypatch.setattr(TLSLibHunter, "from_config", classmethod(lambda cls, cfg: _AttachedThenFails()))
        outcome = _scan_one_process(HunterConfig(target="Gemini", list_only=True), get_formatter("plain"), True)
        assert outcome.error == "the connection is closed"
        assert outcome.process_pid == 13895


class TestSummary:
    def _outcomes(self):
        return [
            ProcessScanOutcome(target="Gemini", result=_result(BARD, 6818, ["libssl.so", "libhttpengine.so"])),
            ProcessScanOutcome(target="568", error="timed out\nhint line", pid=568),
            ProcessScanOutcome(target="7000", result=_result(f"{BARD}:remote", 7000, [])),
        ]

    def test_summary_rows(self):
        assert summary_rows(self._outcomes()) == [
            (BARD, "6818", "libssl.so, libhttpengine.so"),
            ("568", "568", "ERROR: timed out"),
            (f"{BARD}:remote", "7000", "none"),
        ]

    def test_incomplete_scan_is_flagged(self):
        result = _result("gsa:googleapp", 12274, ["libssl.so"])
        result.errors = ["Scan stopped: target process died"]
        rows = summary_rows([ProcessScanOutcome(target="12274", result=result)])
        assert rows == [("gsa:googleapp", "12274", "libssl.so (INCOMPLETE: 1 error(s))")]

    def test_table_and_plain_summaries_list_every_process(self):
        for fmt in ("table", "plain"):
            text = get_formatter(fmt).format_process_summary("Gemini", self._outcomes())
            assert "libhttpengine.so" in text
            assert "ERROR: timed out" in text
            assert "7000" in text

    def test_json_summary_is_one_combined_document(self):
        doc = json.loads(get_formatter("json").format_process_summary("Gemini", self._outcomes()))
        assert doc["target"] == "Gemini"
        assert [p["pid"] for p in doc["processes"]] == [6818, 568, 7000]
        assert doc["processes"][0]["scan"]["tls_library_count"] == 2
        assert doc["processes"][1]["scan"] is None
        assert doc["processes"][1]["error"].startswith("timed out")


class TestCliWiring:
    def test_flag_parses_and_defaults_false(self):
        assert build_parser().parse_args(["Gemini", "--all-processes"]).all_processes is True
        assert build_parser().parse_args(["Gemini"]).all_processes is False

    def test_main_routes_to_orchestrator_and_prints_summary(self, monkeypatch, capsys):
        captured = {}

        def fake_scan_all(config, scan_one, find_related=None):
            captured["config"] = config
            return [ProcessScanOutcome(target="Gemini", result=_result(BARD, 6818, ["libssl.so"]))]

        monkeypatch.setattr("tlslibhunter.multi_process.scan_all_processes", fake_scan_all)
        assert main(["Gemini", "--serial", "S1", "--all-processes", "-l", "-f", "plain"]) == 0
        assert captured["config"].all_processes is True
        assert "All processes related to 'Gemini'" in capsys.readouterr().out

    def test_main_returns_1_when_every_scan_failed(self, monkeypatch):
        monkeypatch.setattr(
            "tlslibhunter.multi_process.scan_all_processes",
            lambda config, scan_one, find_related=None: [ProcessScanOutcome(target="Gemini", error="x")],
        )
        assert main(["Gemini", "--all-processes", "-l"]) == 1


class TestHintSuppressed:
    def test_hint_not_logged_with_all_processes(self, monkeypatch):
        from tlslibhunter.hunter import TLSLibHunter
        from tlslibhunter.utils import android_related

        monkeypatch.setattr(android_related, "find_related_processes", lambda *a: _related())
        hunter = TLSLibHunter.from_config(HunterConfig(target="Gemini", all_processes=True))
        hunter._platform = "android"
        hunter._attached = {"pid": 6818}
        logged = []
        monkeypatch.setattr("tlslibhunter.hunter.logger.log", lambda *a: logged.append(a))
        hunter._hint_related_android_processes()
        assert logged == []
