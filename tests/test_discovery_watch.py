"""Tests for ``discover --watch``: the pure diff, the sampling loop and the CLI."""

import json
import threading

import pytest

from tests.conftest import FixtureRunner
from tlslibhunter import discover_cli
from tlslibhunter.discovery import engine, watch
from tlslibhunter.discovery.profile import Candidate

BARD = "com.google.android.apps.bard"
GSA = "com.google.android.googlequicksearchbox"
SEARCH = f"{GSA}:search"


def cand(process=SEARCH, pid=100, evidence=("foreground_host",), role="delegate", package=GSA):
    return Candidate(pid=pid, process=process, package=package, uid=10156, role=role, evidence=list(evidence))


def keyed(*cands):
    return watch.by_process(list(cands))


class TestDiffCandidates:
    def test_unchanged_sample_has_no_events(self):
        assert watch.diff_candidates(keyed(cand()), keyed(cand())) == []

    def test_new_process_name_is_added(self):
        [event] = watch.diff_candidates({}, keyed(cand()), ts=5.0)
        assert (event.event, event.pid, event.process, event.evidence, event.ts) == (
            "process_added",
            100,
            SEARCH,
            ["foreground_host"],
            5.0,
        )

    def test_same_name_new_pid_is_restarted(self):
        [event] = watch.diff_candidates(keyed(cand()), keyed(cand(pid=200, evidence=["net:tcp:443"])))
        assert (event.event, event.pid, event.evidence) == ("process_restarted", 200, ["net:tcp:443"])

    def test_missing_name_is_gone_with_last_pid(self):
        [event] = watch.diff_candidates(keyed(cand()), {})
        assert (event.event, event.pid, event.process) == ("process_gone", 100, SEARCH)

    def test_new_evidence_on_same_pid_lists_only_the_new_items(self):
        current = keyed(cand(evidence=["foreground_host", "net:udp-connected:443"]))
        [event] = watch.diff_candidates(keyed(cand()), current)
        assert (event.event, event.evidence) == ("evidence_added", ["net:udp-connected:443"])

    def test_lost_evidence_alone_is_no_event(self):
        assert watch.diff_candidates(keyed(cand(evidence=["a", "b"])), keyed(cand(evidence=["a"]))) == []

    def test_mixed_changes_in_one_sample(self):
        previous = keyed(cand(), cand(process=BARD, pid=1, role="target", package=BARD))
        current = keyed(cand(pid=101), cand(process=f"{GSA}:googleapp", pid=7))
        events = [(e.event, e.process) for e in watch.diff_candidates(previous, current)]
        assert events == [
            ("process_restarted", SEARCH),
            ("process_added", f"{GSA}:googleapp"),
            ("process_gone", BARD),
        ]


class TestAdvanceState:
    def test_evidence_accumulates_for_same_pid(self):
        state = watch.advance_state(keyed(cand(evidence=["a"])), keyed(cand(evidence=["b"])))
        assert state[SEARCH].evidence == ["a", "b"]

    def test_restart_resets_evidence(self):
        state = watch.advance_state(keyed(cand(evidence=["a"])), keyed(cand(pid=2, evidence=["b"])))
        assert state[SEARCH].evidence == ["b"]

    def test_gone_processes_are_dropped(self):
        assert watch.advance_state(keyed(cand()), {}) == {}

    def test_flapping_evidence_is_reported_once(self):
        state = watch.advance_state(keyed(cand(evidence=["a", "b"])), keyed(cand(evidence=["a"])))
        assert watch.diff_candidates(state, keyed(cand(evidence=["a", "b"]))) == []


class TestWatchEventJson:
    def test_line_shape(self):
        event = watch.WatchEvent("process_added", 1, "p\nx", GSA, "delegate", ["e"], 2.5)
        line = event.to_json_line()
        assert "\n" not in line
        assert json.loads(line) == {
            "schema": "tlslibhunter.watch/1",
            "event": "process_added",
            "pid": 1,
            "process": "p\nx",
            "package": GSA,
            "role": "delegate",
            "evidence": ["e"],
            "ts": 2.5,
        }


class FakeSampler:
    """Replaces ``collect_candidates``: returns the next snapshot, sets ``stop`` after the last."""

    def __init__(self, snapshots, stop):
        self.snapshots = list(snapshots)
        self.stop = stop
        self.calls = []

    def __call__(self, runner, package, root, probe_evidence=None):
        self.calls.append((package, root, probe_evidence))
        result = self.snapshots.pop(0)
        if not self.snapshots:
            self.stop.set()
        return result


class TestWatchLoop:
    def run(self, monkeypatch, snapshots, stop=None, **kwargs):
        stop = stop or threading.Event()
        sampler = FakeSampler(snapshots, stop)
        monkeypatch.setattr(watch, "collect_candidates", sampler)
        events = list(watch.watch(lambda cmd: "", BARD, 0, stop, root=False, clock=lambda: 9.0, **kwargs))
        return events, sampler

    def test_successive_snapshots_yield_churn_events(self, monkeypatch):
        snapshots = [
            [cand()],
            [cand(pid=200)],
            [cand(pid=200, evidence=["foreground_host", "net:tcp:443"])],
            [],
        ]
        events, sampler = self.run(monkeypatch, snapshots)
        assert [(e.event, e.pid) for e in events] == [
            ("process_added", 100),
            ("process_restarted", 200),
            ("evidence_added", 200),
            ("process_gone", 200),
        ]
        assert all(e.ts == 9.0 for e in events) and len(sampler.calls) == 4

    def test_stop_already_set_still_takes_one_sample(self, monkeypatch):
        stop = threading.Event()
        stop.set()
        events, sampler = self.run(monkeypatch, [[cand()]], stop=stop)
        assert [e.event for e in events] == ["process_added"] and len(sampler.calls) == 1

    def test_probe_evidence_and_root_are_passed_through(self, monkeypatch):
        _, sampler = self.run(monkeypatch, [[]], probe_evidence={GSA: ["handoff:binder:x"]})
        assert sampler.calls == [(BARD, False, {GSA: ["handoff:binder:x"]})]

    def test_invalid_package_is_rejected(self):
        with pytest.raises(ValueError):
            next(watch.watch(lambda cmd: "", "bad;pkg", 1, threading.Event(), root=False))

    def test_fixture_device_first_sample_adds_gsa_search(self):
        stop = threading.Event()
        events = watch.watch(FixtureRunner(), BARD, 0, stop)
        first = [next(events)]
        stop.set()
        first += list(events)
        assert ("process_added", SEARCH) in {(e.event, e.process) for e in first}


class TestCollectCandidates:
    def test_matches_single_sample_discovery(self):
        merged = engine.sample_candidates(FixtureRunner(), BARD, True, 1, 0)
        assert engine.collect_candidates(FixtureRunner(), BARD, True) == merged


class TestWatchCli:
    def parse(self, argv):
        return discover_cli.build_discover_parser().parse_args(argv)

    def test_watch_flag_and_optional_duration(self):
        args = self.parse([BARD, "--watch", "--interval", "0.5"])
        assert (args.watch, args.duration, args.interval) == (True, None, 0.5)
        assert self.parse([BARD, "--watch", "--duration", "20"]).duration == 20.0

    def test_stop_event_without_duration_stays_clear(self):
        assert not discover_cli.stop_event_for(None).is_set()

    def test_stop_event_with_duration_is_set(self):
        assert discover_cli.stop_event_for(0).wait(2)

    def test_run_discover_watch_prints_json_lines(self, capsys):
        args = self.parse([BARD, "--watch", "--duration", "0", "--interval", "0"])
        assert discover_cli.run_discover(args, runner=FixtureRunner()) == 0
        lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        assert lines and all(line["schema"] == "tlslibhunter.watch/1" for line in lines)

    def test_ctrl_c_exits_cleanly(self, capsys, monkeypatch):
        def interrupted(*args, **kwargs):
            yield watch.WatchEvent("process_added", 1, SEARCH, GSA, "delegate")
            raise KeyboardInterrupt

        monkeypatch.setattr(watch, "watch", interrupted)
        args = self.parse([BARD, "--watch"])
        stop = threading.Event()
        assert discover_cli.run_watch(FixtureRunner(), BARD, args, stop=stop) == 0
        out = capsys.readouterr()
        assert json.loads(out.out)["event"] == "process_added" and "Stopped" in out.err
        assert stop.is_set()
