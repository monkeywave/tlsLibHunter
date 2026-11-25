"""``discover --watch``: follow process churn (restarts, new delegates) without Frida.

Each sample is the engine's single-snapshot collection
(:func:`~tlslibhunter.discovery.engine.collect_candidates`). Consecutive samples
are compared per process name by the pure :func:`diff_candidates`, which turns
the difference into :class:`WatchEvent` records (schema ``tlslibhunter.watch/1``).

Process, package and evidence strings come from the device; they are emitted
only through ``json.dumps``, which escapes control characters, so one event
always stays one line.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from typing import Any

from tlslibhunter.discovery.engine import ProbeEvidence, Runner, collect_candidates, detect_root
from tlslibhunter.discovery.profile import Candidate
from tlslibhunter.discovery.topology import validate_package_name

WATCH_SCHEMA = "tlslibhunter.watch/1"

EVENT_PROCESS_ADDED = "process_added"
EVENT_PROCESS_RESTARTED = "process_restarted"
EVENT_PROCESS_GONE = "process_gone"
EVENT_EVIDENCE_ADDED = "evidence_added"

# Known candidates keyed by process name.
CandidateMap = dict[str, Candidate]


@dataclass
class WatchEvent:
    """One change between two samples; ``evidence`` is the new evidence for ``evidence_added``."""

    event: str
    pid: int
    process: str
    package: str
    role: str
    evidence: list[str] = field(default_factory=list)
    ts: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": WATCH_SCHEMA,
            "event": self.event,
            "pid": self.pid,
            "process": self.process,
            "package": self.package,
            "role": self.role,
            "evidence": list(self.evidence),
            "ts": self.ts,
        }

    def to_json_line(self) -> str:
        return json.dumps(self.to_dict())


def _event(name: str, cand: Candidate, evidence: list[str], ts: float) -> WatchEvent:
    return WatchEvent(name, cand.pid, cand.process, cand.package, cand.role, list(evidence), ts)


def _change_event(previous: Candidate | None, cand: Candidate, ts: float) -> WatchEvent | None:
    """Event for a process present in the current sample, or None if nothing changed."""
    if previous is None:
        return _event(EVENT_PROCESS_ADDED, cand, cand.evidence, ts)
    if previous.pid != cand.pid:
        return _event(EVENT_PROCESS_RESTARTED, cand, cand.evidence, ts)
    new_evidence = [item for item in cand.evidence if item not in previous.evidence]
    return _event(EVENT_EVIDENCE_ADDED, cand, new_evidence, ts) if new_evidence else None


def diff_candidates(previous: CandidateMap, current: CandidateMap, ts: float = 0.0) -> list[WatchEvent]:
    """Events turning ``previous`` into ``current`` (both keyed by process name).

    New name -> ``process_added``; same name, new pid -> ``process_restarted``;
    same pid with evidence not seen before -> ``evidence_added``; name missing
    from ``current`` -> ``process_gone`` (with the last known pid).
    """
    changes = (_change_event(previous.get(name), cand, ts) for name, cand in current.items())
    events = [event for event in changes if event is not None]
    gone = (cand for name, cand in previous.items() if name not in current)
    return events + [_event(EVENT_PROCESS_GONE, cand, cand.evidence, ts) for cand in gone]


def advance_state(previous: CandidateMap, current: CandidateMap) -> CandidateMap:
    """Next known state: evidence accumulates while a process keeps its pid, resets on restart."""
    state: CandidateMap = {}
    for name, cand in current.items():
        before = previous.get(name)
        if before is not None and before.pid == cand.pid:
            cand = replace(cand, evidence=list(dict.fromkeys(before.evidence + cand.evidence)))
        state[name] = cand
    return state


def by_process(candidates: list[Candidate]) -> CandidateMap:
    """Candidates keyed by process name (the last one wins on duplicates)."""
    return {cand.process: cand for cand in candidates}


def watch(
    runner: Runner,
    target_package: str,
    interval: float,
    stop: threading.Event,
    *,
    root: bool | None = None,
    clock: Callable[[], float] = time.time,
    probe_evidence: ProbeEvidence | None = None,
) -> Iterator[WatchEvent]:
    """Yield change events every ``interval`` seconds until ``stop`` is set.

    At least one sample is taken; it reports every candidate as ``process_added``.
    ``stop.wait`` is the sleep, so setting ``stop`` ends the loop without waiting
    out the interval.
    """
    validate_package_name(target_package)
    has_root = detect_root(runner) if root is None else root
    known: CandidateMap = {}
    while True:
        current = by_process(collect_candidates(runner, target_package, has_root, probe_evidence))
        yield from diff_candidates(known, current, clock())
        known = advance_state(known, current)
        if stop.wait(max(interval, 0.0)):
            return
