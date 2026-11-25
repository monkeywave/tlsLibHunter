"""Discovery orchestration: snapshot the device, classify processes, merge samples.

Every device access goes through an injected ``runner`` (``cmd -> stdout``,
``""`` on failure), so the whole pipeline is testable with recorded output.
:func:`make_adb_runner` builds the real runner on top of
:func:`~tlslibhunter.utils.adb.adb_shell` (root commands use ``su -c``, as in
:mod:`tlslibhunter.utils.android_process`).
"""

from __future__ import annotations

import re
import shlex
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace

from tlslibhunter.discovery import sockets
from tlslibhunter.discovery.handoff import (
    OomLink,
    OomProcess,
    delegate_packages,
    parse_oom_adj_sources,
    parse_oom_processes,
    top_activity_pids,
)
from tlslibhunter.discovery.probe import ProbeResult, probe_package_evidence, unmapped_descriptors
from tlslibhunter.discovery.profile import (
    ROLE_DELEGATE,
    ROLE_SDK_SANDBOX,
    ROLE_SHARED_SYSTEM,
    ROLE_SIBLING,
    ROLE_TARGET,
    ROLES,
    Candidate,
    Profile,
    gate_packages_from,
)
from tlslibhunter.discovery.shared_delegates import is_shared_delegate, load_shared_delegates
from tlslibhunter.discovery.text import safe_text
from tlslibhunter.discovery.tls_libs import (
    build_maps_scan_script,
    is_tls_confirmed,
    parse_maps_tls_libs,
    tls_lib_evidence,
)
from tlslibhunter.discovery.topology import (
    SDK_SANDBOX_NAME_SUFFIX,
    parse_pm_packages_uids,
    validate_package_name,
)
from tlslibhunter.discovery.uids import same_app
from tlslibhunter.utils.adb import adb_shell
from tlslibhunter.utils.android_related import (
    _DUMPSYS_COMMAND,
    _PS_COMMAND,
    ProcessEntry,
    is_plausible_delegate,
    package_of,
    parse_foreground_package,
    parse_ps_output,
)

Runner = Callable[[str], str]
# Package -> evidence learned outside the snapshots (``discover --probe``).
ProbeEvidence = dict[str, list[str]]

PM_COMMAND = "pm list packages -U"
OOM_COMMAND = "dumpsys activity oom"
ROOT_CHECK_COMMAND = "su -c id"
FINGERPRINT_COMMAND = "getprop ro.build.fingerprint"
PROC_NET_PROTOCOLS = ("tcp", "tcp6", "udp", "udp6")
# Without root, sockets are only attributable per UID; DNS (53) and DoT (853)
# are mostly resolver traffic, so only 443 counts.
UID_ATTRIBUTED_PORTS = (443,)

EVIDENCE_UID_ATTRIBUTED = "net:uid-attributed"
EVIDENCE_FOREGROUND_HOST = "foreground_host"
EVIDENCE_SAME_UID = "same_uid"
EVIDENCE_OOM_BOUND_BY = "oom_bound_by:"

_VERSION_CODE_RE = re.compile(r"versionCode=(\d+)")


@dataclass
class Snapshot:
    """Device state at one point in time; ``inode_map`` is None without root."""

    processes: list[ProcessEntry] = field(default_factory=list)
    package_uids: dict[str, list[int]] = field(default_factory=dict)
    sockets: list[sockets.SocketEntry] = field(default_factory=list)
    foreground_package: str | None = None
    oom_processes: list[OomProcess] = field(default_factory=list)
    oom_links: list[OomLink] = field(default_factory=list)
    inode_map: dict[int, list[int]] | None = None

    @property
    def root(self) -> bool:
        return self.inode_map is not None


# --------------------------------------------------------------------------- device access


def as_root(cmd: str) -> str:
    """Wrap ``cmd`` (which must not contain single quotes) in ``su -c '...'``."""
    return f"su -c '{cmd}'"


def make_adb_runner(serial: str | None = None) -> Runner:
    """Runner over ``adb shell``; returns ``""`` when the command fails."""

    def run(cmd: str) -> str:
        rc, out = adb_shell(cmd, serial=serial)
        return out if rc == 0 else ""

    return run


def detect_root(runner: Runner) -> bool:
    """True if ``su`` grants uid 0 on the device."""
    return "uid=0" in runner(ROOT_CHECK_COMMAND)


def _read_sockets(runner: Runner, root: bool) -> list[sockets.SocketEntry]:
    entries: list[sockets.SocketEntry] = []
    for protocol in PROC_NET_PROTOCOLS:
        cmd = f"cat /proc/net/{protocol}"
        entries += sockets.parse_proc_net(runner(as_root(cmd) if root else cmd), protocol)
    return entries


def tls_socket_uids(entries: Iterable[sockets.SocketEntry], ports: Iterable[int]) -> set[int]:
    """UIDs owning at least one socket to a remote port in ``ports``."""
    wanted = tuple(ports)
    return {entry.uid for entry in entries if sockets.is_remote_tls_port(entry, wanted)}


def fd_scan_pids(processes: Iterable[ProcessEntry], entries: Iterable[sockets.SocketEntry]) -> list[int]:
    """PIDs worth an fd scan: those whose UID owns remote 443/853 sockets."""
    uids = tls_socket_uids(entries, sockets.DEFAULT_TLS_PORTS)
    return [proc.pid for proc in processes if proc.uid in uids]


def _scan_fds(runner: Runner, pids: list[int]) -> dict[int, list[int]]:
    if not pids:
        return {}
    return sockets.parse_fd_socket_listing(runner(as_root(sockets.build_fd_scan_script(pids))))


def collect_snapshot(runner: Runner, root: bool) -> Snapshot:
    """Read processes, package UIDs, sockets, foreground app and oom bindings once."""
    processes = parse_ps_output(runner(_PS_COMMAND))
    entries = _read_sockets(runner, root)
    oom_text = runner(OOM_COMMAND)
    return Snapshot(
        processes=processes,
        package_uids=parse_pm_packages_uids(runner(PM_COMMAND)),
        sockets=entries,
        foreground_package=parse_foreground_package(runner(_DUMPSYS_COMMAND)),
        oom_processes=parse_oom_processes(oom_text),
        oom_links=parse_oom_adj_sources(oom_text),
        inode_map=_scan_fds(runner, fd_scan_pids(processes, entries)) if root else None,
    )


# --------------------------------------------------------------------------- classification


@dataclass
class _Context:
    """Per-snapshot lookups shared by the classification helpers."""

    snapshot: Snapshot
    target_package: str
    delegates: list[str]
    packages_by_uid: dict[int, list[str]]
    sockets_by_pid: dict[int, list[sockets.SocketEntry]]
    uid_attributed: set[int]
    top_pids: list[int]
    probe_evidence: ProbeEvidence = field(default_factory=dict)


def _packages_by_uid(package_uids: dict[str, list[int]]) -> dict[int, list[str]]:
    by_uid: dict[int, list[str]] = {}
    for package, uids in package_uids.items():
        for uid in uids:
            by_uid.setdefault(uid, []).append(package)
    return by_uid


def _tls_sockets_by_pid(snapshot: Snapshot) -> dict[int, list[sockets.SocketEntry]]:
    if not snapshot.root:
        return {}
    tls = [entry for entry in snapshot.sockets if sockets.is_remote_tls_port(entry)]
    return sockets.owners_by_pid(tls, snapshot.inode_map or {})


def probe_delegates(target_package: str, probe_evidence: ProbeEvidence, known: Iterable[str]) -> list[str]:
    """Non-shared probe packages that are plausible delegates and not already in ``known``."""
    known_set = set(known)
    return [
        package
        for package in probe_evidence
        if package not in known_set
        and not is_shared_delegate(package)
        and is_plausible_delegate(package, target_package)
    ]


def _build_context(snapshot: Snapshot, target_package: str, probe_evidence: ProbeEvidence | None = None) -> _Context:
    probe_evidence = probe_evidence or {}
    delegates = delegate_packages(
        target_package, snapshot.foreground_package, snapshot.oom_links, load_shared_delegates()
    )
    delegates += probe_delegates(target_package, probe_evidence, delegates)
    uid_attributed = set() if snapshot.root else tls_socket_uids(snapshot.sockets, UID_ATTRIBUTED_PORTS)
    return _Context(
        snapshot=snapshot,
        target_package=target_package,
        delegates=delegates,
        packages_by_uid=_packages_by_uid(snapshot.package_uids),
        sockets_by_pid=_tls_sockets_by_pid(snapshot),
        uid_attributed=uid_attributed,
        top_pids=top_activity_pids(snapshot.oom_processes),
        probe_evidence=probe_evidence,
    )


def resolve_package(proc: ProcessEntry, ctx: _Context) -> str:
    """Package of ``proc``: its name prefix if installed, else the package owning its UID."""
    named = package_of(proc.name)
    if named in ctx.snapshot.package_uids:
        return named
    owners = ctx.packages_by_uid.get(proc.uid, [])
    return owners[0] if owners else named


def _target_uids(ctx: _Context) -> list[int]:
    uids = list(ctx.snapshot.package_uids.get(ctx.target_package, []))
    target_procs = (proc for proc in ctx.snapshot.processes if package_of(proc.name) == ctx.target_package)
    return uids + [proc.uid for proc in target_procs]


def _role_of(proc: ProcessEntry, package: str, ctx: _Context) -> str | None:
    if package == ctx.target_package:
        return ROLE_TARGET
    if proc.name == ctx.target_package + SDK_SANDBOX_NAME_SUFFIX:
        return ROLE_SDK_SANDBOX
    if any(same_app(proc.uid, uid) for uid in _target_uids(ctx)):
        return ROLE_SIBLING
    if package in ctx.delegates:
        return ROLE_DELEGATE
    if is_shared_delegate(package):
        return ROLE_SHARED_SYSTEM
    return None


def _net_evidence(proc: ProcessEntry, ctx: _Context) -> list[str]:
    if not ctx.snapshot.root:
        return [EVIDENCE_UID_ATTRIBUTED] if proc.uid in ctx.uid_attributed else []
    return [sockets.socket_evidence(entry) for entry in ctx.sockets_by_pid.get(proc.pid, [])]


def _is_foreground_host(proc: ProcessEntry, package: str, ctx: _Context) -> bool:
    if package != ctx.snapshot.foreground_package:
        return False
    return not ctx.top_pids or proc.pid in ctx.top_pids


def _oom_evidence(proc: ProcessEntry, ctx: _Context) -> list[str]:
    related = {ctx.target_package, *ctx.delegates}
    return [
        safe_text(EVIDENCE_OOM_BOUND_BY + link.client_process)
        for link in ctx.snapshot.oom_links
        if link.served_pid == proc.pid and package_of(link.client_process) in related
    ]


def _evidence_for(proc: ProcessEntry, package: str, role: str, ctx: _Context) -> list[str]:
    evidence = _net_evidence(proc, ctx)
    if _is_foreground_host(proc, package, ctx):
        evidence.append(EVIDENCE_FOREGROUND_HOST)
    evidence += _oom_evidence(proc, ctx)
    if role in (ROLE_DELEGATE, ROLE_SHARED_SYSTEM):
        evidence += ctx.probe_evidence.get(package, [])
    if role == ROLE_SIBLING:
        evidence.append(EVIDENCE_SAME_UID)
    return _unique(evidence)


def _unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _has_net_evidence(evidence: list[str]) -> bool:
    return any(item.startswith("net:") for item in evidence)


def _is_kept(role: str, evidence: list[str]) -> bool:
    """Target-side processes always; delegates with any evidence; shared ones only with sockets."""
    if role == ROLE_DELEGATE:
        return bool(evidence)
    if role == ROLE_SHARED_SYSTEM:
        return _has_net_evidence(evidence)
    return True


def _candidate_for(proc: ProcessEntry, ctx: _Context) -> Candidate | None:
    package = resolve_package(proc, ctx)
    role = _role_of(proc, package, ctx)
    if role is None:
        return None
    evidence = _evidence_for(proc, package, role, ctx)
    if not _is_kept(role, evidence):
        return None
    return Candidate(pid=proc.pid, process=proc.name, package=package, uid=proc.uid, role=role, evidence=evidence)


def sort_candidates(candidates: Iterable[Candidate]) -> list[Candidate]:
    """Order by role (target first, shared system last), then process name."""
    return sorted(candidates, key=lambda cand: (ROLES.index(cand.role), cand.process))


def classify(snapshot: Snapshot, target_package: str, probe_evidence: ProbeEvidence | None = None) -> list[Candidate]:
    """Candidates for ``target_package``; unrelated processes (and VPN noise) are dropped.

    ``probe_evidence`` (package -> ``handoff:binder:`` evidence) adds those packages'
    processes as delegates (shared system ones still need a TLS socket to be kept).
    """
    ctx = _build_context(snapshot, target_package, probe_evidence)
    candidates = (_candidate_for(proc, ctx) for proc in snapshot.processes)
    return sort_candidates(cand for cand in candidates if cand is not None)


# --------------------------------------------------------------------------- TLS library confirmation


def read_tls_libs(runner: Runner, pids: list[int]) -> dict[int, list[str]]:
    """TLS library labels mapped by each PID (one root ``su -c`` call for all of them)."""
    if not pids:
        return {}
    return parse_maps_tls_libs(runner(as_root(build_maps_scan_script(pids))))


def with_tls_lib_evidence(cand: Candidate, labels: list[str]) -> Candidate:
    """Copy of ``cand`` with ``tls_lib:`` evidence added and ``confirmed`` re-evaluated."""
    evidence = _unique(cand.evidence + tls_lib_evidence(labels))
    return replace(cand, evidence=evidence, confirmed=is_tls_confirmed(evidence))


def confirm_candidates(runner: Runner, candidates: list[Candidate]) -> list[Candidate]:
    """Add mapped-TLS-library evidence to attributable (non-shared) candidates; needs root."""
    pids = [cand.pid for cand in candidates if cand.is_attributable]
    libs = read_tls_libs(runner, pids)
    return [
        with_tls_lib_evidence(cand, libs.get(cand.pid, [])) if cand.is_attributable else cand for cand in candidates
    ]


# --------------------------------------------------------------------------- sampling


def merge_candidates(merged: dict[str, Candidate], sample: Iterable[Candidate]) -> dict[str, Candidate]:
    """Merge one sample into ``merged`` (keyed by process name): union evidence, latest pid wins.

    ``confirmed`` is re-derived from the union, so a socket seen in one sample and
    a TLS library seen in another still confirm the candidate.
    """
    for cand in sample:
        previous = merged.get(cand.process)
        evidence = _unique((previous.evidence if previous else []) + cand.evidence)
        merged[cand.process] = replace(cand, evidence=evidence, confirmed=is_tls_confirmed(evidence))
    return merged


def sample_count(duration: float, interval: float) -> int:
    """Number of snapshots taken over ``duration`` seconds (at least one)."""
    if interval <= 0:
        return 1
    return max(1, int(duration // interval))


def collect_candidates(
    runner: Runner, target_package: str, root: bool, probe_evidence: ProbeEvidence | None = None
) -> list[Candidate]:
    """Candidates from one snapshot; with root, TLS-library evidence is added (``confirm_candidates``)."""
    candidates = classify(collect_snapshot(runner, root), target_package, probe_evidence)
    return confirm_candidates(runner, candidates) if root else candidates


def sample_candidates(
    runner: Runner,
    target_package: str,
    root: bool,
    samples: int,
    interval: float,
    sleep: Callable = time.sleep,
    probe_evidence: ProbeEvidence | None = None,
) -> list[Candidate]:
    """Take ``samples`` snapshots ``interval`` seconds apart and merge their candidates."""
    merged: dict[str, Candidate] = {}
    for index in range(samples):
        if index:
            sleep(interval)
        merge_candidates(merged, collect_candidates(runner, target_package, root, probe_evidence))
    return sort_candidates(merged.values())


# --------------------------------------------------------------------------- profile


def read_device_fingerprint(runner: Runner) -> str | None:
    return runner(FINGERPRINT_COMMAND).strip() or None


def version_code_command(package: str) -> str:
    """``dumpsys package <package>`` filtered to ``versionCode``; raises ValueError on a bad name."""
    return f"dumpsys package {shlex.quote(validate_package_name(package))} | grep versionCode"


def read_version_code(runner: Runner, package: str) -> int | None:
    """``versionCode`` of ``package`` from ``dumpsys package``, or None."""
    output = runner(version_code_command(package))
    match = _VERSION_CODE_RE.search(output)
    return int(match.group(1)) if match else None


def process_patterns_from(candidates: Iterable[Candidate]) -> list[str]:
    """Process names of attributable (non-shared) candidates, deduplicated in order."""
    return _unique(cand.process for cand in candidates if cand.is_attributable)


def discover(
    runner: Runner,
    target_package: str,
    duration: float = 0.0,
    interval: float = 2.0,
    *,
    target: str | None = None,
    root: bool | None = None,
    sleep: Callable = time.sleep,
    probe: ProbeResult | None = None,
) -> Profile:
    """Sample the device for ``duration`` seconds and build a capture :class:`Profile`.

    ``probe`` (from :func:`~tlslibhunter.discovery.probe.run_probe`) adds the
    packages behind the binder interfaces the target called; unmapped ones are
    listed in ``binder_descriptors``.
    """
    validate_package_name(target_package)
    has_root = detect_root(runner) if root is None else root
    samples = sample_count(duration, interval)
    probe_evidence = probe_package_evidence(probe) if probe else None
    candidates = sample_candidates(runner, target_package, has_root, samples, interval, sleep, probe_evidence)
    return Profile(
        target=target or target_package,
        target_package=target_package,
        gate_packages=gate_packages_from(candidates),
        process_patterns=process_patterns_from(candidates),
        device_fingerprint=read_device_fingerprint(runner),
        version_code=read_version_code(runner, target_package),
        candidates=candidates,
        binder_descriptors=unmapped_descriptors(probe) if probe else [],
    )
