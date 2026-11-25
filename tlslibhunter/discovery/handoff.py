"""Pure parsers for UI/service hand-offs between Android apps.

``dumpsys activity oom`` prints one header line per process, optionally
followed by the binding that raised its priority (its "adj source")::

    Proc # 2: vis  F/ /BTOP LCMNFU  t: 0 19016:com.google.android.gms/u0a162 (service)
        com.google.android.gms/...LocationManagerService<=Proc{568:com.google...:search/u0a156}

Read: process 568 (the *client*) is bound to a service of process 19016 (the
*served* process). Together with the foreground package
(:func:`~tlslibhunter.utils.android_related.parse_foreground_package`) these
links tell which other apps do work on behalf of a target.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import NamedTuple

from tlslibhunter.utils.android_related import belongs_to_package, is_plausible_delegate, package_of

TOP_ACTIVITY_REASON = "top-activity"

_OOM_HEADER_RE = re.compile(r"^\s*(?:Proc|PERS)\s*#\s*\d+:.*?\s(\d+):(\S+?)/\S+\s+\(([^)]*)\)")
_ADJ_SOURCE_RE = re.compile(r"<=Proc\{(\d+):(\S+?)/[^}]*\}")


class OomProcess(NamedTuple):
    """One process header of ``dumpsys activity oom``."""

    pid: int
    process: str
    reason: str


class OomLink(NamedTuple):
    """``client`` is bound to (and raises the priority of) ``served``."""

    client_process: str
    client_pid: int
    served_process: str
    served_pid: int


def _parse_header(line: str) -> OomProcess | None:
    match = _OOM_HEADER_RE.match(line)
    if not match:
        return None
    return OomProcess(int(match.group(1)), match.group(2), match.group(3))


def parse_oom_processes(text: str) -> list[OomProcess]:
    """Process headers (pid, process name, adj reason such as ``top-activity``)."""
    headers = (_parse_header(line) for line in text.splitlines())
    return [header for header in headers if header is not None]


def _link_from(line: str, served: OomProcess | None) -> OomLink | None:
    match = _ADJ_SOURCE_RE.search(line)
    if not match or served is None or _parse_header(line):
        return None
    return OomLink(match.group(2), int(match.group(1)), served.process, served.pid)


def parse_oom_adj_sources(text: str) -> list[OomLink]:
    """``Proc{...}`` adj-source bindings, attributed to the preceding process header."""
    links: list[OomLink] = []
    current: OomProcess | None = None
    for line in text.splitlines():
        current = _parse_header(line) or current
        link = _link_from(line, current)
        if link and link not in links:
            links.append(link)
    return links


def top_activity_pids(processes: Iterable[OomProcess]) -> list[int]:
    """PIDs whose adj reason says they host the top (foreground) activity."""
    return [proc.pid for proc in processes if proc.reason == TOP_ACTIVITY_REASON]


def bound_by_target(links: Iterable[OomLink], target_package: str) -> list[str]:
    """Packages of processes the target's processes are bound to (deduplicated, in order)."""
    packages: list[str] = []
    for link in links:
        served = package_of(link.served_process)
        if belongs_to_package(link.client_process, target_package) and served not in packages:
            packages.append(served)
    return packages


def delegate_packages(
    target_package: str,
    foreground_pkg: str | None,
    oom_links: Iterable[OomLink],
    shared: Iterable[str],
) -> list[str]:
    """Non-shared packages doing work for the target: the foreground host first, then bound ones.

    The target itself, launchers and systemui are never delegates.
    """
    shared_set = frozenset(shared)
    ordered = ([foreground_pkg] if foreground_pkg else []) + bound_by_target(oom_links, target_package)
    delegates: list[str] = []
    for package in ordered:
        if package in shared_set or package in delegates:
            continue
        if is_plausible_delegate(package, target_package):
            delegates.append(package)
    return delegates
