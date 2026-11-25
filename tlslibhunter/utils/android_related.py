"""Discover Android processes related to an attached target.

Some Android apps are trampolines: their launcher entry immediately hands the
UI (and thus the network traffic) to another package. Example: the Gemini app
(``com.google.android.apps.bard``) whose UI is hosted by
``com.google.android.googlequicksearchbox:search``. Apps also commonly split
work across several processes of the same package (``pkg:remote``, ...).

This module finds those related processes so the user can be pointed at them.
Parsing and decision logic are pure functions; only
:func:`find_related_processes` talks to the device.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from tlslibhunter.utils.adb import adb_shell

logger = logging.getLogger("tlslibhunter.utils.android_related")

# Android assigns app UIDs from 10000 upwards; lower UIDs are system/shared
# (e.g. 1000 = system) and would make "same UID" meaningless.
FIRST_APPLICATION_UID = 10000

# Foreground packages that just mean "the user is not inside any app".
_NON_DELEGATE_PACKAGES = frozenset({"com.android.systemui", "android"})

_PS_COMMAND = "ps -A -o PID,UID,NAME"
_DUMPSYS_COMMAND = "dumpsys activity activities | grep -E 'ResumedActivity'"

# Preference order: Android 10+ reports topResumedActivity; older releases
# only have mResumedActivity (newer ones also print "ResumedActivity:").
_RESUMED_ACTIVITY_KEYS = ("topResumedActivity=", "mResumedActivity: ", "ResumedActivity: ")
_ACTIVITY_RECORD_RE = r"ActivityRecord\{\S+ u\d+ ([A-Za-z0-9_.]+)/"


@dataclass(frozen=True)
class ProcessEntry:
    """One row of ``ps -A -o PID,UID,NAME``."""

    pid: int
    uid: int
    name: str


@dataclass
class RelatedProcesses:
    """Processes related to an attached Android target."""

    target_package: str | None
    target_pid: int | None = None
    sibling_processes: list[ProcessEntry] = field(default_factory=list)
    foreground_package: str | None = None
    delegate_processes: list[ProcessEntry] = field(default_factory=list)

    @property
    def has_delegate(self) -> bool:
        """True when another package hosts the foreground UI of the target."""
        return bool(self.delegate_processes)

    @property
    def related_pids(self) -> list[int]:
        """PIDs worth scanning besides the target (delegates first, deduplicated)."""
        pids: list[int] = []
        for proc in self.delegate_processes + self.sibling_processes:
            if proc.pid not in pids:
                pids.append(proc.pid)
        return pids


def package_of(process_name: str) -> str:
    """Return the package part of an Android process name (``pkg:proc`` -> ``pkg``)."""
    return process_name.split(":", 1)[0]


def belongs_to_package(process_name: str, package: str) -> bool:
    """True if ``process_name`` is ``package`` or one of its ``package:xyz`` processes."""
    return process_name == package or process_name.startswith(package + ":")


def parse_ps_output(text: str) -> list[ProcessEntry]:
    """Parse ``ps -A -o PID,UID,NAME`` output; malformed lines are skipped."""
    entries: list[ProcessEntry] = []
    for line in text.splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3 or not (parts[0].isdigit() and parts[1].isdigit()):
            continue
        entries.append(ProcessEntry(pid=int(parts[0]), uid=int(parts[1]), name=parts[2].strip()))
    return entries


def parse_foreground_package(dumpsys_text: str) -> str | None:
    """Return the package of the resumed (foreground) activity, or None."""
    for key in _RESUMED_ACTIVITY_KEYS:
        match = re.search(re.escape(key) + _ACTIVITY_RECORD_RE, dumpsys_text)
        if match:
            return match.group(1)
    return None


def is_plausible_delegate(foreground_package: str | None, target_package: str | None) -> bool:
    """True if the foreground package differs from the target and is a real app."""
    if not foreground_package or not target_package or foreground_package == target_package:
        return False
    if foreground_package in _NON_DELEGATE_PACKAGES:
        return False
    return "launcher" not in foreground_package.lower()


def find_siblings(processes: list[ProcessEntry], target: ProcessEntry | None, package: str) -> list[ProcessEntry]:
    """Other processes of ``package``, or sharing the target's application UID."""
    target_pid = target.pid if target else None
    shared_uid = target.uid if target and target.uid >= FIRST_APPLICATION_UID else None
    return [
        proc
        for proc in processes
        if proc.pid != target_pid and (belongs_to_package(proc.name, package) or proc.uid == shared_uid)
    ]


def processes_of_package(processes: list[ProcessEntry], package: str) -> list[ProcessEntry]:
    """All processes belonging to ``package``."""
    return [proc for proc in processes if belongs_to_package(proc.name, package)]


def build_related_processes(
    processes: list[ProcessEntry],
    target_pid: int | None = None,
    target_package: str | None = None,
    foreground_package: str | None = None,
) -> RelatedProcesses | None:
    """Combine ps rows and the foreground package into a :class:`RelatedProcesses`.

    The target is identified by PID when possible (its process name yields the
    package), otherwise by ``target_package``. Returns None if neither works.
    """
    target = next((proc for proc in processes if proc.pid == target_pid), None)
    package = package_of(target.name) if target else target_package
    if not package:
        return None
    delegates: list[ProcessEntry] = []
    if is_plausible_delegate(foreground_package, package):
        delegates = processes_of_package(processes, foreground_package)
    return RelatedProcesses(
        target_package=package,
        target_pid=target.pid if target else target_pid,
        sibling_processes=find_siblings(processes, target, package),
        foreground_package=foreground_package,
        delegate_processes=delegates,
    )


def find_related_processes(
    serial: str | None,
    target_pid: int | None = None,
    target_package: str | None = None,
) -> RelatedProcesses | None:
    """Query the device and return the target's related processes.

    Best-effort: returns None when ``ps`` fails or the target cannot be
    identified. A failing ``dumpsys`` only drops the foreground information.
    """
    rc, ps_out = adb_shell(_PS_COMMAND, serial=serial)
    if rc != 0:
        logger.debug("ps failed, skipping related-process lookup: %s", ps_out.strip())
        return None
    rc, dumpsys_out = adb_shell(_DUMPSYS_COMMAND, serial=serial)
    if rc != 0:
        logger.debug("dumpsys activity failed: %s", dumpsys_out.strip())
    foreground = parse_foreground_package(dumpsys_out) if rc == 0 else None
    return build_related_processes(parse_ps_output(ps_out), target_pid, target_package, foreground)


def _process_label(proc: ProcessEntry, package: str) -> str:
    """``568 :search`` for a sub-process of ``package``, else ``568 full.name``."""
    suffix = proc.name[len(package) :] if belongs_to_package(proc.name, package) else proc.name
    return f"{proc.pid} {suffix or proc.name}"


def _format_pid_list(processes: list[ProcessEntry], package: str) -> str:
    return ", ".join(_process_label(proc, package) for proc in processes)


def format_related_hint(related: RelatedProcesses | None) -> tuple[int, str] | None:
    """Decide whether and how to hint about related processes.

    Returns ``(logging level, message)``: WARNING when another package hosts
    the foreground UI, INFO when only sibling processes exist, else None.
    """
    if related is None:
        return None
    if related.has_delegate:
        host = related.foreground_package
        return logging.WARNING, (
            f"Foreground UI of '{related.target_package}' is hosted by '{host}' "
            f"(PIDs {_format_pid_list(related.delegate_processes, host)}). "
            "TLS traffic is likely there — scan those PIDs or use --all-processes."
        )
    if related.sibling_processes:
        return logging.INFO, (
            f"'{related.target_package}' has other processes "
            f"(PIDs {_format_pid_list(related.sibling_processes, related.target_package)}). "
            "TLS traffic may happen there as well — scan those PIDs or use --all-processes."
        )
    return None
