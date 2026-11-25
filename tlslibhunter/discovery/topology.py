"""Pure helpers describing an app's process topology on Android.

Combines ``pm list packages -U`` output (package -> UIDs) with ``ps`` rows
(:class:`~tlslibhunter.utils.android_related.ProcessEntry`) to tell which
processes belong to which app and what kind of process each one is.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from tlslibhunter.discovery.uids import is_app_uid, is_isolated_uid, is_sdk_sandbox_uid, same_app
from tlslibhunter.utils.android_related import ProcessEntry

KIND_APP = "app"
KIND_SDK_SANDBOX = "sdk_sandbox"
KIND_ISOLATED = "isolated"
KIND_SYSTEM = "system"

SDK_SANDBOX_NAME_SUFFIX = "_sdk_sandbox"

_PM_PACKAGE_LINE_RE = re.compile(r"^package:(\S+)\s+uid:([\d,]+)")
# Dot-separated identifiers ("com.example.app"): no shell metacharacters can match.
_ANDROID_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")


def is_valid_android_package(name: object) -> bool:
    """True for an Android package name shape (shell safe); False for anything else."""
    return isinstance(name, str) and bool(_ANDROID_PACKAGE_RE.fullmatch(name))


def validate_package_name(package: str) -> str:
    """Return ``package`` if it is a plausible Android package name (shell safe), else raise."""
    if not is_valid_android_package(package):
        raise ValueError(f"invalid Android package name: {package!r}")
    return package


def _parse_uid_list(field: str) -> list[int]:
    return [int(uid) for uid in field.split(",") if uid]


def parse_pm_packages_uids(text: str) -> dict[str, list[int]]:
    """Parse ``pm list packages -U`` output into ``{package: [uid, ...]}``.

    Multi-user lines (``uid:10156,1010156``) yield one UID per user;
    lines without a UID are skipped.
    """
    packages: dict[str, list[int]] = {}
    for line in text.splitlines():
        match = _PM_PACKAGE_LINE_RE.match(line.strip())
        if match:
            packages[match.group(1)] = _parse_uid_list(match.group(2))
    return packages


def classify_process_kind(proc: ProcessEntry) -> str:
    """One of ``app``, ``sdk_sandbox``, ``isolated`` (cannot network) or ``system``."""
    if is_sdk_sandbox_uid(proc.uid) or proc.name.endswith(SDK_SANDBOX_NAME_SUFFIX):
        return KIND_SDK_SANDBOX
    if is_isolated_uid(proc.uid):
        return KIND_ISOLATED
    if is_app_uid(proc.uid):
        return KIND_APP
    return KIND_SYSTEM


def processes_for_uids(processes: Iterable[ProcessEntry], uids: Iterable[int]) -> list[ProcessEntry]:
    """Processes whose UID is the same app (same app id and user) as any of ``uids``."""
    wanted = tuple(uids)
    return [proc for proc in processes if any(same_app(proc.uid, uid) for uid in wanted)]
