"""Scan a target and its related Android processes (``--all-processes``).

A thin orchestrator: every process is scanned through the regular
single-process path (injected as ``scan_one``), one after another. A failure in
one process is recorded and never aborts the remaining scans.
"""

from __future__ import annotations

import dataclasses
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from tlslibhunter.config import HunterConfig
from tlslibhunter.scanner.results import ExtractionResult, ScanResult

logger = logging.getLogger("tlslibhunter")


@dataclass
class ProcessScanOutcome:
    """What scanning one process produced: a result, or the error that stopped it."""

    target: str
    result: ScanResult | None = None
    extractions: list[ExtractionResult] = field(default_factory=list)
    error: str | None = None
    pid: int | None = None
    name: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None and self.result is not None

    @property
    def process_name(self) -> str:
        if self.result is not None and self.result.attached_process:
            return self.result.attached_process
        return self.name or self.target

    @property
    def process_pid(self) -> int | None:
        if self.result is not None and self.result.attached_pid is not None:
            return self.result.attached_pid
        return self.pid

    @property
    def library_names(self) -> list[str]:
        return [lib.name for lib in self.result.libraries] if self.result else []

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "process": self.process_name,
            "pid": self.process_pid,
            "error": self.error,
            "scan": self.result.to_dict() if self.result else None,
            "extractions": [e.to_dict() for e in self.extractions],
        }


ScanOne = Callable[[HunterConfig], ProcessScanOutcome]
FindRelated = Callable[[str | None, int | None, str | None], Any]


def config_for_pid(config: HunterConfig, pid: int) -> HunterConfig:
    """Config for scanning a related PID: same options, attach (never spawn) by PID.

    With ``-o DIR`` each related process extracts into ``DIR/<pid>`` so libraries
    of different processes never overwrite each other; without it the default
    per-target directory (``./tls_libs_<pid>``) already separates them.
    """
    output_dir = os.path.join(config.output_dir, str(pid)) if config.output_dir else None
    return dataclasses.replace(config, target=str(pid), spawn=False, output_dir=output_dir)


def safe_scan(scan_one: ScanOne, config: HunterConfig) -> ProcessScanOutcome:
    """Run ``scan_one``; turn any exception into a failed outcome instead of raising."""
    try:
        return scan_one(config)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        return failed_outcome(config, e, getattr(e, "pid", None))


def failed_outcome(config: HunterConfig, error: Exception, pid: int | None = None) -> ProcessScanOutcome:
    """Log a per-process failure and record it; ``pid`` lets related lookup still work."""
    logger.error("Scan of '%s' failed: %s", config.target, error)
    return ProcessScanOutcome(target=config.target, error=str(error), pid=pid)


def _target_package(target: str) -> str | None:
    return target if "." in target and not target.isdigit() else None


def _is_android(outcome: ProcessScanOutcome, config: HunterConfig) -> bool:
    if outcome.result is not None:
        return outcome.result.platform == "android"
    return config.is_mobile  # target failed before the platform was known


def related_pids_for(outcome: ProcessScanOutcome, config: HunterConfig, find_related: FindRelated) -> list[int]:
    """PIDs related to the scanned target (delegates first), excluding the target itself."""
    if not _is_android(outcome, config):
        logger.warning("--all-processes is only supported on Android; scanned the single target only.")
        return []
    target_pid = outcome.process_pid
    try:
        related = find_related(config.device_serial, target_pid, _target_package(config.target))
    except Exception as e:
        logger.warning("Could not look up related processes: %s", e)
        return []
    if related is None:
        return []
    return [pid for pid in related.related_pids if pid != target_pid]


def scan_all_processes(
    config: HunterConfig,
    scan_one: ScanOne,
    find_related: FindRelated | None = None,
) -> list[ProcessScanOutcome]:
    """Scan the target, then every related process; one outcome per process."""
    if find_related is None:
        from tlslibhunter.utils.android_related import find_related_processes as find_related

    target_outcome = safe_scan(scan_one, config)
    pids = related_pids_for(target_outcome, config, find_related)
    if pids:
        logger.info("--all-processes: scanning %d related process(es): PIDs %s", len(pids), ", ".join(map(str, pids)))
    return [target_outcome] + [safe_scan(scan_one, config_for_pid(config, pid)) for pid in pids]


def summary_rows(outcomes: list[ProcessScanOutcome]) -> list[tuple[str, str, str]]:
    """``(process, pid, libraries-or-error)`` rows shared by the summary formatters."""
    rows = []
    for outcome in outcomes:
        pid = str(outcome.process_pid) if outcome.process_pid is not None else "?"
        if outcome.error:
            status = f"ERROR: {outcome.error.splitlines()[0]}"
        else:
            status = ", ".join(outcome.library_names) or "none"
            if outcome.result.errors:  # e.g. the process died mid-scan
                status += f" (INCOMPLETE: {len(outcome.result.errors)} error(s))"
        rows.append((outcome.process_name, pid, status))
    return rows
