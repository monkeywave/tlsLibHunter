"""``tlsLibHunter discover <app>``: find the processes that carry an app's TLS traffic.

Samples the Android device (``ps``, ``/proc/net``, ``dumpsys``; per-socket PIDs
with root) for a while and prints the candidate processes with their role and
evidence, or the full capture profile as JSON. With root, each candidate's
mapped TLS libraries (``/proc/<pid>/maps``) are added as ``tls_lib:`` evidence
and may mark it ``confirmed``.

With ``--probe`` a small Frida agent first watches which binder interfaces the
running target calls (launching it if needed) and adds the packages behind
them as delegates; see :mod:`tlslibhunter.discovery.probe`.

With ``--watch`` it keeps sampling and prints one ``tlslibhunter.watch/1`` JSON
line per change (process added/restarted/gone, new evidence) until Ctrl+C or,
when given, ``--duration``; see :mod:`tlslibhunter.discovery.watch`.
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
from collections.abc import Callable

from tlslibhunter.discovery import probe as probe_mod
from tlslibhunter.discovery import watch as watch_mod
from tlslibhunter.discovery.engine import PM_COMMAND, Runner, discover, make_adb_runner
from tlslibhunter.discovery.profile import Candidate, Profile
from tlslibhunter.discovery.text import MAX_MESSAGE_LENGTH, safe_text
from tlslibhunter.discovery.topology import parse_pm_packages_uids

logger = logging.getLogger("tlslibhunter.discover")

DISCOVER_COMMAND = "discover"
DEFAULT_DURATION = 20.0
DEFAULT_INTERVAL = 2.0
_TABLE_HEADER = ("PROCESS", "PID", "ROLE", "TLS", "EVIDENCE")


def build_discover_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tlsLibHunter discover",
        description="Android: find the processes (target, delegates, SDK sandbox, shared system "
        "services) that carry an app's TLS traffic.",
    )
    p.add_argument("app", metavar="APP", help="Package name (or app label, resolved via Frida)")
    p.add_argument(
        "--duration",
        type=float,
        default=None,
        metavar="SEC",
        help=f"Sampling duration in seconds (default: {DEFAULT_DURATION:g}); with --watch an "
        "optional stop bound (default: until Ctrl+C)",
    )
    p.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        metavar="SEC",
        help=f"Seconds between samples (default: {DEFAULT_INTERVAL:g})",
    )
    p.add_argument("--json", action="store_true", help="Print the profile as JSON")
    p.add_argument("--write-profile", metavar="PATH", default=None, help="Write the profile JSON to PATH")
    p.add_argument("--serial", default=None, metavar="ID", help="Device serial (from 'adb devices')")
    p.add_argument(
        "--probe",
        action="store_true",
        help="Before sampling, attach a Frida probe to the running app (launched if needed; "
        "thawed if frozen, root) for --duration seconds and learn delegates from the binder "
        "interfaces it calls",
    )
    p.add_argument(
        "--watch",
        action="store_true",
        help="Keep sampling every --interval seconds and print one JSON line "
        f"({watch_mod.WATCH_SCHEMA}) per process added/restarted/gone or new evidence, "
        "until Ctrl+C (or --duration, when given)",
    )
    p.add_argument("-d", "--debug", action="store_true", help="Debug output")
    return p


def sampling_duration(args: argparse.Namespace) -> float:
    """``--duration``, or :data:`DEFAULT_DURATION` when it was not given."""
    return DEFAULT_DURATION if args.duration is None else args.duration


def installed_packages(runner: Runner) -> set[str]:
    return set(parse_pm_packages_uids(runner(PM_COMMAND)))


def _resolve_with_frida(app: str, serial: str | None) -> str:
    from tlslibhunter.backends.frida_backend import FridaBackend

    backend = FridaBackend()
    try:
        return backend.resolve_app_identifier(backend.get_device(mobile=True, serial=serial), app)
    finally:
        backend.close()


def resolve_package(app: str, runner: Runner, serial: str | None, frida_resolver: Callable | None = None) -> str:
    """``app`` if it is an installed package, else its identifier looked up by app label via Frida."""
    packages = installed_packages(runner)
    if app in packages:
        return app
    package = (frida_resolver or _resolve_with_frida)(app, serial)
    if package not in packages:
        raise ValueError(f"'{app}' is neither an installed package nor a known app label")
    return package


def _candidate_row(cand: Candidate) -> tuple[str, ...]:
    """Table cells; device-derived strings (process names, evidence) are escaped and capped."""
    confirmed = "confirmed" if cand.confirmed else "-"
    evidence = ", ".join(safe_text(item) for item in cand.evidence) or "-"
    return (safe_text(cand.process), str(cand.pid), safe_text(cand.role), confirmed, evidence)


def _safe_list(items: list[str]) -> str:
    return ", ".join(safe_text(item) for item in items) or "-"


def format_candidate_table(profile: Profile) -> str:
    """Human-readable table: process, pid, role, TLS confirmation, evidence."""
    rows = [_TABLE_HEADER] + [_candidate_row(cand) for cand in profile.candidates]
    widths = [max(len(row[col]) for row in rows) for col in range(len(_TABLE_HEADER) - 1)]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row[:-1], widths)) + "  " + row[-1] for row in rows]
    summary = f"Target: {safe_text(profile.target_package)}   gate packages: {_safe_list(profile.gate_packages)}"
    return "\n".join([summary, ""] + lines + _binder_lines(profile))


def _binder_lines(profile: Profile) -> list[str]:
    if not profile.binder_descriptors:
        return []
    return ["", "Unmapped binder interfaces (probe):"] + [f"  {safe_text(name)}" for name in profile.binder_descriptors]


def render_profile(profile: Profile, as_json: bool) -> str:
    return profile.to_json() if as_json else format_candidate_table(profile)


def write_profile(profile: Profile, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(profile.to_json() + "\n")


def _print_sampling_cue(duration: float) -> None:
    print(f"Sampling for {duration:g}s - exercise the app now (trigger network activity)...", file=sys.stderr)


def _thaw_if_frozen(serial: str | None) -> Callable[[int], None]:
    """``before_attach`` hook: unfreeze a target frozen by the cached-apps freezer (root)."""
    from tlslibhunter.utils import android_process

    def thaw(pid: int) -> None:
        if android_process.read_freeze_state(pid, serial) and android_process.unfreeze(pid, serial):
            logger.warning("Unfroze PID %d (Android cached-apps freezer) for the probe.", pid)

    return thaw


def _frida_probe(package: str, duration: float, serial: str | None, launch: Callable) -> probe_mod.ProbeResult:
    from tlslibhunter.backends.frida_backend import FridaBackend

    backend = FridaBackend()
    try:
        device = backend.get_device(mobile=True, serial=serial)
        return probe_mod.run_probe(device, package, duration, launch=launch, before_attach=_thaw_if_frozen(serial))
    finally:
        backend.close()


def probe_summary(result: probe_mod.ProbeResult) -> str:
    return f"Probe: {len(result.descriptors)} binder interface(s), {result.net_events} TLS socket event(s)"


def run_probe_step(
    runner: Runner, package: str, args: argparse.Namespace, frida_probe: Callable | None = None
) -> probe_mod.ProbeResult | None:
    """Run the probe (launching ``package`` if needed); None (with a warning) if it fails."""

    def launch() -> None:
        print(f"Launching {safe_text(package)} for the probe...", file=sys.stderr)
        probe_mod.launch_app(runner, package)

    duration = sampling_duration(args)
    print(f"Probing for {duration:g}s - exercise the app now...", file=sys.stderr)
    try:
        result = (frida_probe or _frida_probe)(package, duration, args.serial, launch)
    except Exception as e:
        logger.warning("Probe failed, continuing without it: %s", safe_text(e, MAX_MESSAGE_LENGTH))
        return None
    print(probe_summary(result), file=sys.stderr)
    return result


def run_discover(args: argparse.Namespace, runner: Runner | None = None, frida_probe: Callable | None = None) -> int:
    """Execute a parsed ``discover`` command; returns the exit code."""
    runner = runner or make_adb_runner(args.serial)
    try:
        package = resolve_package(args.app, runner, args.serial)
    except Exception as e:
        logger.error("Error: %s", safe_text(e, MAX_MESSAGE_LENGTH))
        return 1
    probe = run_probe_step(runner, package, args, frida_probe) if args.probe else None
    if args.watch:
        return run_watch(runner, package, args, probe)
    duration = sampling_duration(args)
    _print_sampling_cue(duration)
    profile = discover(runner, package, duration, args.interval, target=args.app, probe=probe)
    print(render_profile(profile, args.json))
    if args.write_profile:
        write_profile(profile, args.write_profile)
        print(f"Profile written to {args.write_profile}", file=sys.stderr)
    return 0


def stop_event_for(duration: float | None) -> threading.Event:
    """Stop event for ``--watch``; set automatically after ``duration`` seconds when given."""
    stop = threading.Event()
    if duration is not None:
        timer = threading.Timer(max(duration, 0.0), stop.set)
        timer.daemon = True
        timer.start()
    return stop


def run_watch(
    runner: Runner,
    package: str,
    args: argparse.Namespace,
    probe: probe_mod.ProbeResult | None = None,
    stop: threading.Event | None = None,
) -> int:
    """Print one JSON line per watch event until Ctrl+C or ``--duration``; returns 0."""
    stop = stop or stop_event_for(args.duration)
    probe_evidence = probe_mod.probe_package_evidence(probe) if probe else None
    print(f"Watching {safe_text(package)} every {args.interval:g}s - Ctrl+C to stop...", file=sys.stderr)
    try:
        for event in watch_mod.watch(runner, package, args.interval, stop, probe_evidence=probe_evidence):
            print(event.to_json_line(), flush=True)
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
    finally:
        stop.set()
    return 0


def discover_main(argv: list[str]) -> int:
    """Entry point for ``tlsLibHunter discover ...`` (``argv`` without the subcommand)."""
    args = build_discover_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO, format="%(levelname)s: %(message)s", stream=sys.stderr
    )
    try:
        return run_discover(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
