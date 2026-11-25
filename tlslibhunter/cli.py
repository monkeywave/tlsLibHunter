"""TLSLibHunter command-line interface."""

from __future__ import annotations

import argparse
import logging
import re
import sys
import traceback
from datetime import datetime

from tlslibhunter.about import __version__

# Matches ANSI escape sequences (colors, cursor moves) so the debug log file
# captures clean, greppable text rather than terminal control codes.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class _TeeStream:
    """Write-through stream that mirrors output to a log file (ANSI stripped).

    Wraps the real stdout/stderr so everything the user sees in the terminal is
    also persisted to the debug log. Unknown attributes (isatty, encoding,
    fileno, …) proxy to the original stream so Rich and friends behave normally.
    """

    def __init__(self, original, log_fh):
        self._original = original
        self._log = log_fh

    def write(self, s: str) -> int:
        self._original.write(s)
        self._log.write(_ANSI_RE.sub("", s))
        return len(s)

    def flush(self) -> None:
        self._original.flush()
        self._log.flush()

    def write_log_only(self, s: str) -> None:
        """Persist text to the debug log file without echoing it to the terminal."""
        self._log.write(_ANSI_RE.sub("", s))
        self._log.flush()

    def __getattr__(self, attr):
        return getattr(self._original, attr)


def _setup_debug_log_file(target: str) -> str | None:
    """Tee stdout/stderr into a timestamped log file in the cwd.

    Returns the log path, or None if the file could not be opened.
    """
    safe_target = str(target).replace("/", "_").replace("\\", "_")
    log_path = f"tlslibhunter_{safe_target}_{datetime.now():%Y%m%d-%H%M%S}.log"
    try:
        log_fh = open(log_path, "w", encoding="utf-8")  # noqa: SIM115 (kept open for process lifetime)
    except OSError as e:
        print(f"Warning: could not open debug log file '{log_path}': {e}", file=sys.stderr)
        return None
    sys.stdout = _TeeStream(sys.stdout, log_fh)
    sys.stderr = _TeeStream(sys.stderr, log_fh)
    return log_path


def _write_traceback_to_debug_log() -> bool:
    """Write the active exception's traceback to the -d log file only.

    The debug log is a tee of stderr, so logging the traceback normally would
    also flood the terminal. Returns False when no debug log file is active.
    """
    if not isinstance(sys.stderr, _TeeStream):
        return False
    sys.stderr.write_log_only(traceback.format_exc())
    return True


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tlsLibHunter",
        description="Identify and extract TLS/SSL libraries from running processes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  tlsLibHunter firefox -l              List TLS libraries in Firefox
  tlsLibHunter firefox                 List + extract TLS libraries
  tlsLibHunter com.example.app -m -l   List TLS libs on Android device
  tlsLibHunter com.example.app --serial ABC123   Specific device by serial
  tlsLibHunter Gemini --serial ABC123 --all-processes -l   Target + related processes
  tlsLibHunter 1234 -l                 Attach to PID 1234
  tlsLibHunter firefox -f json         JSON output
  tlsLibHunter firefox --host 10.0.0.1:27042   Remote Frida device
  tlsLibHunter discover com.google.android.apps.bard --serial ABC123   Find the processes carrying an app's TLS
""",
    )
    p.add_argument("target", metavar="TARGET", help="Process name, PID, or package name")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "-l",
        "--list-only",
        action="store_true",
        help="Only list TLS libraries (no extraction). Overridden by -o",
    )
    p.add_argument("-o", "--output", metavar="DIR", default=None, help="Output directory for extracted libs")
    p.add_argument(
        "-f", "--format", choices=["table", "json", "plain"], default="table", help="Output format (default: table)"
    )
    p.add_argument("-m", "--mobile", action="store_true", help="Target mobile device (first USB device)")
    p.add_argument(
        "--serial",
        default=None,
        metavar="ID",
        help="Device serial/ID (from 'adb devices' or 'frida-ls-devices'). Implies -m",
    )
    p.add_argument("--host", default=None, help="Remote Frida device (ip:port)")
    p.add_argument("-s", "--spawn", action="store_true", help="Spawn process instead of attach")
    p.add_argument(
        "--unfreeze",
        action="store_true",
        help="Android (root): if attaching times out because the app is frozen by the "
        "cached-apps freezer, unfreeze it and retry once",
    )
    p.add_argument(
        "--all-processes",
        action="store_true",
        help="Android: after the target, also scan its related processes (other processes of "
        "the same app and the app hosting its foreground UI, e.g. Gemini -> Google app)",
    )
    p.add_argument("-d", "--debug", action="store_true", help="Debug output")
    p.add_argument("-v", "--verbose", action="store_true", help="Show all scanned modules")
    p.add_argument("--backend", choices=["frida"], default="frida", help="Instrumentation backend (default: frida)")
    p.add_argument("--timeout", type=int, default=10, metavar="SEC", help="Attachment timeout in seconds (default: 10)")
    p.add_argument(
        "--scan-labels",
        action="store_true",
        help="Raw label scan: scan ALL modules for TLS HKDF/PRF labels without filtering",
    )
    p.add_argument(
        "--scan-split-constants",
        action="store_true",
        help="Search for split substrings of TLS string patterns",
    )
    p.add_argument(
        "--scan-stack-strings",
        action="store_true",
        help="Scan writable memory for runtime-assembled stack strings",
    )
    p.add_argument(
        "--scan-rwx-regions",
        action="store_true",
        help="Scan process-wide RWX (JIT) memory regions",
    )
    p.add_argument(
        "--scan-encoded-strings",
        action="store_true",
        help="Search for XOR/base64-encoded TLS strings",
    )
    p.add_argument(
        "--scan-all-modules",
        action="store_true",
        help="Bypass TLS heuristic filter; scan every module except the hard skip-list "
        "(libc, libm, libart, *.oat, etc.). Logs per-module SCAN/SKIP lines.",
    )
    p.add_argument(
        "--scan-everything",
        action="store_true",
        help="Scan every loaded module INCLUDING libc/libm/ART runtime files. Also "
        "bypasses the 10 KiB minimum-size filter. Diagnostic / paranoia mode.",
    )
    return p


def _scan_and_extract(hunter, config, formatter, emit: bool = True) -> tuple:
    """Scan one process, print its results, and extract unless list-only.

    ``emit=False`` suppresses the per-process stdout output (used by
    ``--all-processes -f json``, which prints one combined document instead).

    Returns:
        (ScanResult, list of ExtractionResult)
    """
    # Scan
    result = hunter.scan()

    if not result.libraries:
        print("No TLS/SSL libraries detected.", file=sys.stderr)
        if result.errors:
            for err in result.errors:
                print(f"  Error: {err}", file=sys.stderr)
        return result, []

    # Output scan results
    if emit:
        print(formatter.format_scan(result))

    extractions = []
    # Extract unless list-only (but -o overrides -l)
    should_extract = not config.list_only or config.output_dir is not None
    if should_extract:
        output_dir = config.effective_output_dir
        print(
            f"\nExtracting {len(result.libraries)} libraries to {output_dir}...",
            file=sys.stderr,
        )
        extractions = hunter.extract(result, output_dir=output_dir)
        if extractions:
            if emit:
                print(formatter.format_extractions(extractions))
            success_count = sum(1 for e in extractions if e.success)
            print(
                f"\nExtracted {success_count}/{len(extractions)} libraries to {output_dir}",
                file=sys.stderr,
            )
    return result, extractions


def _scan_one_process(config, formatter, emit: bool):
    """Single-process scan path wrapped as a ProcessScanOutcome (for --all-processes)."""
    from tlslibhunter.hunter import TLSLibHunter
    from tlslibhunter.multi_process import ProcessScanOutcome, failed_outcome

    print(f"\n=== Scanning '{config.target}' ===", file=sys.stderr)
    with TLSLibHunter.from_config(config) as hunter:
        try:
            result, extractions = _scan_and_extract(hunter, config, formatter, emit=emit)
        except Exception as e:
            # Keep the PID the hunter attached to, so related processes can still
            # be found when the target dies or re-freezes mid-scan.
            return failed_outcome(config, e, getattr(e, "pid", None) or hunter.attached_pid)
    return ProcessScanOutcome(target=config.target, result=result, extractions=extractions)


def _run_all_processes(config, formatter) -> int:
    """Scan the target and its related Android processes; print a combined summary.

    Returns 1 only when every scan failed.
    """
    from tlslibhunter.multi_process import scan_all_processes

    emit_each = config.format != "json"
    outcomes = scan_all_processes(config, lambda cfg: _scan_one_process(cfg, formatter, emit_each))
    print(formatter.format_process_summary(config.target, outcomes))
    return 0 if any(o.succeeded for o in outcomes) else 1


def _setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    fmt = "%(levelname)s: %(message)s" if not debug else "%(levelname)s [%(name)s] %(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)


def _is_discover_command(argv: list[str]) -> bool:
    return bool(argv) and argv[0] == "discover"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if _is_discover_command(argv):
        from tlslibhunter.discover_cli import discover_main

        return discover_main(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)

    # Tee terminal output to a log file before logging is configured, so the
    # logging StreamHandler binds the teed stderr and the file captures both the
    # rendered table (stdout) and all log records (stderr).
    log_path = _setup_debug_log_file(args.target) if args.debug else None
    _setup_logging(args.debug)
    if log_path:
        logging.getLogger("tlslibhunter").info("Debug log: %s", log_path)

    from tlslibhunter.backends.base import BackendError
    from tlslibhunter.config import HunterConfig
    from tlslibhunter.hunter import TLSLibHunter
    from tlslibhunter.output import get_formatter

    if args.scan_labels:
        args.scan_split_constants = True
        args.scan_stack_strings = True
        args.scan_rwx_regions = True
        args.scan_encoded_strings = True

    config = HunterConfig(
        target=args.target,
        mobile=args.mobile or (args.serial is not None),
        serial=args.serial,
        host=args.host,
        spawn=args.spawn,
        unfreeze=args.unfreeze,
        backend=args.backend,
        timeout=args.timeout,
        list_only=args.list_only,
        output_dir=args.output,
        format=args.format,
        debug=args.debug,
        verbose=args.verbose,
        scan_mode="labels" if args.scan_labels else "standard",
        scan_split_constants=args.scan_split_constants,
        scan_stack_strings=args.scan_stack_strings,
        scan_rwx_regions=args.scan_rwx_regions,
        scan_encoded_strings=args.scan_encoded_strings,
        scan_all_modules=args.scan_all_modules,
        scan_everything=args.scan_everything,
        all_processes=args.all_processes,
    )

    formatter = get_formatter(config.format)

    if config.all_processes:
        try:
            return _run_all_processes(config, formatter)
        except KeyboardInterrupt:
            print("\nInterrupted.", file=sys.stderr)
            return 130

    try:
        hunter = TLSLibHunter.from_config(config)
    except Exception as e:
        logging.getLogger("tlslibhunter").error("Initialization failed: %s", e)
        return 1

    try:
        with hunter:
            _scan_and_extract(hunter, config, formatter)

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except BackendError as e:
        # Expected user-facing failure (process/device not found, attach
        # refused): one clean line on the terminal; the traceback goes to the
        # debug log file only.
        logger = logging.getLogger("tlslibhunter")
        logger.error("Error: %s", e)
        if args.debug and _write_traceback_to_debug_log():
            logger.debug("Full traceback written to debug log: %s", log_path)
        return 1
    except Exception as e:
        logging.getLogger("tlslibhunter").error("Error: %s", e)
        if args.debug:
            import traceback

            traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
