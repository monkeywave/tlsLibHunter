"""TLSLibHunter command-line interface."""

from __future__ import annotations

import argparse
import logging
import sys

from tlslibhunter.about import __version__


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
  tlsLibHunter 1234 -l                 Attach to PID 1234
  tlsLibHunter firefox -f json         JSON output
  tlsLibHunter firefox --host 10.0.0.1:27042   Remote Frida device
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
    p.add_argument("-d", "--debug", action="store_true", help="Debug output")
    p.add_argument("-v", "--verbose", action="store_true", help="Show all scanned modules")
    p.add_argument("--backend", choices=["frida"], default="frida", help="Instrumentation backend (default: frida)")
    p.add_argument("--timeout", type=int, default=10, metavar="SEC", help="Attachment timeout in seconds (default: 10)")
    return p


def _setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    fmt = "%(levelname)s: %(message)s" if not debug else "%(levelname)s [%(name)s] %(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.debug)

    from tlslibhunter.config import HunterConfig
    from tlslibhunter.hunter import TLSLibHunter
    from tlslibhunter.output import get_formatter

    config = HunterConfig(
        target=args.target,
        mobile=args.mobile or (args.serial is not None),
        serial=args.serial,
        host=args.host,
        spawn=args.spawn,
        backend=args.backend,
        timeout=args.timeout,
        list_only=args.list_only,
        output_dir=args.output,
        format=args.format,
        debug=args.debug,
        verbose=args.verbose,
    )

    formatter = get_formatter(config.format)

    try:
        hunter = TLSLibHunter.from_config(config)
    except Exception as e:
        logging.getLogger("tlslibhunter").error("Initialization failed: %s", e)
        return 1

    try:
        with hunter:
            # Scan
            result = hunter.scan()

            if not result.libraries:
                print("No TLS/SSL libraries detected.", file=sys.stderr)
                if result.errors:
                    for err in result.errors:
                        print(f"  Error: {err}", file=sys.stderr)
                return 0

            # Output scan results
            print(formatter.format_scan(result))

            # Extract unless list-only (but -o overrides -l)
            should_extract = not config.list_only or config.output_dir is not None
            if should_extract:
                output_dir = config.effective_output_dir
                extractions = hunter.extract(result, output_dir=output_dir)
                if extractions:
                    print(formatter.format_extractions(extractions))
                    success_count = sum(1 for e in extractions if e.success)
                    print(
                        f"\nExtracted {success_count}/{len(extractions)} libraries to {output_dir}",
                        file=sys.stderr,
                    )

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as e:
        logging.getLogger("tlslibhunter").error("Error: %s", e)
        if args.debug:
            import traceback

            traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
