"""ADB command wrapper utilities."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
import time

logger = logging.getLogger("tlslibhunter.utils.adb")


def check_adb() -> bool:
    """Check if adb is available in PATH."""
    return shutil.which("adb") is not None


def run_cmd(args: list[str], timeout: int = 60) -> tuple[int, str]:
    """Run a shell command and return (returncode, output)."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 1, "Command timed out"
    except Exception as e:
        return 1, f"Command failed: {e}"


_SERIAL_LINE_RE = re.compile(r"^([\w.:\-]+)\s+device\s*$")
_MULTI_DEVICE_RE = re.compile(r"more than one device(?:/emulator)?", re.IGNORECASE)
_NOT_FOUND_RE = re.compile(r"device '([^']+)' not found", re.IGNORECASE)

_serial_cache: dict[str, object] = {"ts": 0.0, "serials": []}
_serial_lock = threading.Lock()
_SERIAL_TTL = 5.0


def list_adb_serials() -> list[str]:
    """Return connected device serials parsed from `adb devices`.

    Returns an empty list if adb is unavailable, the command fails, or the
    output cannot be parsed. Only devices in the "device" state are returned
    (offline / unauthorized / no-permissions entries are skipped).
    """
    if not check_adb():
        return []
    ret, out = run_cmd(["adb", "devices"], timeout=10)
    if ret != 0:
        return []
    serials: list[str] = []
    for line in out.splitlines()[1:]:  # skip "List of devices attached" header
        m = _SERIAL_LINE_RE.match(line.strip())
        if m:
            serials.append(m.group(1))
    return serials


def _cached_serials() -> list[str]:
    """Return adb serials with a 5-second TTL cache to avoid repeated adb calls."""
    with _serial_lock:
        now = time.monotonic()
        if now - _serial_cache["ts"] < _SERIAL_TTL:
            return list(_serial_cache["serials"])
        s = list_adb_serials()
        _serial_cache["ts"] = now
        _serial_cache["serials"] = s
        return list(s)


def _enrich_adb_error(out: str) -> str:
    """Append a helpful hint to adb error output when the failure points to
    a missing or ambiguous --serial.
    """
    if _MULTI_DEVICE_RE.search(out):
        serials = _cached_serials()
        return out.rstrip() + (
            f"\nadb requires a specific device. Available serials: {serials}. Use --serial <SERIAL>."
        )
    m = _NOT_FOUND_RE.search(out)
    if m:
        serials = _cached_serials()
        return out.rstrip() + f"\nDevice '{m.group(1)}' not connected. Available: {serials}."
    return out


def adb_pull(remote: str, local: str, serial: str | None = None, timeout: int = 180) -> tuple[bool, str]:
    """Pull a file from Android device via adb.

    Args:
        remote: Remote file path on device
        local: Local destination path
        serial: Optional device serial
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, output_message)
    """
    os.makedirs(os.path.dirname(local) or ".", exist_ok=True)
    cmd = ["adb"]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(["pull", remote, local])

    ret, out = run_cmd(cmd, timeout=timeout)
    if ret != 0:
        out = _enrich_adb_error(out)
    return (ret == 0, out)


def adb_shell(cmd: str, serial: str | None = None) -> tuple[int, str]:
    """Run a command via adb shell.

    Args:
        cmd: Shell command to execute
        serial: Optional device serial

    Returns:
        Tuple of (returncode, output)
    """
    args = ["adb"]
    if serial:
        args.extend(["-s", serial])
    args.extend(["shell", cmd])
    ret, out = run_cmd(args, timeout=60)
    if ret != 0:
        out = _enrich_adb_error(out)
    return ret, out


def get_package_apk_paths(package: str, serial: str | None = None) -> list[str]:
    """Get APK paths for a package via pm path.

    Args:
        package: Android package name
        serial: Optional device serial

    Returns:
        List of remote APK paths
    """
    ret, out = adb_shell(f"pm path {package}", serial=serial)
    if ret != 0:
        return []

    paths = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            paths.append(line.split("package:", 1)[1])
    return paths
