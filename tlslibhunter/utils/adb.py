"""ADB command wrapper utilities."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess

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
    return run_cmd(args, timeout=60)


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
