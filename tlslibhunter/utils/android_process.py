"""Android process state inspection for diagnosing Frida attach failures.

Frida's attach can time out ("timed out while waiting for stop") when the
target process cannot respond to a ptrace stop. The two common causes are:

* Android's cached-apps freezer has frozen the process via cgroup v2
  (``/sys/fs/cgroup/uid_<uid>/pid_<pid>/cgroup.freeze == 1``).
* Another process is already ptrace-attached (anti-debugging), visible as a
  non-zero ``TracerPid`` in ``/proc/<pid>/status``.

All checks need root on the device (``su``). The PID is always formatted as an
integer to avoid shell injection.
"""

from __future__ import annotations

import logging

from tlslibhunter.utils.adb import adb_shell

logger = logging.getLogger("tlslibhunter.utils.android_process")


def _freeze_path(pid: int) -> str:
    """Return the cgroup.freeze glob path for ``pid`` (coerced to int)."""
    return f"/sys/fs/cgroup/uid_*/pid_{int(pid)}/cgroup.freeze"


def _status_path(pid: int) -> str:
    """Return the /proc status path for ``pid`` (coerced to int)."""
    return f"/proc/{int(pid)}/status"


def _last_nonempty_line(output: str) -> str:
    """Return the last non-empty, stripped line of ``output`` (or "")."""
    lines = [line.strip() for line in output.strip().splitlines() if line.strip()]
    return lines[-1] if lines else ""


def read_freeze_state(pid: int, serial: str | None = None) -> bool | None:
    """Read whether ``pid`` is frozen by the cgroup v2 cached-apps freezer.

    Returns:
        True if cgroup.freeze is "1", False if "0", None if unknown
        (no root, missing file, adb error, unexpected output).
    """
    rc, out = adb_shell(f"su -c 'cat {_freeze_path(pid)}'", serial=serial)
    if rc != 0:
        logger.debug("freeze state read failed for pid %d: %s", int(pid), out.strip())
        return None
    value = _last_nonempty_line(out)
    if value == "1":
        return True
    if value == "0":
        return False
    logger.debug("unexpected cgroup.freeze output for pid %d: %r", int(pid), out)
    return None


def read_tracer_pid(pid: int, serial: str | None = None) -> int | None:
    """Read the TracerPid of ``pid`` from /proc/<pid>/status.

    Returns:
        The tracer PID (0 if not traced), or None if it could not be read.
    """
    rc, out = adb_shell(f"su -c 'grep TracerPid {_status_path(pid)}'", serial=serial)
    if rc != 0:
        logger.debug("TracerPid read failed for pid %d: %s", int(pid), out.strip())
        return None
    line = _last_nonempty_line(out)
    if not line.startswith("TracerPid:"):
        return None
    try:
        return int(line.split(":", 1)[1].strip())
    except ValueError:
        return None


def unfreeze(pid: int, serial: str | None = None) -> bool:
    """Thaw ``pid`` by writing 0 to its cgroup.freeze (requires root).

    Returns:
        True only if a follow-up read confirms the process is no longer frozen.
    """
    # Android's sh (mksh) does not glob-expand a redirection target, so
    # `echo 0 > /sys/fs/cgroup/uid_*/...` fails; a for-loop expands the glob.
    adb_shell(f"su -c 'for f in {_freeze_path(pid)}; do echo 0 > \"$f\"; done'", serial=serial)
    thawed = read_freeze_state(pid, serial) is False
    logger.debug("unfreeze pid %d: %s", int(pid), "ok" if thawed else "failed")
    return thawed


def _frozen_hint(pid: int) -> str:
    return (
        f"PID {pid} is frozen by Android's cached-apps freezer (cgroup.freeze=1), "
        "so it cannot handle the ptrace stop Frida waits for. Re-run with --unfreeze "
        "(needs root), or disable the freezer: adb shell settings put global "
        "cached_apps_freezer disabled, then reboot."
    )


def _traced_hint(pid: int, tracer: int) -> str:
    return (
        f"PID {pid} is already being ptraced by PID {tracer} (TracerPid) — likely "
        "anti-debugging. Try spawning it with -s instead."
    )


def _healthy_hint(pid: int) -> str:
    return (
        f"PID {pid} is neither frozen (cgroup.freeze=0) nor ptraced by another process "
        "(TracerPid=0), so the attach timeout is likely a frida-server problem. "
        "Try restarting frida-server and make sure the frida client and server "
        "versions match."
    )


def _unknown_hint(pid: int) -> str:
    return (
        f"Could not determine why attaching to PID {pid} timed out (root may be "
        "unavailable). Possible causes: (1) the process is frozen by Android's "
        f"cached-apps freezer, check with: adb shell su -c 'cat {_freeze_path(pid)}'; "
        "(2) another process is already ptrace-attached (anti-debugging), check "
        f"with: adb shell su -c 'grep TracerPid {_status_path(pid)}'."
    )


def diagnose_attach_timeout(pid: int, serial: str | None = None) -> str:
    """Return a human-readable hint explaining a Frida attach timeout on ``pid``."""
    pid = int(pid)
    frozen = read_freeze_state(pid, serial)
    if frozen:
        return _frozen_hint(pid)
    tracer = read_tracer_pid(pid, serial)
    if tracer:
        return _traced_hint(pid, tracer)
    if frozen is False and tracer == 0:
        return _healthy_hint(pid)
    return _unknown_hint(pid)
