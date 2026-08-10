"""Frida instrumentation backend."""

from __future__ import annotations

import contextlib
import logging
from typing import Any, Callable

from tlslibhunter.backends.base import (
    AttachmentError,
    Backend,
    DeviceNotFoundError,
    ProcessNotFoundError,
    ScriptError,
)
from tlslibhunter.utils.process_resolver import is_exact_name, name_matches

logger = logging.getLogger("tlslibhunter.backends.frida")
agent_logger = logging.getLogger("tlslibhunter.agent")

# console.log levels used by the agent, mapped onto Python logging levels.
_AGENT_LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}


def _forward_agent_log(level: str, text: str) -> None:
    """Send agent console.log output to the log stream instead of stdout.

    Frida's default handler prints info-level agent logs to **stdout**
    (frida/core.py default_log_handler), the same stream the formatted result
    goes to -- which made ``--format json`` impossible to parse. Routing them
    through logging keeps the messages (the agent deliberately reports skipped
    ranges) while leaving stdout to carry only the result.
    """
    agent_logger.log(_AGENT_LOG_LEVELS.get(level, logging.INFO), "%s", text)


def _import_frida():
    """Import frida with a helpful error message."""
    try:
        import frida

        return frida
    except ImportError as e:
        raise ImportError("Frida is required but not installed. Install with:\n  pip install frida frida-tools") from e


class FridaBackend(Backend):
    """Frida-based instrumentation backend."""

    def __init__(self) -> None:
        # Remote devices this instance registered, so close() removes only those.
        self._remote_hosts: list[str] = []
        self._device_manager: Any = None

    def close(self) -> None:
        """Release per-instance resources. Idempotent.

        Scope is this backend object, NOT the process: frida's device manager is
        a module-global that must outlive us.
        """
        manager = self._device_manager
        if manager is not None:
            for host in reversed(self._remote_hosts):
                try:
                    manager.remove_remote_device(host)
                    logger.debug("Removed remote device: %s", host)
                except Exception as e:
                    logger.debug("remove_remote_device(%s): %s", host, e)
        self._remote_hosts.clear()
        self._device_manager = None

    def get_device(
        self,
        mobile: bool = False,
        serial: str | None = None,
        host: str | None = None,
        timeout: int = 10,
    ) -> Any:
        frida = _import_frida()

        try:
            if host:
                manager = frida.get_device_manager()
                self._device_manager = manager
                try:
                    manager.add_remote_device(host)
                except Exception as e:
                    # Already registered by someone else in this process, or
                    # rejected. Only record hosts WE added, so close() never
                    # removes a device another caller owns.
                    logger.debug("add_remote_device(%s): %s", host, e)
                else:
                    self._remote_hosts.append(host)
                device = frida.get_device(host, timeout=timeout)
                logger.debug("Connected to remote device: %s", host)
            elif serial:
                device = frida.get_device(serial, timeout=timeout)
                logger.debug("Connected to device: %s", serial)
            elif mobile:
                device = frida.get_usb_device(timeout=timeout)
                logger.debug("Connected to USB device")
            else:
                device = frida.get_local_device()
                logger.debug("Using local device")
            return device
        except Exception as e:
            raise DeviceNotFoundError(f"Failed to get device: {e}") from e

    def set_detached_callback(self, session: Any, callback: Callable) -> None:
        """Register a detach handler on an existing session (frida session.on)."""
        if callback is None:
            return
        with contextlib.suppress(Exception):
            session.on("detached", callback)

    def attach(
        self,
        device: Any,
        target: str | int,
        timeout: int = 10,
        on_detached: Callable | None = None,
    ) -> Any:
        frida = _import_frida()

        # A PID is unambiguous: attach to exactly it, or fail. Never substitute
        # a different process for one the caller identified numerically.
        if isinstance(target, int):
            try:
                session = device.attach(target)
            except Exception as e:
                raise AttachmentError(f"Failed to attach to PID {target}: {e}") from e
            logger.debug("Attached to PID %d", target)
            self.set_detached_callback(session, on_detached)
            return session

        # Frida resolves a bare name with an exact (fnmatchcase) comparison and
        # raises ProcessNotFoundError for both "no such name" and "ambiguous
        # name" -- so this attempt is authoritative for the exactly-named
        # process, and any OTHER exception means that process exists.
        try:
            session = device.attach(target)
        except frida.ProcessNotFoundError as e:
            # No single process carries this name. Falling back to a looser
            # name match below is legitimate.
            resolve_error: Exception = e
        except Exception as e:
            # The exactly-named process EXISTS but cannot be instrumented: a
            # hardened or SIP-protected binary, a missing entitlement, or denied
            # permission. Retargeting by name here would silently scan a
            # DIFFERENT process and report it under the requested name -- that
            # is how `tlslibhunter Finder` came to scan a QLMarkdown Quick Look
            # plugin and label the table "Finder". Fail loudly instead.
            raise AttachmentError(
                f"Found process '{target}' but could not attach to it: {e}. "
                f"It is likely hardened or SIP-protected; another process is NOT "
                f"substituted. Pass an explicit PID to override."
            ) from e
        else:
            logger.debug("Attached to '%s'", target)
            self.set_detached_callback(session, on_detached)
            return session

        return self._attach_by_name_match(device, target, resolve_error, on_detached)

    def _attach_by_name_match(
        self,
        device: Any,
        target: str,
        resolve_error: Exception,
        on_detached: Callable | None = None,
    ) -> Any:
        """Attach to a process whose name merely *contains* the requested target.

        Only reached when no single process carries the requested name exactly.
        Every retarget is reported at WARNING (not INFO) together with the
        alternatives, because the results then describe a process the caller did
        not name.
        """
        try:
            procs = device.enumerate_processes()
        except Exception as e:
            raise AttachmentError(f"Failed to attach to '{target}': {resolve_error}") from e

        target = str(target)

        # Several processes share the exact name. Frida refused to guess between
        # them and so do we -- picking one silently makes the scan irreproducible.
        exact = [p for p in procs if is_exact_name(p.name, target)]
        if len(exact) > 1:
            listed = ", ".join(f"{p.name} (PID {p.pid})" for p in exact)
            raise AttachmentError(
                f"'{target}' is ambiguous: {len(exact)} processes share that name "
                f"({listed}). Re-run with an explicit PID."
            )

        candidates = [p for p in procs if name_matches(p.name, target)]
        if not candidates:
            # Preserved from the original: show the user what IS running.
            proc_names = [f"{p.name} (PID {p.pid})" for p in procs[:20]]
            raise ProcessNotFoundError(
                f"Process '{target}' not found. Available processes:\n  " + "\n  ".join(proc_names)
            )

        alternatives = ", ".join(f"{p.name} (PID {p.pid})" for p in candidates[:5])
        last_error: Exception | None = None
        for proc in candidates:
            try:
                session = device.attach(proc.pid)
            except Exception as e:
                last_error = e
                logger.debug("Name match '%s' (PID %d) failed: %s", proc.name, proc.pid, e)
                continue
            logger.warning(
                "No process is named exactly '%s'; attached to '%s' (PID %d) by name match. "
                "Results describe THAT process. Candidates were: %s",
                target,
                proc.name,
                proc.pid,
                alternatives,
            )
            self.set_detached_callback(session, on_detached)
            return session

        raise AttachmentError(
            f"Process '{target}' not found, and none of the {len(candidates)} name "
            f"match(es) could be attached ({alternatives}). Last error: {last_error}"
        )

    def describe_session(self, device: Any, session: Any) -> dict[str, Any] | None:
        """Identify the process a session is really attached to.

        Used to label results with the truth rather than with what was
        requested. Best-effort: returns None when the backend cannot tell.
        """
        pid = self._session_pid(session)
        if pid is None:
            return None
        return {"pid": pid, "name": self._process_name(device, pid)}

    @staticmethod
    def _session_pid(session: Any) -> int | None:
        """PID behind a frida session.

        ``frida.core.Session`` does NOT proxy ``pid`` -- only the native
        ``_frida.Session`` carries it -- so the private ``_impl`` is the only
        route. Frida's own ``shutdown()`` reaches through ``_impl`` the same way.
        The public attribute is tried first so a future frida that exposes it
        wins.
        """
        for candidate in (session, getattr(session, "_impl", None)):
            pid = getattr(candidate, "pid", None)
            if isinstance(pid, int):
                return pid
        return None

    @staticmethod
    def _process_name(device: Any, pid: int) -> str | None:
        """Name for *pid*, or None if it cannot be resolved."""
        try:
            matches = device.enumerate_processes(pids=[pid])
            if matches:
                return matches[0].name
            # Some backends ignore the pids filter; fall back to a full sweep.
            for proc in device.enumerate_processes():
                if proc.pid == pid:
                    return proc.name
        except Exception as e:
            logger.debug("Could not resolve name for PID %d: %s", pid, e)
        return None

    def spawn(
        self,
        device: Any,
        target: str,
        timeout: int = 10,
        on_detached: Callable | None = None,
    ) -> Any:
        pid = None
        session = None
        try:
            pid = device.spawn([target])
            session = device.attach(pid)
            self.set_detached_callback(session, on_detached)
            device.resume(pid)
            logger.info("Spawned and attached to '%s' (PID %d)", target, pid)
            return session
        except Exception as e:
            # device.spawn() returns a SUSPENDED process. If attach or resume
            # then fails, nothing will ever resume or reap it -- it would sit
            # frozen for the lifetime of the machine. Clean it up before
            # reporting the failure.
            self._abandon_spawn(device, pid, session)
            raise ProcessNotFoundError(f"Failed to spawn '{target}': {e}") from e

    def _abandon_spawn(self, device: Any, pid: int | None, session: Any) -> None:
        """Tear down a spawned-but-unusable target."""
        if session is not None:
            self.detach(session)
        if pid is None:
            return  # device.spawn() itself failed -- nothing exists to kill
        try:
            device.kill(pid)
            logger.debug("Killed orphaned spawn (PID %d)", pid)
        except Exception as e:
            logger.warning("Could not kill orphaned spawn (PID %d): %s", pid, e)

    def create_script(
        self,
        session: Any,
        source: str,
        on_message: Callable | None = None,
        on_script_destroyed: Callable | None = None,
    ) -> Any:
        script = None
        try:
            script = session.create_script(source)
            # Install before load() so logs emitted during startup are captured.
            with contextlib.suppress(Exception):
                script.set_log_handler(_forward_agent_log)
            if on_message:
                script.on("message", on_message)
            if on_script_destroyed:
                with contextlib.suppress(Exception):
                    script.on("destroyed", on_script_destroyed)
            script.load()
            logger.debug("Script loaded successfully")
            return script
        except Exception as e:
            # A script that was created but failed to load still exists in the
            # target; without this it would stay resident for the whole session.
            self.unload_script(script)
            raise ScriptError(f"Failed to create/load script: {e}") from e

    def detach(self, session: Any) -> None:
        try:
            session.detach()
            logger.debug("Session detached")
        except Exception as e:
            logger.warning("Error detaching session: %s", e)

    def enumerate_processes(self, device: Any) -> list[dict[str, Any]]:
        try:
            procs = device.enumerate_processes()
            return [{"name": p.name, "pid": p.pid} for p in procs]
        except Exception as e:
            logger.warning("Failed to enumerate processes: %s", e)
            return []

    def get_device_platform(self, device: Any) -> str:
        try:
            params = device.query_system_parameters()
            os_name = params.get("os", {}).get("id", "").lower()
            if "android" in os_name:
                return "android"
            elif "ios" in os_name:
                return "ios"
            elif "windows" in os_name:
                return "windows"
            elif "darwin" in os_name or "macos" in os_name:
                return "macos"
            elif "linux" in os_name:
                return "linux"
        except Exception:
            pass

        # Fallback: check device type
        try:
            dtype = str(device.type).lower()
            if "usb" in dtype or "remote" in dtype:
                return "android"  # Most common mobile target
        except Exception:
            pass

        # Local device: detect from Python's platform
        import platform

        system = platform.system().lower()
        if system == "darwin":
            return "macos"
        elif system == "windows":
            return "windows"
        return "linux"
