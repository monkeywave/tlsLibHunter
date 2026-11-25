"""Frida instrumentation backend."""

from __future__ import annotations

import contextlib
import logging
import re
import threading
from typing import Any, Callable

from tlslibhunter.backends.base import (
    AttachmentError,
    AttachTimeoutError,
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


# frida's DeviceManager is process-global, so a remote device registered by one
# backend is visible to every other. Removing it on close() would rip the device
# out from under a second hunter still scanning through the same host, so
# registrations are reference-counted across the process and only the last user
# out removes the device.
_remote_host_lock = threading.Lock()
_remote_host_users: dict[str, int] = {}
_remote_hosts_registered: set[str] = set()


def _acquire_remote_host(host: str, registered_now: bool) -> None:
    """Record that a backend is using *host*."""
    with _remote_host_lock:
        _remote_host_users[host] = _remote_host_users.get(host, 0) + 1
        if registered_now:
            _remote_hosts_registered.add(host)


def _release_remote_host(host: str) -> bool:
    """Drop one use of *host*; True when the caller should remove the device."""
    with _remote_host_lock:
        remaining = _remote_host_users.get(host, 0) - 1
        if remaining > 0:
            _remote_host_users[host] = remaining
            return False
        _remote_host_users.pop(host, None)
        # Only remove a device this process actually registered.
        was_registered = host in _remote_hosts_registered
        _remote_hosts_registered.discard(host)
        return was_registered


def _forward_agent_log(level: str, text: str) -> None:
    """Send agent console.log output to the log stream instead of stdout.

    Frida's default handler prints info-level agent logs to **stdout**
    (frida/core.py default_log_handler), the same stream the formatted result
    goes to -- which made ``--format json`` impossible to parse. Routing them
    through logging keeps the messages (the agent deliberately reports skipped
    ranges) while leaving stdout to carry only the result.
    """
    agent_logger.log(_AGENT_LOG_LEVELS.get(level, logging.INFO), "%s", text)


class _NeverRaised(Exception):
    """Placeholder for frida exception classes absent from a (fake) frida module."""


def _timed_out_error(frida: Any) -> type[BaseException]:
    """``frida.TimedOutError``, or a class nothing raises if the module lacks it."""
    return getattr(frida, "TimedOutError", _NeverRaised)


def _is_attach_timeout(frida: Any, error: Exception) -> bool:
    """True when an attach failed because Frida timed out waiting on the process.

    Older frida reports this as ``TimedOutError`` ("timed out while waiting for
    stop from process"); frida 17.26+ reports the same frozen-process case as
    ``TransportError: timeout was reached``.
    """
    if isinstance(error, _timed_out_error(frida)):
        return True
    transport_error = getattr(frida, "TransportError", _NeverRaised)
    return isinstance(error, transport_error) and "timeout" in str(error).lower()


_PID_IN_MESSAGE = re.compile(r"PID (\d+)")


def _resolve_pid_for_timeout(device: Any, target: str, error: Exception) -> int | None:
    """Best-effort PID for a named target whose attach timed out."""
    try:
        return int(device.get_process(target).pid)
    except Exception:
        match = _PID_IN_MESSAGE.search(str(error))
        return int(match.group(1)) if match else None


def _attach_timeout_message(device: Any, target: str | int, pid: int | None, error: Exception) -> str:
    """Explain a Frida attach timeout as the Frida-level failure it is."""
    pid_part = f" (PID {pid})" if pid is not None else ""
    device_id = getattr(device, "id", None)
    device_part = f"-D {device_id} " if device_id else ""
    return (
        f"Frida timed out attaching to '{target}'{pid_part}: {error}. "
        f"This is a Frida-level failure: ptrace could not stop the process, so plain "
        f"`frida {device_part}{target}` fails the same way. It is not a tlsLibHunter bug."
    )


def _attach_timeout_error(device: Any, target: str | int, pid: int | None, error: Exception) -> AttachTimeoutError:
    """Build the AttachTimeoutError for a timed-out attach to *target*."""
    return AttachTimeoutError(_attach_timeout_message(device, target, pid, error), target=target, pid=pid)


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
        # Remote hosts this instance is USING (one entry per get_device call),
        # used to release its share of the process-wide reference count.
        self._remote_hosts: list[str] = []
        self._device_manager: Any = None

    def close(self) -> None:
        """Release per-instance resources. Idempotent.

        Scope is this backend object, NOT the process: frida's device manager is
        a module-global that must outlive us.
        """
        manager = self._device_manager
        for host in reversed(self._remote_hosts):
            if _release_remote_host(host) and manager is not None:
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
                registered_now = True
                try:
                    manager.add_remote_device(host)
                except Exception as e:
                    # Usually "already registered" by another backend in this
                    # process; we still take a reference so the device is not
                    # removed while we are using it.
                    logger.debug("add_remote_device(%s): %s", host, e)
                    registered_now = False
                _acquire_remote_host(host, registered_now)
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
                if _is_attach_timeout(frida, e):
                    raise _attach_timeout_error(device, target, target, e) from e
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
            # name match is legitimate here, and only here.
            return self._attach_by_name_match(device, target, e, on_detached)
        except (frida.PermissionDeniedError, frida.NotSupportedError) as e:
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
        except Exception as e:
            if _is_attach_timeout(frida, e):
                # The exactly-named process exists but Frida could not stop it
                # (typically a frozen app). Say plainly that this is Frida-level.
                pid = _resolve_pid_for_timeout(device, target, e)
                raise _attach_timeout_error(device, target, pid, e) from e
            # Anything else is a transport/link failure, not a statement about
            # this process: frida resolves the name by enumerating over the
            # device link first, so a dead frida-server surfaces here too.
            # Report it verbatim rather than blaming the target -- but still do
            # not fall back to a name match, which would attach to the wrong
            # process on a link that is merely flaky.
            raise AttachmentError(f"Failed to attach to '{target}': {e}") from e

        logger.debug("Attached to '%s'", target)
        self.set_detached_callback(session, on_detached)
        return session

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
            # No process matches -- but on mobile the user usually names an app
            # by its label ("Gemini") or identifier, neither of which is the
            # process name. Consult the installed apps before giving up.
            return self._attach_by_application(device, target, on_detached)

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

    def _find_applications(self, device: Any, target: str) -> list:
        """Installed apps whose label or identifier matches *target*.

        Exact matches (on either field) win; otherwise loose matches are
        returned. Best-effort: devices without app enumeration (desktop) or any
        enumeration failure yield an empty list.
        """
        try:
            apps = list(device.enumerate_applications())
        except Exception as e:
            logger.debug("Could not enumerate applications: %s", e)
            return []

        target = str(target)
        exact = [a for a in apps if is_exact_name(a.name, target) or is_exact_name(a.identifier, target)]
        if exact:
            return exact
        return [a for a in apps if name_matches(a.name, target) or name_matches(a.identifier, target)]

    def _attach_by_application(self, device: Any, target: str, on_detached: Callable | None = None) -> Any:
        """Attach to a running app matching *target*, or explain why we cannot."""
        apps = self._find_applications(device, target)
        running = [a for a in apps if a.pid]
        if running:
            return self._attach_to_app(device, target, running[0], on_detached)
        if apps:
            raise ProcessNotFoundError(self._not_running_message(target, apps))
        raise ProcessNotFoundError(self._no_match_message(device, target))

    def _attach_to_app(self, device: Any, target: str, app: Any, on_detached: Callable | None = None) -> Any:
        """Attach to the main process of a running *app*."""
        frida = _import_frida()
        try:
            session = device.attach(app.pid)
        except Exception as e:
            if _is_attach_timeout(frida, e):
                raise _attach_timeout_error(device, target, app.pid, e) from e
            raise AttachmentError(f"Failed to attach to app '{app.name}' ({app.identifier}, PID {app.pid}): {e}") from e
        logger.warning(
            "No process is named exactly '%s'; attached to app '%s' (%s, PID %d). Results describe THAT process.",
            target,
            app.name,
            app.identifier,
            app.pid,
        )
        self.set_detached_callback(session, on_detached)
        return session

    @staticmethod
    def _not_running_message(target: str, apps: list) -> str:
        """Error text for an app that is installed but has no running process."""
        if len(apps) == 1:
            identifier = apps[0].identifier
            return (
                f"'{target}' is installed ({identifier}) but not running. Start the app first, "
                f"or re-run with -s to spawn it, e.g.: tlsLibHunter -m -s {identifier}"
            )
        listed = "\n  ".join(f"{a.name} ({a.identifier})" for a in apps)
        return (
            f"'{target}' matches several installed apps, none of them running:\n  {listed}\n"
            f"Start the app first, or re-run with -s <identifier> to spawn it, "
            f"e.g.: tlsLibHunter -m -s {apps[0].identifier}"
        )

    def _no_match_message(self, device: Any, target: str) -> str:
        """Error text when neither a process nor an installed app matches."""
        message = f"Process '{target}' is not running and no installed app matches it."
        running = self._running_apps(device)
        if running:
            listed = "\n  ".join(f"{a.name} ({a.identifier}, PID {a.pid})" for a in running[:10])
            message += f"\nRunning apps:\n  {listed}"
        return message + "\nList apps with: frida-ps -Uai (mobile) or frida-ps (local)"

    @staticmethod
    def _running_apps(device: Any) -> list:
        """Apps with a live process, or [] when the device cannot enumerate apps."""
        try:
            return [a for a in device.enumerate_applications() if a.pid]
        except Exception as e:
            logger.debug("Could not enumerate applications: %s", e)
            return []

    def resolve_app_identifier(self, device: Any, target: str) -> str:
        """Public alias of the app label -> identifier mapping (e.g. ``Gemini`` -> package)."""
        return self._resolve_spawn_target(device, target)

    def _resolve_spawn_target(self, device: Any, target: str) -> str:
        """Map an app label to its identifier so mobile spawn() can find it.

        Identifiers and anything not matching an installed app (desktop paths
        and binaries) are returned unchanged.
        """
        apps = self._find_applications(device, target)
        if any(a.identifier == target for a in apps):
            return target
        labelled = [a for a in apps if is_exact_name(a.name, target)]
        if len(labelled) > 1:
            listed = ", ".join(f"{a.name} ({a.identifier})" for a in labelled)
            raise ProcessNotFoundError(
                f"'{target}' is ambiguous: {len(labelled)} installed apps share that label "
                f"({listed}). Re-run with the app identifier."
            )
        if labelled:
            logger.info("Resolved '%s' to app identifier '%s'", target, labelled[0].identifier)
            return labelled[0].identifier
        return target

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
            # Always confirm the pid rather than trusting matches[0]: a backend
            # that ignores the `pids` filter returns the whole process list, and
            # taking the first entry would stamp an unrelated process name onto
            # the result -- exactly the mislabelling this code exists to prevent.
            for source in (device.enumerate_processes(pids=[pid]), device.enumerate_processes()):
                for proc in source:
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
        # Resolved before the try: an ambiguous label is reported as-is rather
        # than wrapped in "Failed to spawn".
        target = self._resolve_spawn_target(device, str(target))
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
