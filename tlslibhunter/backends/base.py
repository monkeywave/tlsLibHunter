"""Abstract backend interface and exception hierarchy."""

from __future__ import annotations

import abc
import logging
from typing import Any, Callable

logger = logging.getLogger("tlslibhunter.backends")


class BackendError(Exception):
    """Base exception for backend errors."""


class DeviceNotFoundError(BackendError):
    """Raised when the target device cannot be found."""


class ProcessNotFoundError(BackendError):
    """Raised when the target process cannot be found or attached to."""


class ScriptError(BackendError):
    """Raised when a Frida script fails to load or execute."""


class AttachmentError(BackendError):
    """Raised when attachment to a process fails."""


class AttachTimeoutError(AttachmentError):
    """Raised when Frida times out attaching (ptrace could not stop the process).

    This is a Frida-level failure -- typically a frozen or unresponsive app --
    not a tlsLibHunter bug. ``target`` and ``pid`` describe what was attempted.
    """

    def __init__(self, message: str, *, target: str | int | None = None, pid: int | None = None) -> None:
        super().__init__(message)
        self.target = target
        self.pid = pid


class Backend(abc.ABC):
    """Abstract instrumentation backend.

    Defines the interface that all backends (Frida, LLDB, etc.) must implement.
    """

    @abc.abstractmethod
    def get_device(
        self,
        mobile: bool = False,
        serial: str | None = None,
        host: str | None = None,
        timeout: int = 10,
    ) -> Any:
        """Get a device handle.

        Args:
            mobile: True to connect to first USB device.
            serial: Device serial/ID for a specific device (implies mobile).
            host: Remote device address (ip:port).
            timeout: Connection timeout in seconds.

        Returns:
            Device handle (type depends on backend).

        Raises:
            DeviceNotFoundError: If device cannot be found.
        """

    @abc.abstractmethod
    def attach(
        self,
        device: Any,
        target: str | int,
        timeout: int = 10,
        on_detached: Callable | None = None,
    ) -> Any:
        """Attach to a running process.

        Args:
            device: Device handle from get_device().
            target: Process name (str) or PID (int).
            timeout: Attachment timeout in seconds.
            on_detached: Optional callback invoked when the session detaches
                (e.g. the target process dies). Signature: ``cb(reason, crash)``.

        Returns:
            Session handle.

        Implementations MUST NOT silently substitute a different process for the
        one named. Specifically: if a process with the requested name exists but
        cannot be instrumented (hardened binary, missing entitlement, permission
        denied), raise rather than falling back to a near-match -- otherwise the
        caller gets a confident answer about the wrong process. A looser
        name match is only legitimate when no process carries the name, an
        ambiguous name must be refused, and any retarget must be logged at
        WARNING so it appears in normal output.

        Raises:
            ProcessNotFoundError: If process cannot be found.
            AttachmentError: If attachment fails, or the named process exists
                but cannot be instrumented, or the name is ambiguous.
        """

    @abc.abstractmethod
    def spawn(
        self,
        device: Any,
        target: str,
        timeout: int = 10,
        on_detached: Callable | None = None,
    ) -> Any:
        """Spawn a process and attach.

        Args:
            device: Device handle from get_device().
            target: Process/package name to spawn.
            timeout: Spawn timeout in seconds.
            on_detached: Optional callback invoked when the session detaches.
                Signature: ``cb(reason, crash)``.

        Returns:
            Session handle.

        Raises:
            ProcessNotFoundError: If process cannot be spawned.
        """

    @abc.abstractmethod
    def create_script(
        self,
        session: Any,
        source: str,
        on_message: Callable | None = None,
        on_script_destroyed: Callable | None = None,
    ) -> Any:
        """Create and load an instrumentation script.

        Args:
            session: Session handle from attach() or spawn().
            source: JavaScript source code.
            on_message: Optional message handler callback.
            on_script_destroyed: Optional callback invoked when the script is
                destroyed (e.g. the process died). Signature: ``cb()``.

        Returns:
            Script handle with exports accessible.

        Raises:
            ScriptError: If script fails to load.
        """

    def set_detached_callback(self, session: Any, callback: Callable) -> None:
        """Register a detach callback on an already-attached session.

        Default no-op for backends without session detach signals. Backends that
        support it (Frida) override this to wire ``session.on("detached", cb)``.

        Args:
            session: Session handle from attach() or spawn().
            callback: Invoked when the session detaches. Signature: ``cb(reason, crash)``.
        """
        return None

    def close(self) -> None:
        """Release resources owned by this backend *instance*. Idempotent.

        Scope is the instance, not the process: anything process-global (such as
        Frida's module-level device manager) must outlive a single run, so it is
        deliberately out of scope here.

        Default no-op: backends holding no per-instance state need nothing.
        """
        return None

    def unload_script(self, script: Any) -> None:
        """Unload a script, best-effort.

        Tolerates ``None`` and an already-dead script so callers can put it in a
        ``finally`` without guarding. Teardown must never mask the original
        failure it is cleaning up after.

        Args:
            script: Script handle from create_script(), or None.
        """
        if script is None:
            return
        try:
            script.unload()
        except Exception as e:
            # Swallowed, but not silently: a backend whose script handle has no
            # unload() would otherwise leak scripts with no trace at all.
            logger.debug("unload_script: %s: %s", type(e).__name__, e)

    def describe_session(self, device: Any, session: Any) -> dict[str, Any] | None:
        """Identify the process a session is really attached to.

        Name-based targeting can resolve to a process the caller did not name,
        so results must be labelled with what was actually instrumented rather
        than with what was requested.

        Args:
            device: Device handle from get_device().
            session: Session handle from attach() or spawn().

        Returns:
            ``{"pid": int, "name": str | None}``, or None when the backend
            cannot determine it. Default: None.
        """
        return None

    @abc.abstractmethod
    def detach(self, session: Any) -> None:
        """Detach from a process.

        Args:
            session: Session handle to detach.
        """

    @abc.abstractmethod
    def enumerate_processes(self, device: Any) -> list[dict[str, Any]]:
        """List running processes on the device.

        Args:
            device: Device handle.

        Returns:
            List of dicts with 'name' and 'pid' keys.
        """

    @abc.abstractmethod
    def get_device_platform(self, device: Any) -> str:
        """Detect the platform of the device.

        Args:
            device: Device handle.

        Returns:
            Platform string: "android", "ios", "windows", "linux", "macos"
        """
