"""Abstract backend interface and exception hierarchy."""

from __future__ import annotations

import abc
from typing import Any, Callable


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
    def attach(self, device: Any, target: str | int, timeout: int = 10) -> Any:
        """Attach to a running process.

        Args:
            device: Device handle from get_device().
            target: Process name (str) or PID (int).
            timeout: Attachment timeout in seconds.

        Returns:
            Session handle.

        Raises:
            ProcessNotFoundError: If process cannot be found.
            AttachmentError: If attachment fails.
        """

    @abc.abstractmethod
    def spawn(self, device: Any, target: str, timeout: int = 10) -> Any:
        """Spawn a process and attach.

        Args:
            device: Device handle from get_device().
            target: Process/package name to spawn.
            timeout: Spawn timeout in seconds.

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
    ) -> Any:
        """Create and load an instrumentation script.

        Args:
            session: Session handle from attach() or spawn().
            source: JavaScript source code.
            on_message: Optional message handler callback.

        Returns:
            Script handle with exports accessible.

        Raises:
            ScriptError: If script fails to load.
        """

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
