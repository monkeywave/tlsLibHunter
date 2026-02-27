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

logger = logging.getLogger("tlslibhunter.backends.frida")


def _import_frida():
    """Import frida with a helpful error message."""
    try:
        import frida

        return frida
    except ImportError as e:
        raise ImportError("Frida is required but not installed. Install with:\n  pip install frida frida-tools") from e


class FridaBackend(Backend):
    """Frida-based instrumentation backend."""

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
                with contextlib.suppress(Exception):
                    manager.add_remote_device(host)
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

    def attach(self, device: Any, target: str | int, timeout: int = 10) -> Any:
        # Try direct attachment first
        try:
            if isinstance(target, int):
                session = device.attach(target)
                logger.debug("Attached to PID %d", target)
                return session
            else:
                session = device.attach(target)
                logger.debug("Attached to '%s'", target)
                return session
        except Exception as e:
            last_error = e
            logger.debug("Direct attachment to '%s' failed: %s", target, e)

        if isinstance(target, int):
            raise AttachmentError(f"Failed to attach to PID {target}: {last_error}")

        # Fuzzy match by process name
        try:
            procs = device.enumerate_processes()
        except Exception as e:
            raise AttachmentError(f"Failed to attach to '{target}': {last_error}") from e

        target_lower = str(target).lower()
        for proc in procs:
            proc_lower = proc.name.lower()
            if target_lower in proc_lower or proc_lower in target_lower:
                logger.info("Found match: '%s' (PID %d)", proc.name, proc.pid)
                try:
                    session = device.attach(proc.pid)
                    logger.info("Attached to '%s' (PID %d)", proc.name, proc.pid)
                    return session
                except Exception:
                    continue

        # List available processes for error message
        proc_names = [f"{p.name} (PID {p.pid})" for p in procs[:20]]
        raise ProcessNotFoundError(f"Process '{target}' not found. Available processes:\n  " + "\n  ".join(proc_names))

    def spawn(self, device: Any, target: str, timeout: int = 10) -> Any:
        try:
            pid = device.spawn([target])
            session = device.attach(pid)
            device.resume(pid)
            logger.info("Spawned and attached to '%s' (PID %d)", target, pid)
            return session
        except Exception as e:
            raise ProcessNotFoundError(f"Failed to spawn '{target}': {e}") from e

    def create_script(
        self,
        session: Any,
        source: str,
        on_message: Callable | None = None,
    ) -> Any:
        try:
            script = session.create_script(source)
            if on_message:
                script.on("message", on_message)
            script.load()
            logger.debug("Script loaded successfully")
            return script
        except Exception as e:
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
