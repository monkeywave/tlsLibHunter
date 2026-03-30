"""Configuration dataclasses for TLSLibHunter."""

from __future__ import annotations

import warnings
from dataclasses import dataclass


@dataclass
class HunterConfig:
    """Configuration for TLSLibHunter.

    Attributes:
        target: Process name, PID, or package name to scan.
        mobile: Mobile device mode flag.
        serial: Device serial/ID (implies mobile=True).
        host: Remote Frida device (ip:port).
        spawn: Spawn process instead of attaching.
        backend: Instrumentation backend name (default: "frida").
        timeout: Attachment timeout in seconds.
        list_only: Only list TLS libraries, skip extraction.
        output_dir: Directory for extracted libraries.
        format: Output format ("table", "json", "plain").
        debug: Enable debug logging.
        verbose: Show all scanned modules.
        scan_mode: Scanning mode ("standard" or "labels").
        scan_split_constants: Search for split substrings of TLS string patterns.
        scan_stack_strings: Scan writable memory for runtime-assembled stack strings.
        scan_rwx_regions: Scan process-wide RWX (JIT) memory regions.
        scan_encoded_strings: Search for XOR/base64-encoded TLS strings.
    """

    target: str = ""
    mobile: bool = False
    serial: str | None = None
    host: str | None = None
    spawn: bool = False
    backend: str = "frida"
    timeout: int = 10
    list_only: bool = False
    output_dir: str | None = None
    format: str = "table"
    debug: bool = False
    verbose: bool = False
    scan_mode: str = "standard"
    scan_split_constants: bool = False
    scan_stack_strings: bool = False
    scan_rwx_regions: bool = False
    scan_encoded_strings: bool = False

    def __post_init__(self):
        # Deprecation shim: if someone passes a string to mobile, migrate to serial
        if isinstance(self.mobile, str):
            warnings.warn(
                "Passing a serial string to 'mobile' is deprecated. Use serial='...' instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            self.serial = self.mobile
            self.mobile = True
        elif self.mobile is None:
            self.mobile = False

    @property
    def is_mobile(self) -> bool:
        """Check if targeting a mobile device."""
        return self.mobile or self.serial is not None

    @property
    def device_serial(self) -> str | None:
        """Get device serial if specified."""
        return self.serial

    @property
    def effective_output_dir(self) -> str:
        """Get output directory, using default if not set."""
        if self.output_dir:
            return self.output_dir
        safe_target = str(self.target).replace("/", "_").replace("\\", "_")
        return f"./tls_libs_{safe_target}"
