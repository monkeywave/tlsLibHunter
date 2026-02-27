"""Scan and extraction result dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectedLibrary:
    """A single detected TLS/SSL library."""

    name: str
    path: str
    base_address: str = ""
    size: int = 0
    # openssl, boringssl, gnutls, wolfssl, mbedtls, schannel, nss, securetransport, unknown
    library_type: str = "unknown"
    classification: str = "unknown"  # system, app, unknown
    matched_patterns: list[str] = field(default_factory=list)
    matched_exports: list[str] = field(default_factory=list)
    matched_fingerprints: list[str] = field(default_factory=list)
    detected_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "base_address": self.base_address,
            "size": self.size,
            "library_type": self.library_type,
            "classification": self.classification,
            "matched_patterns": self.matched_patterns,
            "matched_exports": self.matched_exports,
            "matched_fingerprints": self.matched_fingerprints,
            "detected_version": self.detected_version,
        }


@dataclass
class ScanResult:
    """Full scan result with metadata."""

    target: str
    platform: str = "unknown"
    backend: str = "frida"
    libraries: list[DetectedLibrary] = field(default_factory=list)
    total_modules_scanned: int = 0
    scan_duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def tls_library_count(self) -> int:
        return len(self.libraries)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "platform": self.platform,
            "backend": self.backend,
            "libraries": [lib.to_dict() for lib in self.libraries],
            "total_modules_scanned": self.total_modules_scanned,
            "scan_duration_seconds": self.scan_duration_seconds,
            "tls_library_count": self.tls_library_count,
            "errors": self.errors,
        }


@dataclass
class ExtractionResult:
    """Result of a library extraction."""

    library: DetectedLibrary
    success: bool
    output_path: str = ""
    method: str = ""  # disk_copy, memory_dump, adb_pull, apk_extract, frida_read
    size_bytes: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "library_name": self.library.name,
            "success": self.success,
            "output_path": self.output_path,
            "method": self.method,
            "size_bytes": self.size_bytes,
            "error": self.error,
        }
