"""Module classification - determines system vs app and TLS library type."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from tlslibhunter.platforms.detection import get_platform_handler
from tlslibhunter.scanner.tls_indicators import identify_library_type

if TYPE_CHECKING:
    pass

logger = logging.getLogger("tlslibhunter.scanner.classifier")


class ModuleClassifier:
    """Classifies loaded modules by their TLS library type and system/app status."""

    def __init__(self, platform: str, package_name: str | None = None):
        """Initialize classifier.

        Args:
            platform: Platform name (android, ios, windows, linux, macos)
            package_name: Optional package name for Android classification
        """
        self.platform = platform
        self.package_name = package_name
        self._handler = get_platform_handler(platform)

    def classify_module(
        self,
        name: str,
        path: str,
        matched_exports: list[str] | None = None,
        fingerprint_type: str | None = None,
        detected_version: str = "",
    ) -> dict[str, str]:
        """Classify a single module.

        Args:
            name: Module filename
            path: Full module path
            matched_exports: Export symbols found in the module
            fingerprint_type: Library type from fingerprint scanning
            detected_version: Version string from fingerprint scanning

        Returns:
            Dict with 'classification', 'library_type', and 'detected_version'
        """
        # Determine system vs app
        if self.platform == "android" and hasattr(self._handler, "classify"):
            classification = self._handler.classify(name, path, self.package_name)
        else:
            classification = self._handler.classify(name, path)

        # Identify TLS library type
        library_type = identify_library_type(name, matched_exports, fingerprint_type)

        # Apply platform-specific overrides
        library_type = self._apply_platform_override(library_type, name, path)

        return {
            "classification": classification,
            "library_type": library_type,
            "detected_version": detected_version,
        }

    def _apply_platform_override(self, library_type: str, name: str, path: str) -> str:
        """Apply platform-specific library type overrides.

        Handles cases where generic library names map to platform-specific forks:
        - Android system libssl/libcrypto → BoringSSL
        - macOS system libssl/libcrypto → LibreSSL
        - Chromium modules → BoringSSL

        Only overrides "openssl" to a more specific type. Never overrides
        other library types (e.g., gnutls stays gnutls).

        Args:
            library_type: Currently identified library type
            name: Module filename
            path: Full module path

        Returns:
            Possibly refined library type
        """
        name_lower = name.lower()
        path_lower = path.lower()

        # Only override openssl → more specific type
        if library_type == "openssl":
            # Android system libraries are BoringSSL
            if self.platform == "android":
                android_system_paths = ("/system/", "/vendor/", "/apex/")
                if any(p in path_lower for p in android_system_paths):
                    return "boringssl"

            # macOS system libraries are LibreSSL
            if self.platform == "macos":
                if path_lower.startswith("/usr/lib/"):
                    return "libressl"

        # Chromium modules use BoringSSL regardless of platform
        chromium_modules = ("libmonochrome", "libchrome", "libwebview")
        if any(cm in name_lower for cm in chromium_modules):
            return "boringssl"

        return library_type

    def is_scan_worthy(self, name: str, path: str) -> bool:
        """Check if a module is worth scanning for TLS patterns.

        Skips modules that are definitely not TLS libraries (like libc, libart, etc.)

        Args:
            name: Module filename
            path: Full module path

        Returns:
            True if the module should be scanned
        """
        name_lower = name.lower()

        # Skip known non-TLS system libraries
        skip_names = {
            "libc.so",
            "libm.so",
            "libdl.so",
            "libart.so",
            "liblog.so",
            "libz.so",
            "libstdc++.so",
            "ntdll.dll",
            "kernel32.dll",
            "kernelbase.dll",
            "user32.dll",
            "gdi32.dll",
            "advapi32.dll",
        }
        if name_lower in skip_names:
            return False

        # Skip ART runtime files on Android
        if self.platform == "android":
            art_extensions = (".odex", ".oat", ".vdex", ".art")
            if any(name_lower.endswith(ext) for ext in art_extensions):
                return False

        return True
