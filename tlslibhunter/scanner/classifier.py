"""Module classification - determines system vs app and TLS library type."""

from __future__ import annotations

import logging

from tlslibhunter.platforms.detection import get_platform_handler
from tlslibhunter.platforms.macos import SYSTEM_FRAMEWORK_PREFIXES
from tlslibhunter.scanner.tls_indicators import (
    KNOWN_TLS_LIBRARY_EXACT,
    KNOWN_TLS_LIBRARY_STEMS,
    _extract_stem,
    identify_library_type,
)

logger = logging.getLogger("tlslibhunter.scanner.classifier")

# macOS/iOS libraries that are NOT TLS implementations despite confusing names.
# Defense-in-depth: also skips expensive pattern scanning for these modules.
_MACOS_NON_TLS = frozenset({
    "libcommoncrypto.dylib",
    "securityhi",
    "securityfoundation",
    "securityinterface",
    "libinterpretersecurity.dylib",
    "libendpointsecuritysystem.dylib",
    "messagesecurity",
    "networkserviceproxy",
    "libnetworkextension.dylib",
    "libsystem_networkextension.dylib",
    "networkextension",
    "captivenetwork",
    "libbnns.dylib",
    "mpsneuralnetwork",
    "locationlogencryption",
    "launchservices",
    "libsoftokn3.dylib",
})

# Derive TLS candidate stems from the canonical lists in tls_indicators,
# plus a few extra consumer libraries we want to scan on macOS.
_MACOS_EXTRA_TLS_STEMS = frozenset({
    "libcrypto", "libtls", "libnspr4", "libcurl", "libssh2",
})
_MACOS_TLS_CANDIDATE_STEMS = (
    frozenset(KNOWN_TLS_LIBRARY_STEMS) | frozenset(KNOWN_TLS_LIBRARY_EXACT) | _MACOS_EXTRA_TLS_STEMS
)

# Substrings in module name/path that hint at TLS relevance.
_TLS_PATH_KEYWORDS = ("ssl", "tls", "crypto", "nss")


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
            if self.platform == "macos" and path_lower.startswith("/usr/lib/"):
                return "libressl"

        # macOS libcoretls is Apple's CoreTLS, classified under securetransport
        if self.platform in ("macos", "ios") and "libcoretls" in name_lower:
            return "securetransport"

        # Chromium modules use BoringSSL regardless of platform
        chromium_modules = ("libmonochrome", "libchrome", "libwebview")
        if any(cm in name_lower for cm in chromium_modules):
            return "boringssl"

        # Schannel is Windows-only; reject on other platforms
        if library_type == "schannel" and self.platform != "windows":
            logger.debug(
                "Rejecting schannel classification for %s on %s (Windows-only)",
                name,
                self.platform,
            )
            return "unknown"

        return library_type

    def is_system_library(self, name: str, path: str) -> bool:
        """Check if a library is a system/OS library.

        Args:
            name: Module filename
            path: Full module path

        Returns:
            True if the library is a system library
        """
        return self._handler.is_system_library(name, path)

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

        # Skip known non-TLS macOS/iOS libraries with confusing names
        if self.platform in ("macos", "ios"):
            if name_lower in _MACOS_NON_TLS:
                return False

        return True

    def is_tls_candidate(self, name: str, path: str) -> bool:
        """Stricter than is_scan_worthy — aggressively filters macOS system frameworks.

        On macOS, most of the ~1000 loaded modules come from /System/Library/ paths
        and are UI, audio, graphics, etc. frameworks. This method skips them unless
        the module name matches a TLS-candidate whitelist or contains TLS keywords.

        Non-system paths always pass through (app-bundled libraries must be scanned).

        Args:
            name: Module filename
            path: Full module path

        Returns:
            True if the module should proceed to TLS scanning pipeline
        """
        # First apply the basic non-TLS filter
        if not self.is_scan_worthy(name, path):
            return False

        # Aggressive filtering only applies to macOS/iOS
        if self.platform not in ("macos", "ios"):
            return True

        # Non-system paths always pass (app-bundled, homebrew, etc.)
        if not path or not any(path.startswith(p) for p in SYSTEM_FRAMEWORK_PREFIXES):
            if not path or not path.startswith("/usr/lib/"):
                return True
            # For /usr/lib/ libs, also apply the keyword/stem check below

        # System framework path — only keep if name suggests TLS relevance
        name_lower = name.lower()
        stem = _extract_stem(name)

        if stem in _MACOS_TLS_CANDIDATE_STEMS:
            return True

        # Check if name or path contains TLS-related keywords
        if any(kw in name_lower for kw in _TLS_PATH_KEYWORDS):
            return True

        return False
