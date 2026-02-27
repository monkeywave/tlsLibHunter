"""Module scanner - orchestrates Frida-side TLS pattern scanning."""

from __future__ import annotations

import contextlib
import logging
import os
import time
from typing import Any

from tlslibhunter.scanner.classifier import ModuleClassifier
from tlslibhunter.scanner.fingerprints import fingerprint_library, get_all_fingerprint_strings
from tlslibhunter.scanner.results import DetectedLibrary, ScanResult
from tlslibhunter.scanner.tls_indicators import TLS_EXPORT_SYMBOLS, TLS_STRING_PATTERNS
from tlslibhunter.utils.encoding import build_scan_patterns

logger = logging.getLogger("tlslibhunter.scanner")

# Path to the scanner agent JS file
_SCANNER_JS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "scanner_agent.js")


def _load_scanner_js() -> str:
    """Load the scanner agent JavaScript source."""
    with open(_SCANNER_JS) as f:
        return f.read()


def _build_all_hex_patterns() -> list[str]:
    """Build hex patterns for all TLS string indicators."""
    patterns = []
    for s in TLS_STRING_PATTERNS:
        patterns.extend(build_scan_patterns(s))
    # Deduplicate preserving order
    seen = set()
    unique = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def _build_fingerprint_hex_patterns() -> tuple[list[str], dict[str, str]]:
    """Build hex patterns for fingerprint strings and a reverse mapping.

    Returns:
        Tuple of (hex_patterns, hex_to_string_map) where hex_to_string_map
        maps each hex pattern back to its original string.
    """
    from tlslibhunter.utils.encoding import ascii_to_hex

    fp_strings = get_all_fingerprint_strings()
    hex_patterns: list[str] = []
    hex_to_string: dict[str, str] = {}
    for s in fp_strings:
        h = ascii_to_hex(s)
        hex_patterns.append(h)
        hex_to_string[h] = s
    return hex_patterns, hex_to_string


class ModuleScanner:
    """Scans process modules for TLS library indicators using Frida."""

    def __init__(
        self,
        backend: Any,
        session: Any,
        platform: str,
        package_name: str | None = None,
        verbose: bool = False,
    ):
        self._backend = backend
        self._session = session
        self._platform = platform
        self._verbose = verbose
        self._classifier = ModuleClassifier(platform, package_name)
        self._script = None
        self._exports = None

    def _ensure_script(self) -> None:
        """Load the scanner script if not already loaded."""
        if self._script is not None:
            return
        js_source = _load_scanner_js()
        self._script = self._backend.create_script(self._session, js_source)
        self._exports = getattr(self._script, "exports_sync", None) or getattr(self._script, "exports", None)

    def scan(self, target_name: str) -> ScanResult:
        """Scan all modules in the attached process for TLS libraries.

        Args:
            target_name: Name of the target process (for result metadata)

        Returns:
            ScanResult with detected TLS libraries
        """
        self._ensure_script()
        start_time = time.time()
        result = ScanResult(target=target_name, platform=self._platform)

        # Enumerate modules
        try:
            modules = self._exports.enumerate_modules()
        except Exception as e:
            result.errors.append(f"Failed to enumerate modules: {e}")
            return result

        logger.info("Found %d loaded modules", len(modules))

        # Build hex patterns
        hex_patterns = _build_all_hex_patterns()
        logger.debug("Built %d unique hex patterns from %d TLS strings", len(hex_patterns), len(TLS_STRING_PATTERNS))

        # Known export symbols to check
        export_symbols = list(TLS_EXPORT_SYMBOLS.keys())

        # Build fingerprint hex patterns (for library identification)
        fp_hex_patterns, fp_hex_to_string = _build_fingerprint_hex_patterns()
        logger.debug("Built %d fingerprint hex patterns", len(fp_hex_patterns))

        scanned = 0
        for mod in modules:
            name = mod.get("name", "")
            path = mod.get("path", "")
            base = mod.get("base", "")
            size = int(mod.get("size", 0) or 0)

            # Skip modules not worth scanning
            if not self._classifier.is_scan_worthy(name, path):
                logger.debug("Skipping %s (not scan-worthy)", name)
                continue

            scanned += 1
            matched_patterns = []
            matched_exports = []

            # Kernel-level pattern scan
            try:
                matches = self._exports.scan_module_kernel_level(name, hex_patterns)
                if matches:
                    matched_patterns = [m.get("pattern", "") for m in matches]
                    logger.info("Pattern match in %s: %d hits", name, len(matches))
            except Exception as e:
                logger.debug("Scan error for %s: %s", name, e)

            # Check export symbols (even if no pattern match, for library type ID)
            if matched_patterns or self._verbose:
                try:
                    found_exports = self._exports.check_exports(name, export_symbols)
                    if found_exports:
                        matched_exports = found_exports
                        logger.debug("Exports in %s: %s", name, found_exports)
                except Exception:
                    pass

            # If we found TLS indicators, add to results
            if matched_patterns or matched_exports:
                # Fingerprint scan for library identification
                fingerprint_type = "unknown"
                detected_version = ""
                matched_fingerprints: list[str] = []

                if fp_hex_patterns:
                    try:
                        found_fp_hex = self._exports.scan_for_strings(name, fp_hex_patterns)
                        if found_fp_hex:
                            matched_fingerprints = [fp_hex_to_string[h] for h in found_fp_hex if h in fp_hex_to_string]
                            fingerprint_type, detected_version = fingerprint_library(matched_fingerprints)
                            if fingerprint_type != "unknown":
                                logger.info(
                                    "Fingerprint: %s identified as %s%s",
                                    name,
                                    fingerprint_type,
                                    f" v{detected_version}" if detected_version else "",
                                )
                    except Exception as e:
                        logger.debug("Fingerprint scan error for %s: %s", name, e)

                info = self._classifier.classify_module(
                    name,
                    path,
                    matched_exports,
                    fingerprint_type,
                    detected_version,
                )
                lib = DetectedLibrary(
                    name=name,
                    path=path,
                    base_address=base,
                    size=size,
                    library_type=info["library_type"],
                    classification=info["classification"],
                    matched_patterns=matched_patterns,
                    matched_exports=matched_exports,
                    matched_fingerprints=matched_fingerprints,
                    detected_version=info.get("detected_version", ""),
                )
                result.libraries.append(lib)
                logger.info("Detected: %s (%s, %s)", name, info["library_type"], info["classification"])

        result.total_modules_scanned = scanned
        result.scan_duration_seconds = time.time() - start_time

        logger.info(
            "Scan complete: %d TLS libraries found in %d modules (%.2fs)",
            len(result.libraries),
            scanned,
            result.scan_duration_seconds,
        )

        return result

    def cleanup(self) -> None:
        """Unload the scanner script."""
        if self._script:
            with contextlib.suppress(Exception):
                self._script.unload()
            self._script = None
            self._exports = None
