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
from tlslibhunter.scanner.tls_indicators import (
    TLS_DERIVATION_LABELS,
    TLS_EXPORT_SYMBOLS,
    TLS_STRING_PATTERNS,
    is_known_tls_library,
)
from tlslibhunter.utils.encoding import build_scan_patterns

logger = logging.getLogger("tlslibhunter.scanner")

# Path to the scanner agent JS file
_SCANNER_JS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "scanner_agent.js")


def _load_scanner_js() -> str:
    """Load the scanner agent JavaScript source."""
    with open(_SCANNER_JS) as f:
        return f.read()


def _build_hex_patterns(strings: list[str] | None = None) -> list[str]:
    """Build deduplicated hex patterns for TLS string indicators.

    Args:
        strings: List of strings to encode. Defaults to TLS_STRING_PATTERNS.
    """
    if strings is None:
        strings = TLS_STRING_PATTERNS
    patterns = []
    for s in strings:
        patterns.extend(build_scan_patterns(s))
    seen = set()
    unique = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def _build_hex_pattern_map(strings: list[str]) -> tuple[list[str], dict[str, tuple[str, str]]]:
    """Build hex patterns with a reverse mapping to source label and encoding type.

    Returns:
        Tuple of (hex_patterns, hex_to_label_map) where hex_to_label_map maps
        each hex pattern to (original_label, encoding_type).
    """
    from tlslibhunter.utils.encoding import ascii_to_hex, reversed_chunks_to_hex, utf16le_to_hex

    hex_to_label: dict[str, tuple[str, str]] = {}
    seen = set()
    unique = []

    for label in strings:
        encodings = [
            (ascii_to_hex(label), "ascii"),
            (utf16le_to_hex(label), "utf16le"),
        ]
        for rev_hex in reversed_chunks_to_hex(label):
            encodings.append((rev_hex, "reversed_chunk"))

        for hex_pat, enc_type in encodings:
            if hex_pat not in seen:
                seen.add(hex_pat)
                unique.append(hex_pat)
                hex_to_label[hex_pat] = (label, enc_type)

    return unique, hex_to_label


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


def _build_split_constant_pairs(strings: list[str]) -> list[dict]:
    """Build split constant pairs for JS-side proximity scanning."""
    from tlslibhunter.utils.encoding import split_constants_to_hex

    pairs = []
    for s in strings:
        for left_hex, right_hex, left_str, right_str in split_constants_to_hex(s):
            pairs.append(
                {
                    "leftHex": left_hex,
                    "rightHex": right_hex,
                    "leftStr": left_str,
                    "rightStr": right_str,
                }
            )
    return pairs


def _build_encoded_patterns(strings: list[str]) -> tuple[list[dict], dict]:
    """Build XOR and base64 encoded patterns for scanning."""
    from tlslibhunter.utils.encoding import base64_encode_to_hex, build_xor_patterns

    patterns = []
    for s in strings:
        for hex_pat, key in build_xor_patterns(s):
            patterns.append(
                {
                    "hexPattern": hex_pat,
                    "encodingType": "xor",
                    "detail": f"{s} XOR 0x{key:02x}",
                }
            )
        b64_hex = base64_encode_to_hex(s)
        patterns.append(
            {
                "hexPattern": b64_hex,
                "encodingType": "base64",
                "detail": f"{s} base64",
            }
        )
    return patterns


def _add_extended_scan_hits(
    result: ScanResult,
    classifier: ModuleClassifier,
    name: str,
    path: str,
    base: str,
    size: int,
    hits: list[dict],
    reason: str,
) -> None:
    """Append extended scan hits to an existing library entry, or create a new one."""
    existing = next((lib for lib in result.libraries if lib.name == name), None)
    if existing:
        existing.extended_scan_hits.extend(hits)
        if reason not in existing.detection_reason:
            existing.detection_reason += f"+{reason}"
    else:
        info = classifier.classify_module(name, path)
        lib = DetectedLibrary(
            name=name,
            path=path,
            base_address=base,
            size=size,
            library_type=info["library_type"],
            classification=info["classification"],
            matched_patterns=[],
            matched_exports=[],
            matched_fingerprints=[],
            detected_version="",
            detection_reason=reason,
            extended_scan_hits=hits,
        )
        result.libraries.append(lib)


_PROBE_LABELS: list[str] = [
    "master secret",  # TLS 1.2 — present in virtually all implementations
    "c hs traffic",  # TLS 1.3 — handshake traffic secret label
    "key expansion",  # TLS 1.2 — key derivation label
]
"""Minimal set of TLS derivation labels for the quick probe stage.

Any TLS library implementing TLS 1.2 or 1.3 will contain at least one of these.
Using 3 labels instead of all 11 cuts probe-stage Memory.scanSync calls by ~70%.
"""


def _build_probe_patterns() -> list[str]:
    """Build lightweight ASCII-only hex patterns from TLS derivation labels.

    These are used for the quick probe stage — only 3 patterns (most distinctive
    labels) in ASCII encoding. Much cheaper than the full 300+ pattern set.
    """
    from tlslibhunter.utils.encoding import ascii_to_hex

    return [ascii_to_hex(label) for label in _PROBE_LABELS]


# Scan thresholds — tuning knobs for detection sensitivity vs speed
_TLS_EARLY_EXIT_THRESHOLD = 5  # Stop TLS pattern scan after this many hits
_FP_EARLY_EXIT_THRESHOLD = 5  # Stop fingerprint scan after this many hits
_MIN_PATTERN_HITS = 3  # Pattern-only detections need >= N hits without exports/known name
_MIN_TLS_MODULE_SIZE = 10 * 1024  # Modules smaller than 10 KB cannot contain a TLS implementation


class ModuleScanner:
    """Scans process modules for TLS library indicators using Frida."""

    def __init__(
        self,
        backend: Any,
        session: Any,
        platform: str,
        package_name: str | None = None,
        verbose: bool = False,
        scan_mode: str = "standard",
        scan_split_constants: bool = False,
        scan_stack_strings: bool = False,
        scan_rwx_regions: bool = False,
        scan_encoded_strings: bool = False,
    ):
        self._backend = backend
        self._session = session
        self._platform = platform
        self._verbose = verbose
        self._scan_mode = scan_mode
        self._scan_split_constants = scan_split_constants
        self._scan_stack_strings = scan_stack_strings
        self._scan_rwx_regions = scan_rwx_regions
        self._scan_encoded_strings = scan_encoded_strings
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

    def _deduplicate_modules(self, modules: list[dict]) -> list[dict]:
        """Remove duplicate modules loaded at multiple addresses."""
        seen_paths: set[str] = set()
        unique = []
        for mod in modules:
            path = mod.get("path", "")
            if path in seen_paths:
                logger.debug("Skipping %s (duplicate path, different base address)", mod.get("name", ""))
                continue
            seen_paths.add(path)
            unique.append(mod)
        return unique

    def _scan_labels_mode(
        self,
        modules: list[dict],
        result: ScanResult,
        start_time: float,
    ) -> ScanResult:
        """Execute labels scan mode (--scan-labels flag)."""
        hex_patterns, hex_to_label = _build_hex_pattern_map(TLS_DERIVATION_LABELS)
        logger.info(
            "Label scan mode: built %d patterns from %d TLS derivation labels",
            len(hex_patterns),
            len(TLS_DERIVATION_LABELS),
        )

        scanned = 0
        for mod in modules:
            name = mod.get("name", "")
            path = mod.get("path", "")
            base = mod.get("base", "")
            size = int(mod.get("size", 0) or 0)

            if not self._classifier.is_scan_worthy(name, path):
                continue
            scanned += 1
            try:
                matches = self._exports.scan_module_kernel_level(name, hex_patterns)
                if matches:
                    matched_descriptions = []
                    for m in matches:
                        hex_pat = m.get("pattern", "")
                        label, enc_type = hex_to_label.get(hex_pat, ("?", "?"))
                        desc = f"{label} ({enc_type})"
                        matched_descriptions.append(desc)
                        logger.info(
                            '  Label hit in %s: "%s" [%s] at %s',
                            name,
                            label,
                            enc_type,
                            m.get("address", "?"),
                        )
                    logger.info("Label match in %s: %d hits: %s", name, len(matches), ", ".join(matched_descriptions))
                    info = self._classifier.classify_module(name, path)
                    lib = DetectedLibrary(
                        name=name,
                        path=path,
                        base_address=base,
                        size=size,
                        library_type=info["library_type"],
                        classification=info["classification"],
                        matched_patterns=matched_descriptions,
                        matched_exports=[],
                        matched_fingerprints=[],
                        detected_version="",
                        detection_reason="label_scan",
                    )
                    result.libraries.append(lib)
            except Exception as e:
                logger.debug("Label scan error for %s: %s", name, e)

        result.total_modules_scanned = scanned
        result.scan_duration_seconds = time.time() - start_time
        logger.info(
            "Scan complete: %d TLS libraries found in %d modules (%.2fs)",
            len(result.libraries),
            scanned,
            result.scan_duration_seconds,
        )
        return result

    def _build_per_module_opts(
        self,
        is_known: bool,
        matched_exports: list[str],
        hex_patterns: list[str],
    ) -> dict:
        """Build per-module-specific scan options (excludes shared opts like fpPatterns)."""
        opts: dict = {"fpEarlyExitThreshold": _FP_EARLY_EXIT_THRESHOLD}
        need_tls_scan = not matched_exports and not is_known
        if self._verbose:
            need_tls_scan = True
        if need_tls_scan:
            opts["tlsPatterns"] = hex_patterns
            opts["earlyExitThreshold"] = _TLS_EARLY_EXIT_THRESHOLD
        return opts

    def _process_scan_result(
        self,
        mod: dict,
        is_known: bool,
        matched_exports: list[str],
        combined: dict,
        fp_hex_to_string: dict[str, str],
        result: ScanResult,
    ) -> None:
        """Process combined scan results for a single module."""
        name = mod.get("name", "")
        path = mod.get("path", "")
        base = mod.get("base", "")
        size = int(mod.get("size", 0) or 0)

        matched_patterns: list[str] = []

        tls_matches = combined.get("tlsMatches", [])
        if tls_matches:
            matched_patterns = [m.get("pattern", "") for m in tls_matches]
            logger.info("Pattern match in %s: %d hits", name, len(tls_matches))

        # Require stronger evidence for pattern-only detections
        if matched_patterns and not matched_exports and not is_known and len(matched_patterns) < _MIN_PATTERN_HITS:
            logger.debug(
                "Skipping %s: only %d pattern hit(s), need %d (no exports or known name to corroborate)",
                name,
                len(matched_patterns),
                _MIN_PATTERN_HITS,
            )
            return

        if matched_patterns or matched_exports or is_known:
            fingerprint_type = "unknown"
            detected_version = ""
            matched_fingerprints: list[str] = []

            fp_matches = combined.get("fpMatches", [])
            if fp_matches:
                matched_fingerprints = [fp_hex_to_string[h] for h in fp_matches if h in fp_hex_to_string]
                fingerprint_type, detected_version = fingerprint_library(matched_fingerprints)

            info = self._classifier.classify_module(
                name,
                path,
                matched_exports,
                fingerprint_type,
                detected_version,
            )

            # Log fingerprint with clarity about overrides
            if fingerprint_type != "unknown":
                if info["library_type"] != fingerprint_type:
                    logger.info(
                        "Fingerprint: %s contains %s code (classified as %s by name)",
                        name,
                        fingerprint_type,
                        info["library_type"],
                    )
                else:
                    logger.info(
                        "Fingerprint: %s identified as %s%s",
                        name,
                        fingerprint_type,
                        f" v{detected_version}" if detected_version else "",
                    )

            reasons = []
            if matched_patterns:
                reasons.append("pattern")
            if matched_exports:
                reasons.append("export")
            if is_known:
                reasons.append("known_name")
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
                detection_reason="+".join(reasons),
            )
            result.libraries.append(lib)
            logger.info("Detected: %s (%s, %s)", name, info["library_type"], info["classification"])

        # Split constants
        split_matches = combined.get("splitMatches", [])
        if split_matches:
            for sm in split_matches:
                logger.info(
                    "Split constant in %s: %s + %s (distance: %s)",
                    name,
                    sm.get("leftStr"),
                    sm.get("rightStr"),
                    sm.get("distance"),
                )
            hits = [
                {
                    "scan_type": "split_constant",
                    "detail": f"{sm.get('leftStr', '')} + {sm.get('rightStr', '')}",
                    "distance": sm.get("distance", ""),
                }
                for sm in split_matches
            ]
            _add_extended_scan_hits(result, self._classifier, name, path, base, size, hits, "split_constant")

        # Encoded strings
        enc_matches = combined.get("encodedMatches", [])
        if enc_matches:
            for em in enc_matches:
                logger.info("Encoded string in %s: %s [%s]", name, em.get("detail"), em.get("encodingType"))
            hits = [
                {
                    "scan_type": em.get("encodingType", "encoded"),
                    "detail": em.get("detail", ""),
                    "address": em.get("address", ""),
                }
                for em in enc_matches
            ]
            _add_extended_scan_hits(result, self._classifier, name, path, base, size, hits, "encoded_string")

    def scan(self, target_name: str) -> ScanResult:
        """Scan all modules in the attached process for TLS libraries.

        Uses a multi-stage filtering pipeline to avoid scanning all modules:
          Stage 1: Name/path filtering (Python-side, instant)
          Stage 2: Batch export check (single RPC call)
          Stage 3: Quick TLS probe with derivation labels (single RPC call)
          Stage 4: Full detailed scan on confirmed candidates only

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

        total_modules = len(modules)
        logger.info("Found %d loaded modules", total_modules)

        # Deduplicate by path
        modules = self._deduplicate_modules(modules)
        deduped_count = len(modules)

        # Labels mode bypasses the pipeline
        if self._scan_mode == "labels":
            return self._scan_labels_mode(modules, result, start_time)

        # ============================================================
        # STAGE 1: Name/path filtering (Python-side, instant)
        # ============================================================
        stage1_candidates = []
        for mod in modules:
            name = mod.get("name", "")
            path = mod.get("path", "")
            if self._classifier.is_tls_candidate(name, path):
                stage1_candidates.append(mod)

        logger.info(
            "After name/path filtering: %d candidates (%d skipped)",
            len(stage1_candidates),
            deduped_count - len(stage1_candidates),
        )

        # Track pipeline metadata separately — don't mutate Frida module dicts
        # Keys are module names; values are (is_known, matched_exports)
        module_meta: dict[str, tuple[bool, list[str]]] = {}

        # Separate known-name system TLS libraries (fast path) from unknowns
        known_modules = []
        unknown_modules = []
        for mod in stage1_candidates:
            name = mod.get("name", "")
            path = mod.get("path", "")
            is_system = self._classifier.is_system_library(name, path)
            if is_system and is_known_tls_library(name):
                module_meta[name] = (True, [])
                known_modules.append(mod)
                logger.info("Known TLS library name: %s", name)
            else:
                unknown_modules.append(mod)

        # ============================================================
        # STAGE 2: Batch export check (single RPC call)
        # ============================================================
        export_symbols = list(TLS_EXPORT_SYMBOLS.keys())
        export_confirmed = []
        no_exports = []

        if unknown_modules:
            unknown_names = [m.get("name", "") for m in unknown_modules]
            try:
                export_results = self._exports.batch_check_exports(unknown_names, export_symbols)
            except Exception as e:
                logger.debug("Batch export check error: %s, falling back to individual checks", e)
                export_results = {}

            for mod in unknown_modules:
                name = mod.get("name", "")
                found = export_results.get(name, [])
                if found:
                    module_meta[name] = (False, found)
                    export_confirmed.append(mod)
                    logger.debug("Exports in %s: %s", name, found)
                else:
                    module_meta[name] = (False, [])
                    no_exports.append(mod)

        confirmed_so_far = known_modules + export_confirmed
        logger.info(
            "After export check: %d confirmed, %d remaining",
            len(confirmed_so_far),
            len(no_exports),
        )

        # ============================================================
        # STAGE 3: Quick TLS probe (single RPC call, lightweight)
        # ============================================================
        # Pre-filter: skip tiny modules that cannot contain a TLS implementation
        no_exports = [m for m in no_exports if int(m.get("size", 0) or 0) >= _MIN_TLS_MODULE_SIZE]
        probe_confirmed = []
        if no_exports:
            probe_patterns = _build_probe_patterns()
            probe_names = [m.get("name", "") for m in no_exports]
            try:
                probe_hits = self._exports.batch_probe_modules(probe_names, probe_patterns)
            except Exception as e:
                logger.debug("Batch probe error: %s, including all remaining as candidates", e)
                probe_hits = probe_names  # Fail-safe: include all

            probe_hit_set = set(probe_hits)
            for mod in no_exports:
                if mod.get("name", "") in probe_hit_set:
                    probe_confirmed.append(mod)

        all_confirmed = confirmed_so_far + probe_confirmed

        # In verbose mode, also include modules that didn't pass the probe
        if self._verbose:
            probe_confirmed_names = {m.get("name", "") for m in probe_confirmed}
            for mod in no_exports:
                if mod.get("name", "") not in probe_confirmed_names:
                    all_confirmed.append(mod)

        logger.info(
            "After TLS probe: %d candidates",
            len(all_confirmed),
        )

        # ============================================================
        # STAGE 4: Full detailed scan on confirmed candidates
        # ============================================================
        logger.info("Running detailed scan on %d modules...", len(all_confirmed))

        hex_patterns = _build_hex_patterns()
        fp_hex_patterns, fp_hex_to_string = _build_fingerprint_hex_patterns()

        source_strings = TLS_STRING_PATTERNS
        split_pairs = []
        encoded_patterns = []
        if self._scan_split_constants:
            split_pairs = _build_split_constant_pairs(source_strings)
        if self._scan_encoded_strings:
            encoded_patterns = _build_encoded_patterns(source_strings)

        base_scan_opts: dict = {}
        if fp_hex_patterns:
            base_scan_opts["fpPatterns"] = fp_hex_patterns
        if self._scan_split_constants and split_pairs:
            base_scan_opts["splitPairs"] = split_pairs
            base_scan_opts["maxSplitDistance"] = 256
        if self._scan_encoded_strings and encoded_patterns:
            base_scan_opts["encodedPatterns"] = encoded_patterns

        # Build per-module configs and batch scan in a single RPC call.
        # Shared opts (fpPatterns, splitPairs, etc.) are passed once to avoid
        # duplicating large pattern arrays in every module's RPC payload.
        module_configs = []
        for mod in all_confirmed:
            name = mod.get("name", "")
            is_known, matched_exports = module_meta.get(name, (False, []))
            per_mod_opts = self._build_per_module_opts(
                is_known,
                matched_exports,
                hex_patterns,
            )
            module_configs.append({"name": name, "opts": per_mod_opts})

        batch_results: dict = {}
        try:
            batch_results = self._exports.batch_scan_modules_combined(
                module_configs,
                base_scan_opts,
            )
        except Exception as e:
            logger.debug("Batch scan error: %s, falling back to sequential scan", e)
            # Fallback: scan modules individually (merge shared + per-module opts)
            for cfg in module_configs:
                merged = dict(base_scan_opts)
                merged.update(cfg["opts"])
                try:
                    batch_results[cfg["name"]] = self._exports.scan_module_combined(
                        cfg["name"],
                        merged,
                    )
                except Exception as e2:
                    logger.debug("Combined scan error for %s: %s", cfg["name"], e2)

        for mod in all_confirmed:
            name = mod.get("name", "")
            is_known, matched_exports = module_meta.get(name, (False, []))
            combined = batch_results.get(name, {})
            self._process_scan_result(
                mod,
                is_known,
                matched_exports,
                combined,
                fp_hex_to_string,
                result,
            )

        # Pipeline stats
        result.pipeline_stats = {
            "total_modules": total_modules,
            "after_dedup": deduped_count,
            "after_name_filter": len(stage1_candidates),
            "after_export_check": len(confirmed_so_far) + len(no_exports),
            "confirmed_by_exports": len(export_confirmed),
            "after_tls_probe": len(all_confirmed),
            "detailed_scan": len(all_confirmed),
        }
        result.total_modules_scanned = len(all_confirmed)
        result.scan_duration_seconds = time.time() - start_time

        logger.info(
            "Scan complete: %d TLS libraries found in %d modules (%.2fs)",
            len(result.libraries),
            len(all_confirmed),
            result.scan_duration_seconds,
        )

        # RWX region scan
        if self._scan_rwx_regions:
            try:
                rwx_matches = self._exports.scan_module_rwx_regions(hex_patterns)
                if rwx_matches:
                    logger.info("Found %d pattern(s) in RWX regions", len(rwx_matches))
                    lib = DetectedLibrary(
                        name="[JIT/RWX]",
                        path="",
                        base_address="",
                        size=0,
                        library_type="unknown",
                        classification="unknown",
                        matched_patterns=[m.get("pattern", "") for m in rwx_matches],
                        matched_exports=[],
                        matched_fingerprints=[],
                        detected_version="",
                        detection_reason="rwx_scan",
                        extended_scan_hits=[
                            {
                                "scan_type": "rwx_region",
                                "detail": f"pattern at {m.get('address', '?')}",
                                "protection": m.get("protection", ""),
                            }
                            for m in rwx_matches
                        ],
                    )
                    result.libraries.append(lib)
            except Exception as e:
                logger.debug("RWX region scan error: %s", e)

        # Stack memory scan
        if self._scan_stack_strings:
            try:
                stack_matches = self._exports.scan_stack_memory(hex_patterns)
                if stack_matches:
                    logger.info("Found %d pattern(s) in stack/writable memory", len(stack_matches))
                    lib = DetectedLibrary(
                        name="[stack/heap]",
                        path="",
                        base_address="",
                        size=0,
                        library_type="unknown",
                        classification="unknown",
                        matched_patterns=[m.get("pattern", "") for m in stack_matches],
                        matched_exports=[],
                        matched_fingerprints=[],
                        detected_version="",
                        detection_reason="stack_string",
                        extended_scan_hits=[
                            {
                                "scan_type": "stack_string",
                                "detail": f"pattern at {m.get('address', '?')}",
                                "protection": m.get("protection", ""),
                            }
                            for m in stack_matches
                        ],
                    )
                    result.libraries.append(lib)
            except Exception as e:
                logger.debug("Stack memory scan error: %s", e)

        return result

    def cleanup(self) -> None:
        """Unload the scanner script."""
        if self._script:
            with contextlib.suppress(Exception):
                self._script.unload()
            self._script = None
            self._exports = None
