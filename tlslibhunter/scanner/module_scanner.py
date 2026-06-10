"""Module scanner - orchestrates Frida-side TLS pattern scanning."""

from __future__ import annotations

import contextlib
import logging
import os
import time
from typing import Any

from tlslibhunter.scanner.classifier import ModuleClassifier
from tlslibhunter.scanner.fingerprints import (
    fingerprint_library,
    get_all_fingerprint_strings,
    get_fingerprint_strings_for,
)
from tlslibhunter.scanner.results import DetectedLibrary, ScanResult
from tlslibhunter.scanner.tls_indicators import (
    TLS_DERIVATION_LABELS,
    TLS_EXPORT_SYMBOLS,
    TLS_STRING_PATTERNS,
    TLS_STRING_PATTERNS_STRICT,
    is_known_false_positive,
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

    Encoding variants come from `iter_encodings` so this stays in sync with
    `build_scan_patterns`.

    Returns:
        Tuple of (hex_patterns, hex_to_label_map) where hex_to_label_map maps
        each hex pattern to (original_label, encoding_type).
    """
    from tlslibhunter.utils.encoding import iter_encodings

    hex_to_label: dict[str, tuple[str, str]] = {}
    seen: set[str] = set()
    unique: list[str] = []

    for label in strings:
        for hex_pat, enc_type in iter_encodings(label):
            if hex_pat and hex_pat not in seen:
                seen.add(hex_pat)
                unique.append(hex_pat)
                hex_to_label[hex_pat] = (label, enc_type)

    return unique, hex_to_label


def _build_hex_pattern_map_multi(
    strings: list[str],
) -> tuple[list[str], dict[str, list[tuple[str, str]]]]:
    """Like _build_hex_pattern_map but records ALL (label, encoding) candidates per hex.

    The same 4-byte chunk (e.g. reversed "_TRA") can originate from many TLS
    labels — CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0, etc. The lossy
    1:1 mapping in `_build_hex_pattern_map` hides this multiplicity, which is
    exactly what evidence classification and the weak-detection diagnostic
    table need to see.
    """
    from tlslibhunter.utils.encoding import iter_encodings

    hex_to_meta: dict[str, list[tuple[str, str]]] = {}
    unique: list[str] = []
    for label in strings:
        for hex_pat, enc_type in iter_encodings(label):
            if not hex_pat:
                continue
            if hex_pat not in hex_to_meta:
                hex_to_meta[hex_pat] = []
                unique.append(hex_pat)
            pair = (label, enc_type)
            if pair not in hex_to_meta[hex_pat]:
                hex_to_meta[hex_pat].append(pair)
    return unique, hex_to_meta


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


_COVERAGE_LOG_PREVIEW = 10  # Show at most this many module names in the coverage-summary log line


def _summarize_names(names: list[str], preview: int = _COVERAGE_LOG_PREVIEW) -> str:
    """Render a possibly-long list as 'a, b, c (and N more)'.

    Used by the coverage-summary log so a 300-module skip list doesn't
    produce a multi-kilobyte log record.
    """
    if len(names) <= preview:
        return repr(names)
    return f"[{', '.join(repr(n) for n in names[:preview])}, ... (and {len(names) - preview} more)]"


# Scan thresholds — tuning knobs for detection sensitivity vs speed
_TLS_EARLY_EXIT_THRESHOLD = 5  # Stop TLS pattern scan after this many hits
_FP_EARLY_EXIT_THRESHOLD = 5  # Stop fingerprint scan after this many hits
_MIN_PATTERN_HITS = 3  # Pattern-only detections need >= N hits without exports/known name
_MIN_TLS_MODULE_SIZE = 10 * 1024  # Modules smaller than 10 KB cannot contain a TLS implementation
# Defense-in-depth: if the target process dies mid-scan, re-spawn and bisect to
# isolate the offending module. High enough to bisect one offender out of a few
# hundred modules (~log2(N) re-attaches), bounded to prevent a re-spawn storm.
_MAX_REATTACHES = 12

# Encoding strength tiers — encodings from `iter_encodings()` have very different
# specificity. A full-ASCII match of "SERVER_HANDSHAKE_TRAFFIC_SECRET" is dispositive;
# a 4-byte reversed chunk of any TLS label is borderline coincidence.
_STRONG_ENCODINGS: frozenset[str] = frozenset({"ascii", "ascii_nt", "utf16le", "utf16le_nt", "utf16be"})
_MEDIUM_ENCODINGS: frozenset[str] = frozenset({"reversed_chunk_8"})
_WEAK_ENCODINGS: frozenset[str] = frozenset({"reversed_chunk_4"})


def _hex_pattern_byte_len(hex_pat: str) -> int:
    """Return the byte length of a space-separated hex pattern."""
    return len(hex_pat.split())


def _decode_hex_pattern_ascii(hex_pat: str) -> str:
    """Decode a space-separated hex pattern to printable ASCII (latin1 fallback).

    Used for the weak-evidence diagnostic table — gives a human-readable form
    of each chunk hit so the user can judge whether it looks TLS-related.
    """
    try:
        raw = bytes.fromhex(hex_pat.replace(" ", ""))
    except ValueError:
        return "?"
    return "".join(c if 32 <= ord(c) < 127 else "." for c in raw.decode("latin1", errors="replace"))


def _classify_evidence(
    matched_hex_patterns: list[str],
    hex_to_meta: dict[str, list[tuple[str, str]]],
    matched_exports: list[str],
    is_known: bool,
    matched_fingerprints: list[str],
    library_type: str = "unknown",
) -> tuple[str, dict[str, int]]:
    """Classify detection confidence by encoding strength of pattern hits.

    Returns:
        (confidence, summary) where confidence is "high"/"medium"/"low".
        summary holds per-tier counts for logging.

    Only fingerprints SPECIFIC to the chosen `library_type` count as
    corroboration — finding "crypto/tls" (gotls) or "rust_eh_personality"
    (rust-binary) does NOT corroborate a boringssl identification; it just
    indicates other code is also present in the binary.

    Rules (most→least specific):
      - exports OR known-name OR ≥1 strong-encoding hit → high
      - ≥2 medium-encoding hits → high
      - ≥1 medium hit + corroborating fingerprint → medium
      - ≥3 weak hits AND ≥2 distinct corroborating fingerprint strings → medium
      - otherwise (weak chunks ± a single matching fingerprint) → low
    """
    if matched_exports or is_known:
        return "high", {
            "strong": 0,
            "medium": 0,
            "weak": 0,
            "fingerprints": len(matched_fingerprints),
            "corroborating_fingerprints": len(matched_fingerprints),
        }

    strong = medium = weak = 0
    for hex_pat in matched_hex_patterns:
        encs = {enc for _, enc in hex_to_meta.get(hex_pat, [])}
        if encs & _STRONG_ENCODINGS:
            strong += 1
        elif encs & _MEDIUM_ENCODINGS:
            medium += 1
        elif encs & _WEAK_ENCODINGS:
            weak += 1
        else:
            # Unknown encoding (shouldn't happen if hex_to_meta is built consistently);
            # treat conservatively as weak.
            weak += 1

    # Count only fingerprints that belong to the identified library type.
    corroborating: set[str] = set()
    if library_type and library_type != "unknown":
        lib_fp_set = get_fingerprint_strings_for(library_type)
        for fp in matched_fingerprints:
            if fp in lib_fp_set:
                corroborating.add(fp)
    n_corroborating = len(corroborating)

    summary = {
        "strong": strong,
        "medium": medium,
        "weak": weak,
        "fingerprints": len(matched_fingerprints),
        "corroborating_fingerprints": n_corroborating,
    }

    if strong >= 1 or medium >= 2:
        return "high", summary
    if medium >= 1 and n_corroborating >= 1:
        return "medium", summary
    if weak >= 3 and n_corroborating >= 2:
        return "medium", summary
    return "low", summary


def _format_weak_evidence_table(
    name: str,
    matched_hex_patterns: list[str],
    hex_to_meta: dict[str, list[tuple[str, str]]],
    all_labels: list[str],
) -> str:
    """Build a human-readable evidence table for low-confidence (chunk-only) hits.

    For each 4-byte chunk hit shows:
      - hex (what the scanner searched for, e.g. "48 5f 52 45")
      - forward ASCII decode (e.g. "H_RE")
      - reversed source chunk (e.g. "ER_H" — what a compiler would have loaded)
      - possible origin TLS labels (substring matches in the indicator set)
    """
    header = (
        f"  Weak-evidence breakdown for {name}\n"
        f"  {'Hit (hex)':<14} {'Forward':<10} {'Reversed':<10} Possible origin TLS labels"
    )
    sep = "  " + "-" * 96
    body_lines: list[str] = []
    for hex_pat in matched_hex_patterns:
        forward = _decode_hex_pattern_ascii(hex_pat)
        reversed_chunk = forward[::-1]
        origin_hits: list[str] = []
        if reversed_chunk and "?" not in reversed_chunk and "." not in reversed_chunk:
            for label in all_labels:
                idx = label.find(reversed_chunk)
                if idx >= 0:
                    origin_hits.append(f"{label} @ offset {idx}")
        if not origin_hits:
            # Fallback to the (label, encoding) candidates we already know
            origin_hits = [f"{lbl} ({enc})" for lbl, enc in hex_to_meta.get(hex_pat, [])]
        if len(origin_hits) > 3:
            origin_str = "; ".join(origin_hits[:3]) + f"  (+{len(origin_hits) - 3} more)"
        else:
            origin_str = "; ".join(origin_hits) or "(no TLS label contains this chunk — likely coincidence)"
        body_lines.append(f"  {hex_pat:<14} {forward:<10} {reversed_chunk:<10} {origin_str}")
    verdict = (
        "  Verdict: LOW confidence — all hits are 4-byte reversed chunks. These could "
        "be coincidental ASCII fragments.\n"
        "  Likely meaning: this module REFERENCES BoringSSL/TLS (string in .rodata, "
        "wrapper function, or symbol name) but does\n"
        "  not contain the TLS implementation itself. Check if it imports SSL_*/EVP_*/HKDF_* "
        "symbols from another .so."
    )
    return "\n".join([header, sep, *body_lines, sep, verdict])


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
        scan_all_modules: bool = False,
        scan_everything: bool = False,
        device: Any = None,
        respawn_target: str | None = None,
        spawn_mode: bool = False,
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
        self._scan_all_modules = scan_all_modules
        self._scan_everything = scan_everything
        self._classifier = ModuleClassifier(platform, package_name)
        self._script = None
        self._exports = None
        # Coverage tracking populated during scan() — surfaced in pipeline_stats.
        self._skipped_hard: list[str] = []
        self._skipped_heuristic: list[str] = []
        self._skipped_false_positive: list[str] = []
        # Process-death resilience (defense-in-depth; normal path never touches it).
        self._device = device
        self._respawn_target = respawn_target
        self._spawn_mode = spawn_mode
        self._excluded_modules: set[str] = set()
        self._detach_info: dict = {"detached": False, "reason": None, "crash": None}
        self._reattach_count = 0
        self._closing = False  # set during cleanup() so our own detach isn't a "crash"
        self._unrecoverable_message: str | None = None

    def _ensure_script(self) -> None:
        """Load the scanner script if not already loaded."""
        if self._script is not None:
            return
        js_source = _load_scanner_js()
        # Register a detach handler on the session so a process death is detected
        # cleanly instead of surfacing as a cascade of opaque RPC errors.
        with contextlib.suppress(Exception):
            self._backend.set_detached_callback(self._session, self._on_detached)
        self._script = self._backend.create_script(
            self._session,
            js_source,
            on_script_destroyed=self._on_script_destroyed,
        )
        self._exports = getattr(self._script, "exports_sync", None) or getattr(self._script, "exports", None)

    # ------------------------------------------------------------------
    # Process-death detection & recovery (defense-in-depth)
    # ------------------------------------------------------------------
    @staticmethod
    def _module_name(item: Any) -> str:
        """Module name from either a Frida module dict or a scan config dict."""
        return item.get("name", "") if isinstance(item, dict) else ""

    def _on_detached(self, reason: str | None = None, *rest: Any) -> None:
        """Frida session 'detached' handler: cb(reason, crash)."""
        if self._closing or reason == "application-requested":
            return  # our own teardown, not a crash
        self._detach_info = {
            "detached": True,
            "reason": reason,
            "crash": rest[0] if rest else None,
        }
        logger.warning("Session detached: %s", reason or "unknown")

    def _on_script_destroyed(self) -> None:
        """Frida script 'destroyed' handler: cb()."""
        if self._closing:
            return
        if not self._detach_info.get("detached"):
            self._detach_info = {"detached": True, "reason": "script-destroyed", "crash": None}

    def _is_process_death(self, exc: Exception) -> bool:
        """True if an RPC failure was caused by the target process/script dying."""
        if self._detach_info.get("detached") and self._detach_info.get("reason") != "application-requested":
            return True
        msg = str(exc).lower()
        return (
            "script has been destroyed" in msg
            or "script is destroyed" in msg
            or "session is detached" in msg
            or "process not found" in msg
            or "process not responding" in msg
        )

    def _can_reattach(self) -> bool:
        """Auto-recovery is only feasible in spawn mode (attach mode: PID is gone)."""
        return bool(
            self._spawn_mode
            and self._device is not None
            and self._respawn_target
            and self._reattach_count < _MAX_REATTACHES
        )

    def _reattach(self) -> bool:
        """Re-spawn the target and reload the script. Returns True on success."""
        if not self._can_reattach():
            return False
        self._reattach_count += 1
        logger.info(
            "Re-spawning '%s' to recover (attempt %d/%d)...",
            self._respawn_target,
            self._reattach_count,
            _MAX_REATTACHES,
        )
        # Drop the dead script/session without tripping our own detach handler.
        self._closing = True
        with contextlib.suppress(Exception):
            self.cleanup()
        self._closing = False
        self._detach_info = {"detached": False, "reason": None, "crash": None}
        try:
            self._session = self._backend.spawn(
                self._device,
                self._respawn_target,
                on_detached=self._on_detached,
            )
            self._script = None
            self._exports = None
            self._ensure_script()
            return True
        except Exception as e:
            logger.error("Re-spawn failed: %s", e)
            return False

    def _run_resilient(self, label: str, items: list, run, empty_factory, merge):
        """Run a batch RPC over ``items`` with process-death recovery.

        ``run(subset)`` performs the actual RPC on a subset and returns its
        result; it may raise. On an ordinary (non-death) error this re-raises so
        the caller's existing fallback handles it. On a detected process death it
        re-attaches (spawn mode) and bisects ``items`` to isolate the offending
        module, which is added to ``self._excluded_modules`` and skipped.
        """
        items = [it for it in items if self._module_name(it) not in self._excluded_modules]
        try:
            return run(items)
        except Exception as e:
            if not self._is_process_death(e):
                raise
        logger.error(
            "Target process died during %s (%s). Attempting recovery...",
            label,
            self._detach_info.get("reason") or "script destroyed",
        )
        return self._recover_bisect(label, items, run, empty_factory, merge)

    def _recover_bisect(self, label: str, items: list, run, empty_factory, merge):
        """Bisect ``items`` across re-spawns to isolate process-killing modules."""
        result = empty_factory()
        queue: list[list] = [list(items)]
        need_reattach = True  # we just observed a death
        while queue:
            chunk = [it for it in queue.pop(0) if self._module_name(it) not in self._excluded_modules]
            if not chunk:
                continue
            if need_reattach:
                if not self._reattach():
                    self._record_unrecoverable(label, chunk)
                    return result
                need_reattach = False
            try:
                result = merge(result, run(chunk))
            except Exception as e:
                is_death = self._is_process_death(e)
                if len(chunk) > 1:
                    # Narrow down which module(s) are responsible by re-queueing the
                    # halves. This isolates the offender without dropping the rest of
                    # the chunk — whether the failure killed the process (death) or was
                    # a transient per-batch error (non-death). Only a process death
                    # requires re-spawning before the halves can run.
                    mid = len(chunk) // 2
                    queue[:0] = [chunk[:mid], chunk[mid:]]  # process left half first
                    if is_death:
                        need_reattach = True
                elif is_death:
                    victim = self._module_name(chunk[0])
                    self._excluded_modules.add(victim)
                    logger.error("Excluded offending module after crash: %s", victim)
                    need_reattach = True
                else:
                    logger.debug(
                        "%s: non-fatal error on %s, skipping: %s", label, self._module_name(chunk[0]), e
                    )
        return result

    def _record_unrecoverable(self, label: str, pending: list) -> None:
        """Emit a single clean message when recovery is impossible/exhausted."""
        reason = self._detach_info.get("reason") or "script destroyed"
        if not self._spawn_mode:
            hint = "Re-attach is not possible in attach mode (the process is gone). Relaunch the app and re-run."
        else:
            hint = f"Recovery exhausted after {self._reattach_count} re-spawn(s)."
        excluded = sorted(self._excluded_modules)
        excluded_str = f" Excluded so far: {excluded}." if excluded else ""
        self._unrecoverable_message = (
            f"Scan stopped: target process died during {label} ({reason}); "
            f"{len(pending)} module(s) not scanned. {hint}{excluded_str}"
        )
        logger.error(self._unrecoverable_message)

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
                if not self._scan_everything:
                    self._skipped_hard.append(name)
                    logger.info("SKIP (hard-irrelevant) %s", name)
                    continue
                logger.info("SCAN (forced by --scan-everything) %s", name)
            else:
                logger.info("SCAN %s", name)
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
        self._apply_default_result_filters(result)
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
        hex_to_meta: dict[str, list[tuple[str, str]]] | None = None,
        all_pattern_labels: list[str] | None = None,
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
            for p in matched_patterns:
                logger.debug("  pattern hit in %s: %r", name, p)

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
                for fs in matched_fingerprints:
                    logger.debug("  fingerprint hit in %s: %r", name, fs)
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

            # Encoding-weighted confidence: a "5 hits" detection where all 5 are
            # 4-byte reversed chunks (the weakest encoding from iter_encodings)
            # is borderline coincidence — surface that as low confidence and emit
            # a diagnostic table the user can inspect, instead of treating it
            # the same as a full-ASCII keylog-label hit.
            confidence = "high"
            evidence_summary: dict[str, int] = {}
            if hex_to_meta is not None:
                confidence, evidence_summary = _classify_evidence(
                    matched_patterns,
                    hex_to_meta,
                    matched_exports,
                    is_known,
                    matched_fingerprints,
                    library_type=info["library_type"],
                )
                # The verbose weak-evidence breakdown is only useful when the
                # low-confidence row will actually be shown (--scan-everything)
                # or when debugging (-d); otherwise it just floods a default run
                # that already hides these detections.
                if confidence == "low" and (self._scan_everything or logger.isEnabledFor(logging.DEBUG)):
                    logger.warning(
                        "Weak evidence for %s: %d 4-byte chunk hit(s), %d total fingerprint(s) "
                        "of which %d corroborate %s; this module may REFERENCE TLS code "
                        "rather than implement it",
                        name,
                        evidence_summary.get("weak", 0),
                        evidence_summary.get("fingerprints", 0),
                        evidence_summary.get("corroborating_fingerprints", 0),
                        info["library_type"],
                    )
                    if all_pattern_labels:
                        table = _format_weak_evidence_table(name, matched_patterns, hex_to_meta, all_pattern_labels)
                        for line in table.splitlines():
                            logger.warning(line)

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
                confidence=confidence,
                evidence_summary=evidence_summary,
            )
            result.libraries.append(lib)
            confidence_tag = "" if confidence == "high" else f" [confidence={confidence}]"
            logger.info(
                "Detected: %s (%s, %s)%s",
                name,
                info["library_type"],
                info["classification"],
                confidence_tag,
            )

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
        # Coverage gates:
        #   default                  -> heuristic is_tls_candidate filter + hard is_scan_worthy skip-list
        #   --scan-all-modules       -> bypass heuristic; hard skip-list still applies
        #   --scan-everything        -> also bypass hard skip-list (truly every module)
        if self._scan_all_modules or self._scan_everything:
            logger.info(
                "Coverage mode: %s (per-module SCAN/SKIP lines follow)",
                "scan-everything" if self._scan_everything else "scan-all-modules",
            )

        force_scan = self._scan_all_modules or self._scan_everything

        stage1_candidates = []
        for mod in modules:
            name = mod.get("name", "")
            path = mod.get("path", "")

            if not self._classifier.is_scan_worthy(name, path):
                if not self._scan_everything:
                    self._skipped_hard.append(name)
                    if self._scan_all_modules:
                        logger.info("SKIP (hard-irrelevant) %s", name)
                    continue
                logger.info("SCAN (forced by --scan-everything) %s", name)
                stage1_candidates.append(mod)
                continue

            # Known false positives: crypto-primitive / JNI-wrapper libs that
            # carry TLS strings but are not hookable TLS stacks. Skipped by
            # default; --scan-everything includes them.
            if not self._scan_everything and is_known_false_positive(name):
                self._skipped_false_positive.append(name)
                if self._scan_all_modules:
                    logger.info("SKIP (known false positive) %s", name)
                continue

            if not self._classifier.is_tls_candidate(name, path):
                if not force_scan:
                    self._skipped_heuristic.append(name)
                    continue
                logger.info("SCAN (forced by --scan-all-modules) %s", name)
                stage1_candidates.append(mod)
                continue

            if force_scan:
                logger.info("SCAN %s", name)
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

            def _run_exports(subset):
                names = [m.get("name", "") for m in subset]
                return self._exports.batch_check_exports(names, export_symbols)

            try:
                export_results = self._run_resilient(
                    "export check", unknown_modules, _run_exports, dict, lambda a, b: {**a, **b}
                )
            except Exception as e:
                logger.debug("Batch export check error: %s, falling back to individual checks", e)
                export_results = {}

            for mod in unknown_modules:
                name = mod.get("name", "")
                if name in self._excluded_modules:
                    continue
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
        # Pre-filter: skip tiny modules that cannot contain a TLS implementation.
        # --scan-everything bypasses this floor for diagnostic / paranoia mode.
        if not self._scan_everything:
            no_exports = [m for m in no_exports if int(m.get("size", 0) or 0) >= _MIN_TLS_MODULE_SIZE]
        probe_confirmed = []
        if no_exports:
            probe_patterns = _build_probe_patterns()
            probe_names = [m.get("name", "") for m in no_exports]

            def _run_probe(subset):
                names = [m.get("name", "") for m in subset]
                return self._exports.batch_probe_modules(names, probe_patterns)

            try:
                probe_hits = self._run_resilient(
                    "TLS probe", no_exports, _run_probe, list, lambda a, b: a + b
                )
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

        # Choose pattern set: strict (no short/high-FP labels) by default; broad
        # (includes "tls13 ", "derived", "finished", "derive_secret") when the
        # user explicitly opts into thoroughness via --scan-all-modules/--scan-everything.
        if self._scan_all_modules or self._scan_everything:
            pattern_source = TLS_STRING_PATTERNS
        else:
            pattern_source = TLS_STRING_PATTERNS_STRICT
        # Use the multi-candidate map so each hit can be classified by encoding strength
        # (and so the weak-evidence diagnostic table can list all possible origin labels).
        hex_patterns, tls_hex_to_meta = _build_hex_pattern_map_multi(pattern_source)
        fp_hex_patterns, fp_hex_to_string = _build_fingerprint_hex_patterns()

        source_strings = pattern_source
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
            if name in self._excluded_modules:
                continue
            is_known, matched_exports = module_meta.get(name, (False, []))
            per_mod_opts = self._build_per_module_opts(
                is_known,
                matched_exports,
                hex_patterns,
            )
            module_configs.append({"name": name, "opts": per_mod_opts})

        def _run_scan(subset):
            return self._exports.batch_scan_modules_combined(subset, base_scan_opts)

        batch_results: dict = {}
        try:
            batch_results = self._run_resilient(
                "detailed scan", module_configs, _run_scan, dict, lambda a, b: {**a, **b}
            )
        except Exception as e:
            logger.debug("Batch scan error: %s, falling back to sequential scan", e)
            # Fallback: scan modules individually (merge shared + per-module opts)
            for cfg in module_configs:
                if cfg["name"] in self._excluded_modules:
                    continue
                merged = dict(base_scan_opts)
                merged.update(cfg["opts"])
                try:
                    batch_results[cfg["name"]] = self._exports.scan_module_combined(
                        cfg["name"],
                        merged,
                    )
                except Exception as e2:
                    if self._is_process_death(e2):
                        logger.error("Target process died during sequential scan; stopping further scans.")
                        break
                    logger.debug("Combined scan error for %s: %s", cfg["name"], e2)

        for mod in all_confirmed:
            name = mod.get("name", "")
            if name in self._excluded_modules:
                continue
            is_known, matched_exports = module_meta.get(name, (False, []))
            combined = batch_results.get(name, {})
            self._process_scan_result(
                mod,
                is_known,
                matched_exports,
                combined,
                fp_hex_to_string,
                result,
                hex_to_meta=tls_hex_to_meta,
                all_pattern_labels=pattern_source,
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
            "scan_all_modules_enabled": self._scan_all_modules,
            "scan_everything_enabled": self._scan_everything,
            "hard_skipped_names": self._skipped_hard,
            "heuristic_skipped_names": self._skipped_heuristic,
            "false_positive_skipped_names": self._skipped_false_positive,
            "excluded_modules": sorted(self._excluded_modules),
            "reattach_count": self._reattach_count,
        }
        result.total_modules_scanned = len(all_confirmed)
        result.scan_duration_seconds = time.time() - start_time

        # Surface a single clean message if the process died and recovery was
        # impossible/exhausted (replaces the old per-module error cascade).
        if self._unrecoverable_message and self._unrecoverable_message not in result.errors:
            result.errors.append(self._unrecoverable_message)
        elif self._excluded_modules:
            result.errors.append(
                f"Recovered from {self._reattach_count} process death(s); "
                f"excluded offending module(s): {sorted(self._excluded_modules)}"
            )

        logger.info(
            "Scan complete: %d TLS libraries found in %d modules (%.2fs)",
            len(result.libraries),
            len(all_confirmed),
            result.scan_duration_seconds,
        )
        if (
            self._scan_all_modules
            or self._scan_everything
            or self._skipped_hard
            or self._skipped_heuristic
            or self._skipped_false_positive
        ):
            hard_suffix = f": {_summarize_names(self._skipped_hard)}" if self._skipped_hard else ""
            heuristic_hint = (
                " (use --scan-all-modules to include)" if self._skipped_heuristic and not self._scan_all_modules else ""
            )
            fp_suffix = (
                f" False-positive-skipped {len(self._skipped_false_positive)}"
                f": {_summarize_names(self._skipped_false_positive)} (use --scan-everything to include)."
                if self._skipped_false_positive
                else ""
            )
            logger.info(
                "Coverage: scanned %d/%d modules. Hard-skipped %d%s. Heuristic-skipped %d%s.%s",
                len(stage1_candidates),
                deduped_count,
                len(self._skipped_hard),
                hard_suffix,
                len(self._skipped_heuristic),
                heuristic_hint,
                fp_suffix,
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

        self._apply_default_result_filters(result)
        return result

    def _apply_default_result_filters(self, result: ScanResult) -> None:
        """Hide low-confidence and known-false-positive detections by default.

        Keeps only medium/high-confidence, genuine TLS-stack detections in the
        result so the table / json / plain output and extraction all share one
        filtered view. ``--scan-everything`` disables the filter and yields the
        full raw set. Hidden names are recorded in ``pipeline_stats`` so nothing
        is silently lost.
        """
        if self._scan_everything:
            return

        hidden_low: list[str] = []
        hidden_fp: list[str] = []
        keep: list[DetectedLibrary] = []
        for lib in result.libraries:
            if is_known_false_positive(lib.name):
                hidden_fp.append(lib.name)
            elif getattr(lib, "confidence", "high") == "low":
                hidden_low.append(lib.name)
            else:
                keep.append(lib)

        result.libraries = keep
        result.pipeline_stats["hidden_low_confidence_names"] = hidden_low
        result.pipeline_stats["hidden_false_positive_names"] = hidden_fp
        if hidden_low or hidden_fp:
            logger.info(
                "Hidden %d low-confidence + %d known-false-positive detection(s) from results; "
                "use --scan-everything to show.",
                len(hidden_low),
                len(hidden_fp),
            )

    def cleanup(self) -> None:
        """Unload the scanner script."""
        self._closing = True  # our own unload/detach is not a crash
        if self._script:
            with contextlib.suppress(Exception):
                self._script.unload()
            self._script = None
            self._exports = None
