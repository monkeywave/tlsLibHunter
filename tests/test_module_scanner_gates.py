"""Tests for ModuleScanner's coverage gates (--scan-all-modules / --scan-everything)
and the extended hex pattern map encodings.

These tests exercise the scanner's filter logic by constructing a ModuleScanner with
a mocked backend, then driving _build_hex_pattern_map / __init__ in isolation. They
do NOT instantiate Frida — no on-device dependency.
"""

from __future__ import annotations

from unittest.mock import Mock

from tlslibhunter.scanner.module_scanner import (
    ModuleScanner,
    _build_hex_pattern_map,
    _build_hex_patterns,
)


def _make_scanner(**kwargs) -> ModuleScanner:
    """Build a ModuleScanner with mock backend/session. Avoids Frida initialization."""
    return ModuleScanner(
        backend=Mock(),
        session=Mock(),
        platform=kwargs.pop("platform", "android"),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# __init__ accepts the new flags + tracks coverage state
# ---------------------------------------------------------------------------


def test_scanner_default_scan_all_modules_false():
    sc = _make_scanner()
    assert sc._scan_all_modules is False


def test_scanner_default_scan_everything_false():
    sc = _make_scanner()
    assert sc._scan_everything is False


def test_scanner_accepts_scan_all_modules_true():
    sc = _make_scanner(scan_all_modules=True)
    assert sc._scan_all_modules is True
    assert sc._scan_everything is False


def test_scanner_accepts_scan_everything_true():
    sc = _make_scanner(scan_everything=True)
    assert sc._scan_everything is True


def test_scanner_initialises_coverage_tracking_lists():
    sc = _make_scanner()
    assert sc._skipped_hard == []
    assert sc._skipped_heuristic == []


# ---------------------------------------------------------------------------
# _build_hex_pattern_map includes the new encoding types
# ---------------------------------------------------------------------------


def test_hex_pattern_map_includes_all_encoding_types_for_long_label():
    """A label >= 6 chars must produce ascii, ascii_nt, utf16le, utf16le_nt,
    and utf16be encodings (plus optional reversed chunks)."""
    _, hex_to_label = _build_hex_pattern_map(["CLIENT_RANDOM"])
    enc_types = {enc for (_, enc) in hex_to_label.values()}
    assert "ascii" in enc_types
    assert "ascii_nt" in enc_types
    assert "utf16le" in enc_types
    assert "utf16le_nt" in enc_types
    assert "utf16be" in enc_types
    # 13 chars -> 1 8-byte reversed chunk and at least one 4-byte
    assert any("reversed_chunk" in e for e in enc_types)


def test_hex_pattern_map_skips_utf16be_for_short_labels():
    """A 2-char label must NOT produce a utf16be encoding (FP guard)."""
    _, hex_to_label = _build_hex_pattern_map(["IV"])
    enc_types = {enc for (_, enc) in hex_to_label.values()}
    assert "utf16be" not in enc_types


def test_hex_pattern_map_dedups_across_labels():
    """If two labels share a hex pattern (unlikely but possible for ASCII),
    only one entry survives in the unique list."""
    unique, _ = _build_hex_pattern_map(["SSL", "SSL"])
    assert len(unique) == len(set(unique))


# ---------------------------------------------------------------------------
# _build_hex_patterns uses the broader set when flags are set
# ---------------------------------------------------------------------------


def test_build_hex_patterns_strict_excludes_short_gated_labels():
    """Without flags, the strict pattern source omits 'tls13 ', 'derived', etc."""
    from tlslibhunter.scanner.tls_indicators import TLS_STRING_PATTERNS_STRICT
    from tlslibhunter.utils.encoding import ascii_to_hex

    patterns = _build_hex_patterns(TLS_STRING_PATTERNS_STRICT)
    # The ASCII hex form of "tls13 " (with trailing space) must not appear.
    assert ascii_to_hex("tls13 ") not in patterns
    assert ascii_to_hex("derived") not in patterns
    assert ascii_to_hex("derive_secret") not in patterns


def test_build_hex_patterns_broad_includes_gated_labels():
    """The broad TLS_STRING_PATTERNS list contains gated labels — when scanner
    flags are set, the call site swaps to this source."""
    from tlslibhunter.scanner.tls_indicators import TLS_STRING_PATTERNS
    from tlslibhunter.utils.encoding import ascii_to_hex

    patterns = _build_hex_patterns(TLS_STRING_PATTERNS)
    assert ascii_to_hex("tls13 ") in patterns
    assert ascii_to_hex("derived") in patterns


def test_pattern_count_bounded():
    """Defensive: ensure the strict pattern set doesn't balloon past a sane upper bound.
    With ~6 encodings per label * ~15 labels = ~90 base + reversed chunks.
    Allow generous headroom but catch accidental explosions."""
    from tlslibhunter.scanner.tls_indicators import TLS_STRING_PATTERNS_STRICT

    patterns = _build_hex_patterns(TLS_STRING_PATTERNS_STRICT)
    assert len(patterns) < 600, f"Pattern count exploded to {len(patterns)}"
