"""Tests for encoding-aware evidence classification.

Locks in the behavior added so libmainlinecronet-style chunk-only detections
get a `low` confidence verdict instead of being silently treated as equal to a
full-ASCII keylog-label match.
"""

from __future__ import annotations

from tlslibhunter.scanner.fingerprints import get_fingerprint_strings_for
from tlslibhunter.scanner.module_scanner import (
    _build_hex_pattern_map_multi,
    _classify_evidence,
    _decode_hex_pattern_ascii,
    _format_weak_evidence_table,
)
from tlslibhunter.scanner.tls_indicators import TLS_STRING_PATTERNS_STRICT


def _build_meta():
    _, hex_to_meta = _build_hex_pattern_map_multi(TLS_STRING_PATTERNS_STRICT)
    return hex_to_meta


def _find_hex(hex_to_meta, label: str, enc: str) -> str:
    for h, meta in hex_to_meta.items():
        if (label, enc) in meta:
            return h
    raise AssertionError(f"no hex pattern for ({label!r}, {enc!r})")


# ---------------------------------------------------------------------------
# Encoding strength
# ---------------------------------------------------------------------------


def test_full_ascii_label_is_high_confidence():
    hex_to_meta = _build_meta()
    full_ascii = _find_hex(hex_to_meta, "CLIENT_RANDOM", "ascii")
    conf, summary = _classify_evidence(
        [full_ascii], hex_to_meta, [], False, [], library_type="boringssl"
    )
    assert conf == "high"
    assert summary["strong"] == 1


def test_only_4byte_chunks_no_corroboration_is_low():
    """The libmainlinecronet case — 5 chunks, fingerprints that don't corroborate."""
    hex_to_meta = _build_meta()
    cronet_hits = ["48 5f 52 45", "41 52 54 5f", "54 5f 52 45", "45 52 43 45", "52 45 54 52"]
    conf, summary = _classify_evidence(
        cronet_hits,
        hex_to_meta,
        matched_exports=[],
        is_known=False,
        # crypto/tls is gotls, rust_eh_personality is rust-binary — neither corroborates boringssl
        matched_fingerprints=["BoringSSL", "crypto/tls", "rust_eh_personality"],
        library_type="boringssl",
    )
    assert conf == "low", summary
    assert summary["weak"] == 5
    assert summary["corroborating_fingerprints"] == 1


def test_four_chunks_with_two_corroborating_fingerprints_is_medium():
    """Weak chunks but two BoringSSL-specific fingerprints should rescue to medium."""
    hex_to_meta = _build_meta()
    chunks = ["48 5f 52 45", "41 52 54 5f", "54 5f 52 45"]
    conf, summary = _classify_evidence(
        chunks,
        hex_to_meta,
        matched_exports=[],
        is_known=False,
        matched_fingerprints=["BoringSSL", "tls13_hkdf_expand"],
        library_type="boringssl",
    )
    assert conf == "medium", summary
    assert summary["corroborating_fingerprints"] == 2


def test_exports_match_is_always_high():
    hex_to_meta = _build_meta()
    conf, _ = _classify_evidence(
        [], hex_to_meta, ["SSL_connect", "SSL_new"], False, [], library_type="boringssl"
    )
    assert conf == "high"


def test_known_name_is_always_high():
    hex_to_meta = _build_meta()
    conf, _ = _classify_evidence([], hex_to_meta, [], True, [], library_type="boringssl")
    assert conf == "high"


# ---------------------------------------------------------------------------
# Diagnostic table
# ---------------------------------------------------------------------------


def test_decode_hex_pattern_ascii_roundtrip():
    assert _decode_hex_pattern_ascii("48 5f 52 45") == "H_RE"
    assert _decode_hex_pattern_ascii("43 4c 49 45 4e 54 5f 52 41 4e 44 4f 4d") == "CLIENT_RANDOM"


def test_weak_evidence_table_contains_reversed_chunk_origins():
    hex_to_meta = _build_meta()
    table = _format_weak_evidence_table(
        "libmainlinecronet.so",
        ["48 5f 52 45", "41 52 54 5f", "52 45 54 52"],
        hex_to_meta,
        TLS_STRING_PATTERNS_STRICT,
    )
    # Each chunk should show its forward decode, reversed source, and TLS label origin
    assert "H_RE" in table
    assert "ER_H" in table
    assert "SERVER_HANDSHAKE_TRAFFIC_SECRET" in table  # ER_H @ offset 4
    assert "_TRA" in table  # reversed source of ART_
    assert "RTER" in table  # reversed source of RETR
    assert "EXPORTER_SECRET" in table  # @ offset 4
    assert "LOW confidence" in table


# ---------------------------------------------------------------------------
# Fingerprint-corroboration helper
# ---------------------------------------------------------------------------


def test_corroborating_fingerprints_boringssl():
    fps = get_fingerprint_strings_for("boringssl")
    assert "BoringSSL" in fps
    assert "tls13_hkdf_expand" in fps
    # crypto/tls is registered under gotls, not boringssl
    assert "crypto/tls" not in fps


def test_corroborating_fingerprints_unknown_library_is_empty():
    assert get_fingerprint_strings_for("definitely-not-a-real-library") == set()
