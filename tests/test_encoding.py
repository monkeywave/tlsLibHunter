"""Tests for hex pattern encoding utilities."""

from tlslibhunter.utils.encoding import (
    ascii_null_terminated_to_hex,
    ascii_space_padded_to_hex,
    ascii_to_hex,
    base64_encode_to_hex,
    build_scan_patterns,
    build_xor_patterns,
    reversed_chunks_to_hex,
    split_constant_pairs,
    split_constants_to_hex,
    utf16be_to_hex,
    utf16le_null_terminated_to_hex,
    utf16le_to_hex,
    xor_encode_to_hex,
)


class TestAsciiToHex:
    def test_simple_string(self):
        assert ascii_to_hex("ABC") == "41 42 43"

    def test_underscore(self):
        assert ascii_to_hex("A_B") == "41 5f 42"

    def test_client_random(self):
        result = ascii_to_hex("CLIENT_RANDOM")
        assert result.startswith("43 4c 49 45 4e 54")

    def test_empty_string(self):
        assert ascii_to_hex("") == ""


class TestUtf16leToHex:
    def test_simple_string(self):
        assert utf16le_to_hex("AB") == "41 00 42 00"

    def test_single_char(self):
        assert utf16le_to_hex("A") == "41 00"


class TestBuildScanPatterns:
    def test_returns_list(self):
        patterns = build_scan_patterns("TEST")
        assert isinstance(patterns, list)
        assert len(patterns) > 0

    def test_contains_ascii(self):
        patterns = build_scan_patterns("TEST")
        assert ascii_to_hex("TEST") in patterns

    def test_contains_utf16le(self):
        patterns = build_scan_patterns("TEST")
        assert utf16le_to_hex("TEST") in patterns

    def test_contains_reversed_chunks(self):
        patterns = build_scan_patterns("master secret")
        # "master s" reversed is "s retsam"
        assert ascii_to_hex("s retsam") in patterns

    def test_no_duplicates(self):
        patterns = build_scan_patterns("TEST")
        assert len(patterns) == len(set(patterns))


class TestReversedChunksToHex:
    def test_master_secret(self):
        result = reversed_chunks_to_hex("master secret")
        # "master s" (8 chars) reversed → "s retsam"
        assert ascii_to_hex("s retsam") in result

    def test_s_hs_traffic(self):
        result = reversed_chunks_to_hex("s hs traffic")
        # "s hs tra" (8 chars) reversed → "art sh s"
        assert ascii_to_hex("art sh s") in result

    def test_short_string_no_patterns(self):
        result = reversed_chunks_to_hex("abcde")
        assert result == []

    def test_exactly_6_chars(self):
        result = reversed_chunks_to_hex("abcdef")
        assert ascii_to_hex("fedcba") in result

    def test_empty_string(self):
        result = reversed_chunks_to_hex("")
        assert result == []


class TestSplitConstantPairs:
    def test_client_random_splits_at_underscore(self):
        pairs = split_constant_pairs("CLIENT_RANDOM")
        assert ("CLIENT_", "RANDOM") in pairs

    def test_no_underscore_splits_at_midpoint(self):
        pairs = split_constant_pairs("SSLKEYLOGFILE")
        assert len(pairs) == 1
        left, right = pairs[0]
        assert len(left) >= 4
        assert len(right) >= 4
        assert left + right == "SSLKEYLOGFILE"

    def test_short_string_no_split(self):
        pairs = split_constant_pairs("SSL")
        assert pairs == []

    def test_multiple_underscores(self):
        pairs = split_constant_pairs("CLIENT_HANDSHAKE_TRAFFIC_SECRET")
        assert len(pairs) > 1
        for left, right in pairs:
            assert "_" in left
            assert len(left) >= 4
            assert len(right) >= 4


class TestSplitConstantsToHex:
    def test_returns_hex_pairs(self):
        results = split_constants_to_hex("CLIENT_RANDOM")
        assert len(results) > 0
        for item in results:
            assert len(item) == 4
            left_hex, right_hex, left_str, right_str = item
            assert left_hex == ascii_to_hex(left_str)
            assert right_hex == ascii_to_hex(right_str)


class TestXorEncodeToHex:
    def test_xor_known_value(self):
        result = xor_encode_to_hex("A", 0x55)
        assert result == "14"

    def test_xor_roundtrip(self):
        original = "CLIENT_RANDOM"
        key = 0x55
        encoded = xor_encode_to_hex(original, key)
        # XOR the encoded bytes again with the same key
        decoded_bytes = [int(b, 16) ^ key for b in encoded.split()]
        decoded = "".join(chr(b) for b in decoded_bytes)
        assert decoded == original

    def test_xor_key_zero_is_identity(self):
        result = xor_encode_to_hex("SSL", 0x00)
        assert result == ascii_to_hex("SSL")


class TestBuildXorPatterns:
    def test_default_keys(self):
        patterns = build_xor_patterns("TEST")
        assert len(patterns) == 9

    def test_custom_keys(self):
        patterns = build_xor_patterns("TEST", keys=[0x01, 0x02])
        assert len(patterns) == 2
        for hex_pattern, key in patterns:
            assert hex_pattern == xor_encode_to_hex("TEST", key)


class TestBase64EncodeToHex:
    def test_known_string(self):
        # base64("SSL") == "U1NM"
        result = base64_encode_to_hex("SSL")
        expected = ascii_to_hex("U1NM")
        assert result == expected


class TestUtf16beToHex:
    def test_utf16be_to_hex_basic(self):
        assert utf16be_to_hex("SSL") == "00 53 00 53 00 4c"

    def test_utf16be_to_hex_empty(self):
        assert utf16be_to_hex("") == ""


class TestAsciiNullTerminatedToHex:
    def test_ascii_null_terminated_to_hex_basic(self):
        assert ascii_null_terminated_to_hex("SSL") == "53 53 4c 00"


class TestUtf16leNullTerminatedToHex:
    def test_utf16le_null_terminated_to_hex_basic(self):
        assert utf16le_null_terminated_to_hex("SSL") == "53 00 53 00 4c 00 00 00"


class TestAsciiSpacePaddedToHex:
    def test_ascii_space_padded_to_hex_short(self):
        # "tls13 " has 6 chars (trailing space included); pad_to=8 adds two 0x20 bytes.
        assert ascii_space_padded_to_hex("tls13 ", pad_to=8) == "74 6c 73 31 33 20 20 20"

    def test_ascii_space_padded_to_hex_already_long(self):
        assert ascii_space_padded_to_hex("abcdefgh", pad_to=8) == "61 62 63 64 65 66 67 68"


class TestReversedChunksToHexChunkSize:
    def test_reversed_chunks_4byte(self):
        assert reversed_chunks_to_hex("abcd", chunk_size=4) == [ascii_to_hex("dcba")]

    def test_reversed_chunks_8byte_min_length_preserved(self):
        # 5 chars, below the 6 floor for chunk_size=8
        assert reversed_chunks_to_hex("abcde", chunk_size=8) == []

    def test_reversed_chunks_4byte_3char_skipped(self):
        # 3 chars, below the 4 floor for chunk_size=4
        assert reversed_chunks_to_hex("abc", chunk_size=4) == []


class TestBuildScanPatternsExtended:
    def test_build_scan_patterns_contains_all_encodings(self):
        target = "CLIENT_RANDOM"
        result = build_scan_patterns(target)
        assert ascii_to_hex(target) in result
        assert ascii_null_terminated_to_hex(target) in result
        assert utf16le_to_hex(target) in result
        assert utf16le_null_terminated_to_hex(target) in result
        assert utf16be_to_hex(target) in result
        # At least one 8-byte reversed chunk entry
        eight_byte = reversed_chunks_to_hex(target)
        assert len(eight_byte) >= 1
        assert any(p in result for p in eight_byte)
        # At least one 4-byte reversed chunk entry
        four_byte = reversed_chunks_to_hex(target, chunk_size=4)
        assert len(four_byte) >= 1
        assert any(p in result for p in four_byte)

    def test_build_scan_patterns_skips_utf16be_for_short_strings(self):
        # First confirm utf16be_to_hex("IV") produces a non-empty string when called directly
        assert utf16be_to_hex("IV") != ""
        result = build_scan_patterns("IV")
        assert utf16be_to_hex("IV") not in result

    def test_build_scan_patterns_dedups_empty_strings_filtered(self):
        # Should not crash; result is a list (possibly empty).
        result = build_scan_patterns("")
        assert isinstance(result, list)

    def test_build_scan_patterns_returns_unique_patterns(self):
        result = build_scan_patterns("CLIENT_RANDOM")
        assert len(set(result)) == len(result)
