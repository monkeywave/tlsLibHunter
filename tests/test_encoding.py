"""Tests for hex pattern encoding utilities."""

from tlslibhunter.utils.encoding import ascii_to_hex, build_scan_patterns, utf16le_to_hex


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

    def test_no_duplicates(self):
        patterns = build_scan_patterns("TEST")
        assert len(patterns) == len(set(patterns))
