"""Tests for reporting an incomplete pattern scan.

The scanner agent bounds every ``Memory.scan`` window with a safety net so a hung
native scan cannot deadlock the RPC. That net used to resolve with whatever
matches it had collected and say nothing at all — so a module whose scan timed
out was reported exactly like a module with no TLS library in it. The agent now
returns ``truncated`` per module and the scanner turns that into an entry in
``ScanResult.errors``.
"""

from tlslibhunter.scanner.module_scanner import _truncated_scan_message


class TestTruncatedScanMessage:
    def test_returns_none_when_nothing_was_truncated(self):
        batch = {
            "libssl.3.dylib": {"tlsMatches": [], "truncated": False},
            "libboringssl.dylib": {"tlsMatches": [], "truncated": False},
        }
        assert _truncated_scan_message(batch) is None

    def test_returns_none_for_an_empty_batch(self):
        assert _truncated_scan_message({}) is None

    def test_names_the_truncated_module(self):
        batch = {
            "libssl.3.dylib": {"truncated": False},
            "libmonochrome.so": {"truncated": True},
        }
        message = _truncated_scan_message(batch)
        assert message is not None
        assert "libmonochrome.so" in message
        assert "libssl.3.dylib" not in message

    def test_says_the_result_is_incomplete_not_negative(self):
        # The whole point: the reader must not treat "nothing found" as fact.
        message = _truncated_scan_message({"libx.so": {"truncated": True}})
        assert "INCOMPLETE" in message
        assert "does not mean" in message

    def test_counts_and_sorts_multiple_truncated_modules(self):
        batch = {
            "zlib.so": {"truncated": True},
            "alib.so": {"truncated": True},
            "mlib.so": {"truncated": False},
        }
        message = _truncated_scan_message(batch)
        assert "2 module(s)" in message
        # Sorted so the message is stable across dict ordering.
        assert message.index("alib.so") < message.index("zlib.so")

    def test_tolerates_non_dict_entries(self):
        # A module whose scan raised leaves a non-dict (or missing) entry behind;
        # that must not crash the reporting path.
        batch = {"ok.so": {"truncated": True}, "broken.so": None, "odd.so": "error"}
        message = _truncated_scan_message(batch)
        assert message is not None
        assert "ok.so" in message

    def test_missing_truncated_key_is_treated_as_complete(self):
        # Results produced by an older agent bundle have no `truncated` key at
        # all; absence must read as "finished", not as "unknown".
        assert _truncated_scan_message({"libssl.so": {"tlsMatches": []}}) is None
