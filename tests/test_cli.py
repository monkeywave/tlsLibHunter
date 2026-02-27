"""Tests for CLI argument parsing."""

from tlslibhunter.cli import build_parser


class TestCLIParsing:
    def setup_method(self):
        self.parser = build_parser()

    def test_mobile_does_not_consume_target(self):
        """Regression test: -m should not steal the TARGET positional arg."""
        args = self.parser.parse_args(["-m", "Chrome", "-l"])
        assert args.target == "Chrome"
        assert args.mobile is True
        assert args.list_only is True

    def test_mobile_flag_only(self):
        args = self.parser.parse_args(["app", "-m"])
        assert args.target == "app"
        assert args.mobile is True
        assert args.serial is None

    def test_serial_without_m(self):
        args = self.parser.parse_args(["firefox", "--serial", "ABC"])
        assert args.target == "firefox"
        assert args.serial == "ABC"

    def test_serial_with_m(self):
        args = self.parser.parse_args(["firefox", "-m", "--serial", "ABC"])
        assert args.target == "firefox"
        assert args.mobile is True
        assert args.serial == "ABC"

    def test_list_only_with_output(self):
        args = self.parser.parse_args(["firefox", "-l", "-o", "out"])
        assert args.target == "firefox"
        assert args.list_only is True
        assert args.output == "out"

    def test_basic_target(self):
        args = self.parser.parse_args(["firefox"])
        assert args.target == "firefox"
        assert args.mobile is False
        assert args.serial is None
        assert args.list_only is False
