"""Tests for CLI argument parsing."""

import logging
import sys

from tlslibhunter.backends.base import ProcessNotFoundError
from tlslibhunter.cli import _setup_debug_log_file, build_parser, main


class TestDebugLogFile:
    """The -d log file tees terminal output (ANSI stripped) to disk."""

    def test_creates_log_file_and_strips_ansi(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        real_stdout, real_stderr = sys.stdout, sys.stderr
        try:
            log_path = _setup_debug_log_file("The Weather Channel")
            assert log_path is not None
            # Filename is sanitized + lands in the cwd.
            assert (tmp_path / log_path).exists()
            # Colored (ANSI) output written to the tee is stored clean.
            print("\x1b[32mhigh\x1b[0m row")
            sys.stdout.flush()
        finally:
            sys.stdout, sys.stderr = real_stdout, real_stderr
        contents = (tmp_path / log_path).read_text(encoding="utf-8")
        assert "high row" in contents
        assert "\x1b[" not in contents  # escape codes stripped

    def test_tees_both_stdout_and_stderr(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        real_stdout, real_stderr = sys.stdout, sys.stderr
        try:
            log_path = _setup_debug_log_file("app")
            print("on stdout")
            print("on stderr", file=sys.stderr)
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            sys.stdout, sys.stderr = real_stdout, real_stderr
        contents = (tmp_path / log_path).read_text(encoding="utf-8")
        assert "on stdout" in contents
        assert "on stderr" in contents


class _HunterRaisingOnScan:
    """Minimal hunter stand-in whose scan() fails with a chained BackendError."""

    def __init__(self, error):
        self._error = error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def scan(self):
        try:
            raise RuntimeError("underlying frida failure")
        except RuntimeError as cause:
            raise self._error from cause


class TestBackendErrorReporting:
    """Expected backend errors print one clean line, not a traceback."""

    def test_process_not_found_with_debug_keeps_traceback_off_terminal(self, tmp_path, monkeypatch, capsys, caplog):
        from tlslibhunter.hunter import TLSLibHunter

        monkeypatch.chdir(tmp_path)
        error = ProcessNotFoundError("Process 'Gemini' not found")
        monkeypatch.setattr(TLSLibHunter, "from_config", classmethod(lambda cls, config: _HunterRaisingOnScan(error)))
        real_stdout, real_stderr = sys.stdout, sys.stderr
        try:
            with caplog.at_level(logging.DEBUG, logger="tlslibhunter"):
                exit_code = main(["Gemini", "-d"])
            sys.stderr.flush()
        finally:
            sys.stdout, sys.stderr = real_stdout, real_stderr

        assert exit_code == 1
        assert "Process 'Gemini' not found" in caplog.text
        captured = capsys.readouterr()
        assert "Traceback" not in captured.err
        assert "Traceback" not in captured.out
        assert "Traceback" not in caplog.text
        # The traceback is still preserved in the -d log file for diagnosis.
        log_files = list(tmp_path.glob("tlslibhunter_Gemini_*.log"))
        assert len(log_files) == 1
        log_contents = log_files[0].read_text(encoding="utf-8")
        assert "Traceback" in log_contents
        assert "ProcessNotFoundError" in log_contents


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

    def test_scan_all_modules_flag_parses(self):
        args = self.parser.parse_args(["foo", "--scan-all-modules"])
        assert args.scan_all_modules is True

    def test_scan_everything_flag_parses(self):
        args = self.parser.parse_args(["foo", "--scan-everything"])
        assert args.scan_everything is True

    def test_scan_flags_default_false(self):
        args = self.parser.parse_args(["foo"])
        assert args.scan_all_modules is False
        assert args.scan_everything is False

    def test_unfreeze_flag_parses(self):
        args = self.parser.parse_args(["Gemini", "-m", "--unfreeze"])
        assert args.unfreeze is True

    def test_unfreeze_defaults_false(self):
        args = self.parser.parse_args(["Gemini"])
        assert args.unfreeze is False


class TestUnfreezeConfigWiring:
    """--unfreeze must reach HunterConfig.unfreeze (it is opt-in: needs root, mutates device)."""

    def _captured_config(self, monkeypatch, argv):
        from tlslibhunter.hunter import TLSLibHunter

        captured = {}

        def fake_from_config(cls, config):
            captured["config"] = config
            raise RuntimeError("stop after config capture")

        monkeypatch.setattr(TLSLibHunter, "from_config", classmethod(fake_from_config))
        assert main(argv) == 1  # initialization "failure" short-circuits main()
        return captured["config"]

    def test_unfreeze_flag_sets_config(self, monkeypatch):
        config = self._captured_config(monkeypatch, ["Gemini", "-m", "--unfreeze"])
        assert config.unfreeze is True

    def test_unfreeze_absent_leaves_config_false(self, monkeypatch):
        config = self._captured_config(monkeypatch, ["Gemini", "-m"])
        assert config.unfreeze is False

    def test_hunter_config_unfreeze_defaults_false(self):
        from tlslibhunter.config import HunterConfig

        assert HunterConfig(target="Gemini").unfreeze is False
