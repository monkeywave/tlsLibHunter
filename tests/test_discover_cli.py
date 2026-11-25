"""Tests for the ``tlsLibHunter discover`` subcommand."""

import json

import pytest

from tests.conftest import FixtureRunner
from tlslibhunter import cli, discover_cli

BARD = "com.google.android.apps.bard"


class TestDiscoverParser:
    def test_defaults(self):
        args = discover_cli.build_discover_parser().parse_args([BARD])
        assert (args.app, args.duration, args.interval, args.json) == (BARD, None, 2.0, False)
        assert discover_cli.sampling_duration(args) == 20.0 and args.watch is False
        assert args.write_profile is None and args.serial is None

    def test_all_options(self):
        args = discover_cli.build_discover_parser().parse_args(
            [
                "Gemini",
                "--duration",
                "30",
                "--interval",
                "1.5",
                "--json",
                "--write-profile",
                "p.json",
                "--serial",
                "ABC",
            ]
        )
        assert (args.duration, args.interval, args.json, args.write_profile, args.serial) == (
            30.0,
            1.5,
            True,
            "p.json",
            "ABC",
        )


class TestMainDispatch:
    def test_discover_subcommand_is_dispatched(self, monkeypatch):
        seen = []
        monkeypatch.setattr(discover_cli, "discover_main", lambda argv: seen.append(argv) or 0)
        assert cli.main(["discover", BARD, "--json"]) == 0
        assert seen == [[BARD, "--json"]]

    def test_regular_target_still_uses_scan_parser(self):
        assert cli.build_parser().parse_args(["firefox", "-l"]).target == "firefox"


class TestResolvePackage:
    def test_installed_package_is_used_as_is(self):
        assert discover_cli.resolve_package(BARD, FixtureRunner(), None, frida_resolver=pytest.fail) == BARD

    def test_label_resolved_via_frida(self):
        resolved = discover_cli.resolve_package("Gemini", FixtureRunner(), "ABC", lambda app, serial: BARD)
        assert resolved == BARD

    def test_unknown_app_raises(self):
        with pytest.raises(ValueError):
            discover_cli.resolve_package("Nope", FixtureRunner(), None, lambda app, serial: "Nope")


class TestRunDiscover:
    def run(self, argv, capsys):
        args = discover_cli.build_discover_parser().parse_args(argv + ["--duration", "0"])
        code = discover_cli.run_discover(args, runner=FixtureRunner())
        return code, capsys.readouterr()

    def test_table_output_and_cue(self, capsys):
        code, out = self.run([BARD], capsys)
        assert code == 0
        assert "exercise the app now" in out.err
        header = out.out.splitlines()[2]
        assert header.split() == ["PROCESS", "PID", "ROLE", "TLS", "EVIDENCE"]
        assert "net:udp-connected:443" in out.out

    def test_json_output_and_profile_file(self, capsys, tmp_path):
        path = tmp_path / "profile.json"
        code, out = self.run([BARD, "--json", "--write-profile", str(path)], capsys)
        assert code == 0
        assert json.loads(out.out)["target_package"] == BARD
        assert json.loads(path.read_text())["schema"] == "tlslibhunter.profile/1"

    def test_unresolvable_app_returns_1(self, monkeypatch, capsys):
        monkeypatch.setattr(discover_cli, "_resolve_with_frida", lambda app, serial: "x")
        code, _ = self.run(["Nope"], capsys)
        assert code == 1
