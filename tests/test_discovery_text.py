"""Tests for escaping/capping device-derived strings (process names, evidence, table output)."""

from tlslibhunter import discover_cli
from tlslibhunter.discovery import engine, probe, text, tls_libs
from tlslibhunter.discovery.handoff import OomLink
from tlslibhunter.discovery.profile import Candidate, Profile
from tlslibhunter.utils.android_related import ProcessEntry

APP = "com.app"
DELEGATE = "com.delegate"
ANSI_PROCESS = APP + ":\x1b[31mred\x1b]0;title\x07"
LONG_PROCESS = APP + ":" + "x" * 5000


class TestEscapeText:
    def test_valid_names_are_unchanged(self):
        for name in (APP, "com.google.android.gms:persistent", "com.app_sdk_sandbox", "ü.app:proc"):
            assert text.safe_text(name) == name

    def test_ansi_and_osc_escapes_are_neutralised(self):
        escaped = text.escape_text(ANSI_PROCESS)
        assert "\x1b" not in escaped and "\x07" not in escaped
        assert escaped == APP + ":\\x1b[31mred\\x1b]0;title\\x07"

    def test_c1_bidi_and_newlines_are_escaped(self):
        assert text.escape_text("a\x9b‮\n") == "a\\x9b\\u202e\\x0a"

    def test_long_names_are_capped(self):
        assert len(text.safe_text(LONG_PROCESS)) == text.MAX_TEXT_LENGTH
        assert len(text.safe_text(LONG_PROCESS, 10)) == 10

    def test_safe_text_is_idempotent(self):
        once = text.safe_text(ANSI_PROCESS)
        assert text.safe_text(once) == once

    def test_probe_keeps_its_helpers(self):
        assert probe.cap is text.cap and probe.MAX_EVIDENCE_LENGTH == text.MAX_TEXT_LENGTH
        assert probe.escape_descriptor("a b") == "a\\x20b"


class TestEvidenceIsEscaped:
    def classify(self, client_process: str) -> Candidate:
        snapshot = engine.Snapshot(
            processes=[ProcessEntry(900, 10600, DELEGATE)],
            package_uids={APP: [10500], DELEGATE: [10600]},
            oom_links=[OomLink(client_process, 100, DELEGATE, 900)],
        )
        (cand,) = engine.classify(snapshot, APP)
        return cand

    def test_oom_bound_by_evidence_with_ansi_process(self):
        (evidence,) = self.classify(ANSI_PROCESS).evidence
        assert evidence.startswith(engine.EVIDENCE_OOM_BOUND_BY) and "\x1b" not in evidence

    def test_oom_bound_by_evidence_is_capped(self):
        (evidence,) = self.classify(LONG_PROCESS).evidence
        assert len(evidence) == text.MAX_TEXT_LENGTH

    def test_tls_lib_evidence_is_escaped_and_capped(self):
        (evidence,) = tls_libs.tls_lib_evidence(["lib\x1b[2Jssl" + "y" * 500 + ".so"])
        assert "\x1b" not in evidence and len(evidence) == text.MAX_TEXT_LENGTH


class TestHumanOutputIsEscaped:
    def profile(self, process: str) -> Profile:
        cand = Candidate(pid=1, process=process, package=APP, uid=10500, role="target", evidence=[process])
        return Profile(target=APP, target_package=APP, gate_packages=[process], candidates=[cand])

    def test_table_has_no_raw_escape_sequences(self):
        table = discover_cli.format_candidate_table(self.profile(ANSI_PROCESS))
        assert "\x1b" not in table and "\x07" not in table
        assert "\\x1b[31mred" in table

    def test_table_caps_long_process_names(self):
        table = discover_cli.format_candidate_table(self.profile(LONG_PROCESS))
        assert "x" * text.MAX_TEXT_LENGTH not in table
        assert max(len(line) for line in table.splitlines()) < 3 * text.MAX_TEXT_LENGTH + 40

    def test_json_output_keeps_json_escaping(self):
        assert "\x1b" not in self.profile(ANSI_PROCESS).to_json()

    def test_probe_failure_message_is_escaped(self, caplog):
        args = discover_cli.build_discover_parser().parse_args([APP, "--duration", "0"])

        def failing_probe(*_):
            raise RuntimeError("boom \x1b[31m" + "z" * 5000)

        assert discover_cli.run_probe_step(lambda cmd: "", APP, args, failing_probe) is None
        message = caplog.records[-1].getMessage()
        assert "\x1b" not in message and len(message) < text.MAX_MESSAGE_LENGTH + 60

    def test_launch_cue_is_escaped(self, capsys, monkeypatch):
        monkeypatch.setattr(probe, "launch_app", lambda runner, package: None)
        args = discover_cli.build_discover_parser().parse_args([APP, "--duration", "0"])

        def probe_that_launches(package, duration, serial, launch):
            launch()
            return probe.ProbeResult()

        discover_cli.run_probe_step(lambda cmd: "", ANSI_PROCESS, args, probe_that_launches)
        assert "\x1b" not in capsys.readouterr().err
