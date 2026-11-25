"""Tests for ``discover --probe``: descriptor mapping, evidence, engine merge, CLI wiring."""

import argparse

import pytest

from tests.conftest import FixtureRunner
from tlslibhunter import discover_cli
from tlslibhunter.discovery import engine, probe
from tlslibhunter.discovery.profile import Profile
from tlslibhunter.utils.android_related import ProcessEntry

GMS = "com.google.android.gms"
GSA = "com.google.android.googlequicksearchbox"
VENDING = "com.android.vending"
BARD = "com.google.android.apps.bard"


class TestDescriptorMapping:
    @pytest.mark.parametrize(
        ("descriptor", "package"),
        [
            ("com.google.android.gms.common.internal.IGmsServiceBroker", GMS),
            ("com.google.android.apps.gsa.search.shared.service.ISearchService", GSA),
            ("com.google.android.search.verification.api.ISearchActionVerificationService", GSA),
            ("com.android.vending.billing.IInAppBillingService", VENDING),
            ("com.example.IThing", None),
            ("android.support.customtabs.ICustomTabsService", None),
        ],
    )
    def test_shipped_map(self, descriptor, package):
        assert probe.descriptor_to_package(descriptor) == package

    def test_custom_map_longest_prefix_wins(self):
        known = {"a.": "pkg.a", "a.b.": "pkg.ab"}
        assert probe.descriptor_to_package("a.b.IFoo", known) == "pkg.ab"
        assert probe.descriptor_to_package("a.c.IFoo", known) == "pkg.a"
        assert probe.descriptor_to_package("z.IFoo", known) is None

    @pytest.mark.parametrize(
        "descriptor",
        ["android.os.IServiceManager", "android.app.IActivityManager", "android.content.pm.IPackageManager"],
    )
    def test_generic_system_interfaces_ignored(self, descriptor):
        assert probe.is_ignored_descriptor(descriptor)

    def test_explicit_mapping_beats_ignore(self):
        assert not probe.is_ignored_descriptor("android.support.customtabs.ICustomTabsService")
        assert not probe.is_ignored_descriptor("com.example.IThing")

    def test_shipped_map_is_consistent(self):
        descriptor_map = probe.load_descriptor_map()
        assert descriptor_map.ignore and all(prefix.endswith(".") for prefix in descriptor_map.ignore)


class TestEvidence:
    def test_binder_evidence(self):
        assert probe.binder_evidence("com.x.IFoo") == "handoff:binder:com.x.IFoo"

    def test_escapes_unsafe_characters(self):
        assert probe.escape_descriptor("a b\n'é ") == "a\\x20b\\x0a\\x27\\xe9\\u2028"

    def test_evidence_is_capped(self):
        evidence = probe.binder_evidence("com.x." + "A" * 500)
        assert len(evidence) == probe.MAX_EVIDENCE_LENGTH and evidence.startswith("handoff:binder:com.x.")

    def test_package_evidence_and_unmapped(self):
        result = probe.ProbeResult(
            descriptors={
                "com.google.android.gms.IA",
                "com.google.android.gms.IB",
                "android.os.IServiceManager",
                "org.chromium.IFoo",
                "com.example.I Bar",
            }
        )
        assert probe.probe_package_evidence(result) == {
            GMS: ["handoff:binder:com.google.android.gms.IA", "handoff:binder:com.google.android.gms.IB"]
        }
        assert probe.unmapped_descriptors(result) == ["com.example.I\\x20Bar", "org.chromium.IFoo"]


class TestMessages:
    def test_binder_and_net_messages(self):
        result = probe.ProbeResult()
        probe.record_message(result, {"type": "send", "payload": {"type": "binder", "descriptor": "a.IB"}})
        probe.record_message(result, {"type": "send", "payload": {"type": "net", "port": 443, "proto": "udp"}})
        probe.record_message(result, {"type": "error", "description": "boom"})
        probe.record_message(result, {"type": "send", "payload": {"type": "binder", "descriptor": 5}})
        probe.record_message(result, {"type": "send", "payload": "junk"})
        assert (result.descriptors, result.net_events) == ({"a.IB"}, 1)

    def test_agent_is_bundled(self):
        source = probe.load_probe_agent()
        assert "BinderProxy" in source and "getInterfaceDescriptor" in source


class FakeScript:
    def __init__(self, messages):
        self.messages = messages

    def on(self, signal, callback):
        self.callback = callback

    def load(self):
        for message in self.messages:
            self.callback(message, None)


class FakeSession:
    def __init__(self, messages):
        self.messages, self.detached = messages, False

    def create_script(self, source):
        return FakeScript(self.messages)

    def detach(self):
        self.detached = True


class FakeApp:
    def __init__(self, identifier, pid):
        self.identifier, self.pid = identifier, pid


class FakeDevice:
    def __init__(self, pid=42, messages=()):
        self.pid, self.session, self.calls = pid, FakeSession(list(messages)), []

    def enumerate_applications(self, identifiers):
        return [FakeApp(identifiers[0], self.pid)]

    def attach(self, pid):
        self.calls.append(("attach", pid))
        return self.session

    def spawn(self, argv):
        self.calls.append(("spawn", argv))
        return 77

    def resume(self, pid):
        self.calls.append(("resume", pid))


BINDER_MESSAGE = {"type": "send", "payload": {"type": "binder", "descriptor": "com.google.android.gms.IA"}}


class TestRunProbe:
    def test_attach_runs_before_attach_and_detaches(self):
        device, thawed, slept = FakeDevice(messages=[BINDER_MESSAGE]), [], []
        result = probe.run_probe(device, BARD, 5, before_attach=thawed.append, sleep=slept.append)
        assert result.descriptors == {"com.google.android.gms.IA"}
        assert (thawed, slept, device.calls) == ([42], [5], [("attach", 42)])
        assert device.session.detached

    def test_not_running_raises(self):
        with pytest.raises(RuntimeError):
            probe.run_probe(FakeDevice(pid=0), BARD, 1, sleep=lambda _: None)

    def test_spawn_resumes_after_load(self):
        device = FakeDevice()
        probe.run_probe(device, BARD, 1, spawn=True, sleep=lambda _: None)
        assert device.calls == [("spawn", [BARD]), ("attach", 77), ("resume", 77)]


class TestLaunch:
    def test_launch_app_uses_monkey(self):
        runner, slept = FixtureRunner(), []
        probe.launch_app(runner, BARD, sleep=slept.append)
        assert runner.commands == [f"monkey -p {BARD} 1"] and slept == [probe.LAUNCH_WAIT_SECONDS]

    def test_rejects_unsafe_package(self):
        with pytest.raises(ValueError):
            probe.launch_command("x;reboot")

    def test_not_running_target_is_launched_then_attached(self):
        device = FakeDevice(pid=0)

        def launch():
            device.pid = 99

        probe.run_probe(device, BARD, 1, launch=launch, sleep=lambda _: None)
        assert device.calls == [("attach", 99)]

    def test_still_not_running_after_launch_raises(self):
        with pytest.raises(RuntimeError, match="hand off"):
            probe.running_or_launched_pid(FakeDevice(pid=0), BARD, launch=lambda: None)


class TestEngineMerge:
    def snapshot(self):
        procs = [
            ProcessEntry(1, 10500, "com.app"),
            ProcessEntry(2, 10600, "com.helper"),
            ProcessEntry(3, 10600, "com.helper:bg"),
            ProcessEntry(4, 10162, GMS),
            ProcessEntry(5, 10700, "com.unrelated"),
        ]
        uids = {"com.app": [10500], "com.helper": [10600], GMS: [10162], "com.unrelated": [10700]}
        return engine.Snapshot(processes=procs, package_uids=uids)

    def test_probe_package_processes_become_delegates(self):
        evidence = {"com.helper": ["handoff:binder:com.helper.IX"], GMS: ["handoff:binder:com.google.android.gms.IA"]}
        cands = {cand.process: cand for cand in engine.classify(self.snapshot(), "com.app", evidence)}
        assert set(cands) == {"com.app", "com.helper", "com.helper:bg"}
        assert cands["com.helper:bg"].role == "delegate"
        assert cands["com.helper"].evidence == ["handoff:binder:com.helper.IX"]

    def test_without_probe_no_delegates(self):
        assert [cand.process for cand in engine.classify(self.snapshot(), "com.app")] == ["com.app"]

    def test_probe_delegates_skip_shared_target_and_known(self):
        evidence = {GMS: [], "com.app": [], "com.helper": [], "com.known": []}
        assert engine.probe_delegates("com.app", evidence, ["com.known"]) == ["com.helper"]

    def test_discover_records_unmapped_descriptors(self):
        result = probe.ProbeResult(descriptors={"com.example.IThing", "android.os.IServiceManager"})
        profile = engine.discover(FixtureRunner(root=False), BARD, sleep=lambda _: None, probe=result)
        assert profile.binder_descriptors == ["com.example.IThing"]

    def test_profile_without_binder_descriptors_still_loads(self):
        data = Profile(target="x", target_package="x").to_dict()
        del data["binder_descriptors"]
        assert Profile.from_dict(data).binder_descriptors == []


class TestCli:
    def args(self, argv):
        return discover_cli.build_discover_parser().parse_args(argv)

    def test_probe_flag(self):
        assert self.args([BARD, "--probe"]).probe and not self.args([BARD]).probe

    def test_run_discover_merges_probe(self, capsys, monkeypatch):
        monkeypatch.setattr(probe, "LAUNCH_WAIT_SECONDS", 0)
        result = probe.ProbeResult(descriptors={"com.example.IThing"}, net_events=2)
        seen = []

        def fake_probe(package, duration, serial, launch):
            seen.append((package, duration, serial))
            launch()
            return result

        args = self.args([BARD, "--probe", "--duration", "0", "--serial", "S"])
        runner = FixtureRunner()
        assert discover_cli.run_discover(args, runner=runner, frida_probe=fake_probe) == 0
        out = capsys.readouterr()
        assert seen == [(BARD, 0.0, "S")] and f"monkey -p {BARD} 1" in runner.commands
        assert "1 binder interface(s), 2 TLS socket event(s)" in out.err
        assert "com.example.IThing" in out.out

    def test_probe_failure_is_not_fatal(self, capsys):
        def broken(package, duration, serial, launch):
            raise RuntimeError("attach timed out")

        namespace = argparse.Namespace(duration=0.0, serial=None)
        assert discover_cli.run_probe_step(FixtureRunner(), BARD, namespace, broken) is None
