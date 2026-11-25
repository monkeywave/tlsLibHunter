"""Tests for discovery orchestration on recorded Pixel 5 (Android 14) Gemini fixtures.

Facts of that session: Gemini (bard, uid 10298) has no internet sockets; the
Google app's ``:search`` process (uid 10156) hosts its UI and owns the QUIC
sockets; GMS is uid 10162; Cloudflare WARP (uid 10274) owns a QUIC tunnel.
"""

import pytest

from tests.conftest import FixtureRunner
from tlslibhunter.discovery import engine
from tlslibhunter.discovery.profile import Candidate

BARD = "com.google.android.apps.bard"
GSA = "com.google.android.googlequicksearchbox"
GSA_SEARCH = f"{GSA}:search"
GMS = "com.google.android.gms"
WARP_UID = 10274

# GMS (pid 19016) holding its CLOSE_WAIT 443 socket; absent from the real fd listing.
GMS_FD_LISTING = "PID 19016\nlrwx------ 1 root root 64 d 7 -> socket:[8338687]\n"


def classify(runner: FixtureRunner, root: bool = True) -> dict[str, Candidate]:
    return {cand.process: cand for cand in engine.classify(engine.collect_snapshot(runner, root), BARD)}


class TestCollectSnapshot:
    def test_root_snapshot_scans_fds_only_for_tls_socket_uids(self):
        runner = FixtureRunner()
        snapshot = engine.collect_snapshot(runner, root=True)
        fd_scans = [cmd for cmd in runner.commands if "/proc/$p/fd" in cmd]
        assert fd_scans == [
            engine.as_root(
                'for p in 568 5334 6371 19016 29615 32457 2267; do echo "PID $p"; ls -l /proc/$p/fd 2>/dev/null; done'
            )
        ]
        assert snapshot.root and snapshot.foreground_package == GSA

    def test_root_snapshot_reads_proc_net_via_su(self):
        runner = FixtureRunner()
        engine.collect_snapshot(runner, root=True)
        assert engine.as_root("cat /proc/net/udp6") in runner.commands

    def test_no_root_snapshot_has_no_fd_scan(self):
        runner = FixtureRunner()
        snapshot = engine.collect_snapshot(runner, root=False)
        assert not snapshot.root
        assert not any("su -c" in cmd for cmd in runner.commands)


class TestClassifyRoot:
    def test_gsa_search_is_delegate_with_quic_evidence(self):
        search = classify(FixtureRunner())[GSA_SEARCH]
        assert search.role == "delegate" and search.pid == 568
        assert "net:udp-connected:443" in search.evidence
        assert "foreground_host" in search.evidence

    def test_bard_is_target_without_sockets(self):
        bard = classify(FixtureRunner())[BARD]
        assert (bard.role, bard.pid, bard.evidence) == ("target", 11192, [])

    def test_warp_vpn_is_never_attributed(self):
        assert all(cand.uid != WARP_UID for cand in classify(FixtureRunner()).values())

    def test_gms_absent_when_it_owns_no_sockets(self):
        assert not any(cand.package == GMS for cand in classify(FixtureRunner()).values())

    def test_gms_is_shared_system_when_it_owns_sockets(self):
        gms = classify(FixtureRunner({"su -c 'for p in": GMS_FD_LISTING}))[GMS]
        assert gms.role == "shared_system"
        assert gms.evidence == ["net:tcp:443", f"oom_bound_by:{GSA_SEARCH}"]

    def test_interactor_bound_by_delegate_is_delegate(self):
        interactor = classify(FixtureRunner())[f"{GSA}:interactor"]
        assert interactor.evidence == [f"oom_bound_by:{GSA_SEARCH}"]

    def test_target_first_in_order(self):
        assert list(classify(FixtureRunner()))[0] == BARD


class TestClassifyNoRoot:
    def test_uid_attributed_evidence(self):
        search = classify(FixtureRunner(), root=False)[GSA_SEARCH]
        assert search.evidence[0] == "net:uid-attributed"
        assert not any(item.startswith("net:udp") for item in search.evidence)

    def test_warp_still_not_attributed(self):
        assert all(cand.uid != WARP_UID for cand in classify(FixtureRunner(), root=False).values())

    def test_dns_and_dot_ports_are_ignored(self):
        from tlslibhunter.discovery.sockets import SocketEntry
        from tlslibhunter.utils.android_related import ProcessEntry

        dot = SocketEntry("udp", "10.0.0.2", 4000, "1.1.1.1", 853, "01", 10156, 77)
        dns = SocketEntry("udp", "10.0.0.2", 4001, "1.1.1.1", 53, "01", 10156, 78)
        snapshot = engine.Snapshot(
            processes=[ProcessEntry(568, 10156, GSA_SEARCH)],
            sockets=[dot, dns],
            package_uids={GSA: [10156]},
            foreground_package=GSA,
        )
        (search,) = engine.classify(snapshot, BARD)
        assert search.evidence == ["foreground_host"]


class TestClassifyRoles:
    def snapshot(self, processes):
        return engine.Snapshot(processes=processes, package_uids={"com.app": [10500], "com.other": [10500]})

    def test_sdk_sandbox_and_same_uid_sibling(self):
        from tlslibhunter.utils.android_related import ProcessEntry

        procs = [
            ProcessEntry(1, 10500, "com.app"),
            ProcessEntry(2, 20500, "com.app_sdk_sandbox"),
            ProcessEntry(3, 10500, "com.other"),
        ]
        roles = {cand.process: (cand.role, cand.evidence) for cand in engine.classify(self.snapshot(procs), "com.app")}
        assert roles == {
            "com.app": ("target", []),
            "com.app_sdk_sandbox": ("sdk_sandbox", []),
            "com.other": ("sibling", ["same_uid"]),
        }


class TestMergeAndSampling:
    def test_merge_unions_evidence_and_keeps_latest_pid(self):
        merged = engine.merge_candidates({}, [Candidate(1, "p", "pkg", 10001, "delegate", ["a"])])
        engine.merge_candidates(merged, [Candidate(2, "p", "pkg", 10001, "delegate", ["b", "a"])])
        assert (merged["p"].pid, merged["p"].evidence) == (2, ["a", "b"])

    def test_merge_confirms_socket_and_preloaded_lib_from_different_samples(self):
        merged = engine.merge_candidates({}, [Candidate(1, "p", "pkg", 10001, "target", ["net:tcp:443"])])
        engine.merge_candidates(merged, [Candidate(1, "p", "pkg", 10001, "target", ["tls_lib:conscrypt/libssl.so"])])
        assert merged["p"].confirmed

    @pytest.mark.parametrize(("duration", "interval", "expected"), [(0, 2, 1), (10, 2, 5), (3, 2, 1), (5, 0, 1)])
    def test_sample_count(self, duration, interval, expected):
        assert engine.sample_count(duration, interval) == expected


class TestDiscover:
    def runner(self):
        return FixtureRunner(
            {
                "getprop ro.build.fingerprint": "google/redfin/redfin:14/UP1A/123:user/release-keys\n",
                "dumpsys package com.google.android.apps.bard": "    versionCode=1009090390 minSdk=28 targetSdk=35\n",
            }
        )

    def test_builds_profile_from_merged_samples(self):
        sleeps = []
        profile = engine.discover(self.runner(), BARD, duration=6, interval=2, target="Gemini", sleep=sleeps.append)
        assert sleeps == [2, 2]
        assert (profile.target, profile.target_package) == ("Gemini", BARD)
        assert profile.gate_packages == [BARD, GSA]
        assert profile.process_patterns[0] == BARD and GSA_SEARCH in profile.process_patterns
        assert profile.version_code == 1009090390
        assert profile.device_fingerprint.startswith("google/redfin")

    def test_auto_detects_root(self):
        runner = self.runner()
        profile = engine.discover(runner, BARD, sleep=lambda _: None)
        assert "su -c id" in runner.commands
        assert "net:udp-connected:443" in {e for c in profile.candidates for e in c.evidence}

    def test_without_root_uses_uid_attribution(self):
        runner = FixtureRunner(root=False)
        profile = engine.discover(runner, BARD, sleep=lambda _: None)
        assert "net:uid-attributed" in {e for c in profile.candidates for e in c.evidence}
        assert profile.version_code is None and profile.device_fingerprint is None

    def test_shared_system_excluded_from_patterns(self):
        profile = engine.discover(FixtureRunner(root=False), BARD, sleep=lambda _: None)
        assert GMS not in profile.process_patterns and GMS not in profile.gate_packages

    def test_rejects_shell_unsafe_package(self):
        with pytest.raises(ValueError):
            engine.discover(FixtureRunner(), "com.app; reboot", sleep=lambda _: None)


class TestAdbRunner:
    def test_returns_output_or_empty(self, monkeypatch):
        results = iter([(0, "ok"), (1, "error: no devices")])
        monkeypatch.setattr(engine, "adb_shell", lambda cmd, serial=None: next(results))
        run = engine.make_adb_runner("ABC")
        assert (run("id"), run("id")) == ("ok", "")


class TestPackageNameValidation:
    @pytest.mark.parametrize("name", ["com.example.app", "com.google.android.apps.bard", "a.b_c.d1", "x.1y"])
    def test_accepts_package_names(self, name):
        from tlslibhunter.discovery.topology import is_valid_android_package

        assert is_valid_android_package(name)
        assert engine.validate_package_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "app",
            "com.example\n",
            "com.example;reboot",
            "com.example app",
            "com.$(id).x",
            "1com.example",
            ".com.x",
            "com..x",
            None,
        ],
    )
    def test_rejects_non_package_names(self, name):
        from tlslibhunter.discovery.topology import is_valid_android_package

        assert not is_valid_android_package(name)
        with pytest.raises(ValueError, match="invalid Android package name"):
            engine.validate_package_name(name)

    def test_version_code_command_quotes_and_validates(self):
        assert engine.version_code_command("com.example.app") == "dumpsys package com.example.app | grep versionCode"
        with pytest.raises(ValueError):
            engine.version_code_command("com.example;rm -rf /")

    def test_discover_rejects_injection_before_any_device_command(self):
        calls = []

        def runner(cmd):
            calls.append(cmd)
            return ""

        with pytest.raises(ValueError):
            engine.discover(runner, "com.x`reboot`", root=False)
        assert calls == []


MAPS_SCAN = "PID 1\n7000-8000 r-xp 00000000 fd:21 77 /data/app/x/lib/arm64/libflutter.so\n"


class TestTlsLibConfirmation:
    def candidates(self):
        return [
            Candidate(1, "com.app", "com.app", 10001, "target"),
            Candidate(2, "com.google.android.gms", "com.google.android.gms", 10002, "shared_system", ["net:tcp:443"]),
        ]

    def test_reads_maps_once_for_attributable_pids_only(self):
        runner = FixtureRunner({"su -c 'for p in 1;": MAPS_SCAN})
        target, shared = engine.confirm_candidates(runner, self.candidates())
        maps_cmds = [cmd for cmd in runner.commands if "/maps" in cmd]
        assert maps_cmds == [engine.as_root('for p in 1; do echo "PID $p"; grep r-xp /proc/$p/maps 2>/dev/null; done')]
        assert target.evidence == ["tls_lib:libflutter.so"] and target.confirmed
        assert not shared.confirmed and shared.evidence == ["net:tcp:443"]

    def test_no_pids_no_command(self):
        runner = FixtureRunner()
        assert engine.read_tls_libs(runner, []) == {}
        assert runner.commands == []

    def test_discover_with_root_scans_maps(self):
        runner = FixtureRunner()
        engine.discover(runner, BARD, sleep=lambda _: None)
        assert any("/proc/$p/maps" in cmd for cmd in runner.commands)

    def test_discover_without_root_skips_maps(self):
        runner = FixtureRunner(root=False)
        engine.discover(runner, BARD, sleep=lambda _: None)
        assert not any("/maps" in cmd for cmd in runner.commands)
