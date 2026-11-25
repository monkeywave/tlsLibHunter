"""Tests for dumpsys oom adj-source parsing and delegate package selection."""

from tests.conftest import read_discovery_fixture
from tlslibhunter.discovery import handoff
from tlslibhunter.discovery.handoff import OomLink
from tlslibhunter.utils.android_related import parse_foreground_package

BARD = "com.google.android.apps.bard"
GSA = "com.google.android.googlequicksearchbox"
GMS = "com.google.android.gms"
SHARED = {GMS, "com.android.chrome"}

HEADER = "    Proc # 2: vis    F/ /BTOP LCMNFU  t: 0 19016:com.google.android.gms/u0a162 (service)"
ADJ = "        com.google.android.gms/.Svc<=Proc{568:com.google.android.googlequicksearchbox:search/u0a156}"


class TestParseOomProcesses:
    def test_header_fields(self):
        assert handoff.parse_oom_processes(HEADER) == [handoff.OomProcess(19016, GMS, "service")]

    def test_pers_header_and_padded_index(self):
        text = "    PERS #52: sys    F/ /PER  LCMNFU  t: 0 27734:system/1000 (fixed)\n"
        assert handoff.parse_oom_processes(text) == [handoff.OomProcess(27734, "system", "fixed")]

    def test_real_fixture_top_activity_is_gsa_search(self):
        processes = handoff.parse_oom_processes(read_discovery_fixture("dumpsys_oom.txt"))
        assert len(processes) == 53
        assert handoff.top_activity_pids(processes) == [568]


class TestParseOomAdjSources:
    def test_link_points_from_client_to_preceding_header(self):
        links = handoff.parse_oom_adj_sources(f"{HEADER}\n{ADJ}\n")
        assert links == [(f"{GSA}:search", 568, GMS, 19016)]

    def test_adj_line_without_header_is_ignored(self):
        assert handoff.parse_oom_adj_sources(ADJ) == []

    def test_non_proc_sources_are_ignored(self):
        assert handoff.parse_oom_adj_sources(f"{HEADER}\n        x/.y<=Activity{{abc u0 x/.A}}\n") == []

    def test_real_fixture_gsa_search_binds_interactor_and_gms(self):
        links = handoff.parse_oom_adj_sources(read_discovery_fixture("dumpsys_oom.txt"))
        served_by_search = [link.served_process for link in links if link.client_pid == 568]
        assert served_by_search == [f"{GSA}:interactor", GMS, "com.google.android.gms.unstable"]
        assert all(link.served_pid != 11192 for link in links)


class TestDelegatePackages:
    def test_foreground_host_is_delegate(self):
        foreground = parse_foreground_package(read_discovery_fixture("dumpsys_activities_resumed.txt"))
        assert handoff.delegate_packages(BARD, foreground, [], SHARED) == [GSA]

    def test_packages_bound_by_target_are_delegates(self):
        links = [OomLink(f"{BARD}:bg", 1, "com.example.helper:svc", 2)]
        assert handoff.delegate_packages(BARD, None, links, SHARED) == ["com.example.helper"]

    def test_links_from_other_clients_are_ignored(self):
        links = [OomLink(f"{GSA}:search", 568, "com.example.helper", 2)]
        assert handoff.delegate_packages(BARD, None, links, SHARED) == []

    def test_excludes_shared_target_launcher_and_systemui(self):
        links = [OomLink(BARD, 1, pkg, 2) for pkg in (GMS, BARD, "com.android.systemui")]
        assert handoff.delegate_packages(BARD, "com.google.android.apps.nexuslauncher", links, SHARED) == []

    def test_deduplicates_keeping_foreground_first(self):
        links = [OomLink(BARD, 1, "com.example.helper", 2), OomLink(BARD, 1, GSA, 3)]
        assert handoff.delegate_packages(BARD, GSA, links, SHARED) == [GSA, "com.example.helper"]
