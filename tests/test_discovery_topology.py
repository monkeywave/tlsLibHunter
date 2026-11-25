"""Tests for Android process topology helpers."""

import pytest

from tlslibhunter.discovery import topology
from tlslibhunter.utils.android_related import ProcessEntry

PM_OUTPUT = """\
package:com.example.app uid:10156
package:com.google.android.gms uid:10120,1010120
package:android uid:1000
garbage line
package:no.uid.here
"""


class TestParsePmPackagesUids:
    def test_single_and_multi_user(self):
        result = topology.parse_pm_packages_uids(PM_OUTPUT)
        assert result == {
            "com.example.app": [10156],
            "com.google.android.gms": [10120, 1010120],
            "android": [1000],
        }

    def test_empty(self):
        assert topology.parse_pm_packages_uids("") == {}

    def test_crlf_and_whitespace(self):
        assert topology.parse_pm_packages_uids("  package:a.b uid:10001\r\n") == {"a.b": [10001]}


class TestClassifyProcessKind:
    @pytest.mark.parametrize(
        "uid,name,kind",
        [
            (10156, "com.example.app", topology.KIND_APP),
            (1010156, "com.example.app:remote", topology.KIND_APP),
            (20156, "com.example.app_sdk_sandbox", topology.KIND_SDK_SANDBOX),
            (10156, "com.example.app_sdk_sandbox", topology.KIND_SDK_SANDBOX),
            (99078, "com.android.chrome:sandboxed_process0", topology.KIND_ISOLATED),
            (90012, "com.example.app:zygote_isolated", topology.KIND_ISOLATED),
            (1000, "system_server", topology.KIND_SYSTEM),
            (0, "netd", topology.KIND_SYSTEM),
        ],
    )
    def test_kinds(self, uid, name, kind):
        assert topology.classify_process_kind(ProcessEntry(pid=1, uid=uid, name=name)) == kind


class TestProcessesForUids:
    PROCS = [
        ProcessEntry(1, 10156, "com.example.app"),
        ProcessEntry(2, 10156, "com.example.app:remote"),
        ProcessEntry(3, 1010156, "com.example.app"),
        ProcessEntry(4, 10157, "com.other"),
        ProcessEntry(5, 1000, "system_server"),
    ]

    def test_same_app_same_user(self):
        assert [p.pid for p in topology.processes_for_uids(self.PROCS, [10156])] == [1, 2]

    def test_multi_user_uids(self):
        assert [p.pid for p in topology.processes_for_uids(self.PROCS, [10156, 1010156])] == [1, 2, 3]

    def test_no_uids(self):
        assert topology.processes_for_uids(self.PROCS, []) == []
