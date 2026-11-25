"""Tests for the serializable discovery profile."""

import json

import pytest

from tlslibhunter.discovery import profile as prof
from tlslibhunter.discovery.profile import Candidate, Profile


def _candidates():
    return [
        Candidate(100, "com.example.app", "com.example.app", 10156, prof.ROLE_TARGET, ["net:tcp:443"]),
        Candidate(101, "com.example.app:remote", "com.example.app", 10156, prof.ROLE_SIBLING),
        Candidate(
            200,
            "com.google.android.googlequicksearchbox:search",
            "com.google.android.googlequicksearchbox",
            10090,
            prof.ROLE_DELEGATE,
        ),
        Candidate(300, "com.example.app_sdk_sandbox", "com.example.app_sdk_sandbox", 20156, prof.ROLE_SDK_SANDBOX),
        Candidate(400, "com.google.android.gms.persistent", "com.google.android.gms", 10120, prof.ROLE_SHARED_SYSTEM),
    ]


def _profile():
    cands = _candidates()
    return Profile(
        target="com.example.app",
        target_package="com.example.app",
        gate_packages=prof.gate_packages_from(cands),
        process_patterns=["com.example.app*"],
        device_fingerprint="google/husky/husky:15/AP4A/123:user/release-keys",
        version_code=42,
        candidates=cands,
    )


class TestGatePackagesFrom:
    def test_target_first_then_sorted_excluding_shared(self):
        assert prof.gate_packages_from(_candidates()) == [
            "com.example.app",
            "com.example.app_sdk_sandbox",
            "com.google.android.googlequicksearchbox",
        ]

    def test_empty(self):
        assert prof.gate_packages_from([]) == []


class TestProfile:
    def test_default_schema(self):
        assert _profile().schema == "tlslibhunter.profile/1"

    def test_attributable_excludes_shared_system(self):
        pids = [c.pid for c in _profile().attributable_candidates()]
        assert pids == [100, 101, 200, 300]

    def test_dict_round_trip(self):
        original = _profile()
        data = original.to_dict()
        assert data["candidates"][0]["evidence"] == ["net:tcp:443"]
        assert Profile.from_dict(data) == original

    def test_json_round_trip(self):
        original = _profile()
        text = original.to_json()
        assert json.loads(text)["schema"] == prof.PROFILE_SCHEMA
        assert Profile.from_json(text) == original

    def test_optional_fields_default(self):
        restored = Profile.from_dict({"schema": prof.PROFILE_SCHEMA, "target": "x", "target_package": "x"})
        assert restored.device_fingerprint is None and restored.version_code is None and restored.candidates == []

    @pytest.mark.parametrize("schema", ["tlslibhunter.profile/2", "other", None])
    def test_schema_mismatch_raises(self, schema):
        data = _profile().to_dict()
        data["schema"] = schema
        with pytest.raises(ValueError):
            Profile.from_dict(data)

    def test_confirmed_round_trips_and_defaults_for_old_profiles(self):
        data = _profile().to_dict()
        data["candidates"][0]["confirmed"] = True
        del data["candidates"][1]["confirmed"]
        loaded = Profile.from_dict(data)
        assert loaded.candidates[0].confirmed and not loaded.candidates[1].confirmed

    def test_missing_schema_raises(self):
        with pytest.raises(ValueError):
            Profile.from_dict({"target": "x", "target_package": "x"})
