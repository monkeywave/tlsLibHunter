"""Tests for Android UID classification helpers."""

import pytest

from tlslibhunter.discovery import uids


class TestAppAndUserId:
    def test_primary_user(self):
        assert uids.app_id(10156) == 10156
        assert uids.user_id(10156) == 0

    def test_secondary_user(self):
        assert uids.app_id(1010156) == 10156
        assert uids.user_id(1010156) == 10


class TestIsAppUid:
    @pytest.mark.parametrize("uid", [10000, 10156, 19999, 1010156])
    def test_app_uids(self, uid):
        assert uids.is_app_uid(uid)

    @pytest.mark.parametrize("uid", [0, 1000, 9999, 20000, 99078])
    def test_non_app_uids(self, uid):
        assert not uids.is_app_uid(uid)


class TestIsSdkSandboxUid:
    @pytest.mark.parametrize("uid", [20000, 20156, 29999, 1020156])
    def test_sandbox_uids(self, uid):
        assert uids.is_sdk_sandbox_uid(uid)

    @pytest.mark.parametrize("uid", [19999, 30000, 10156])
    def test_non_sandbox_uids(self, uid):
        assert not uids.is_sdk_sandbox_uid(uid)


class TestIsIsolatedUid:
    @pytest.mark.parametrize("uid", [90000, 98999, 99000, 99078, 99999, 1099078])
    def test_isolated_uids(self, uid):
        assert uids.is_isolated_uid(uid)

    @pytest.mark.parametrize("uid", [89999, 10156, 1000])
    def test_non_isolated_uids(self, uid):
        assert not uids.is_isolated_uid(uid)


class TestSameApp:
    def test_same_uid(self):
        assert uids.same_app(10156, 10156)

    def test_same_app_other_user_is_not_same(self):
        assert not uids.same_app(10156, 1010156)

    def test_different_app_same_user(self):
        assert not uids.same_app(10156, 10301)
