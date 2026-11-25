"""Pure helpers for classifying Android UIDs.

An Android UID encodes the user (profile) and the per-user app id:
``uid = user_id * 100000 + app_id``. The app id ranges tell what kind of
process owns the UID (regular app, SDK sandbox, isolated service).
"""

from __future__ import annotations

PER_USER_RANGE = 100000

FIRST_APPLICATION_APP_ID = 10000
LAST_APPLICATION_APP_ID = 19999
FIRST_SDK_SANDBOX_APP_ID = 20000
LAST_SDK_SANDBOX_APP_ID = 29999
# 90000-98999 are app-zygote isolated UIDs, 99000-99999 plain isolated UIDs.
FIRST_ISOLATED_APP_ID = 90000
LAST_ISOLATED_APP_ID = 99999


def app_id(uid: int) -> int:
    """Per-user app id of ``uid`` (``uid % 100000``)."""
    return uid % PER_USER_RANGE


def user_id(uid: int) -> int:
    """Android user (profile) of ``uid`` (``uid // 100000``)."""
    return uid // PER_USER_RANGE


def _app_id_in_range(uid: int, first: int, last: int) -> bool:
    return first <= app_id(uid) <= last


def is_app_uid(uid: int) -> bool:
    """True for a regular installed application UID (app id 10000-19999)."""
    return _app_id_in_range(uid, FIRST_APPLICATION_APP_ID, LAST_APPLICATION_APP_ID)


def is_sdk_sandbox_uid(uid: int) -> bool:
    """True for an SDK runtime sandbox UID (app id 20000-29999)."""
    return _app_id_in_range(uid, FIRST_SDK_SANDBOX_APP_ID, LAST_SDK_SANDBOX_APP_ID)


def is_isolated_uid(uid: int) -> bool:
    """True for an isolated process UID, including app-zygote isolated (app id 90000-99999)."""
    return _app_id_in_range(uid, FIRST_ISOLATED_APP_ID, LAST_ISOLATED_APP_ID)


def same_app(uid_a: int, uid_b: int) -> bool:
    """True if both UIDs belong to the same app id within the same Android user."""
    return user_id(uid_a) == user_id(uid_b) and app_id(uid_a) == app_id(uid_b)
