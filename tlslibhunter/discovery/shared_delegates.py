"""Shared system delegates: processes that do network work on behalf of many apps.

The list lives in ``shared_delegates.json`` next to this module. WebView is
deliberately absent: it renders inside the app's own process.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

SHARED_DELEGATES_FILE = Path(__file__).with_name("shared_delegates.json")


@lru_cache(maxsize=1)
def load_shared_delegates() -> frozenset[str]:
    """Package names (plus ``netd``) whose traffic cannot be attributed to one app."""
    data = json.loads(SHARED_DELEGATES_FILE.read_text(encoding="utf-8"))
    return frozenset(data["packages"])


def is_shared_delegate(package: str) -> bool:
    """True if ``package`` is a shared system delegate."""
    return package in load_shared_delegates()
