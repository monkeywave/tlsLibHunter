"""iOS platform handler."""

from __future__ import annotations

from tlslibhunter.platforms.base import PlatformHandler

SYSTEM_PREFIXES = (
    "/System/Library/",
    "/usr/lib/",
    "/Developer/",
)


class IOSHandler(PlatformHandler):
    def is_system_library(self, name: str, path: str) -> bool:
        if not path:
            return True
        path_lower = path.lower()
        return any(path_lower.startswith(prefix.lower()) for prefix in SYSTEM_PREFIXES)

    def get_extraction_order(self) -> list[str]:
        return ["frida_read", "memory_dump"]
