"""macOS platform handler."""

from __future__ import annotations

from tlslibhunter.platforms.base import PlatformHandler

SYSTEM_PREFIXES = (
    "/System/Library/",
    "/usr/lib/",
    "/Library/Apple/",
)


class MacOSHandler(PlatformHandler):
    def is_system_library(self, name: str, path: str) -> bool:
        if not path:
            return True
        return any(path.startswith(prefix) for prefix in SYSTEM_PREFIXES)

    def get_extraction_order(self) -> list[str]:
        return ["disk_copy", "memory_dump"]
