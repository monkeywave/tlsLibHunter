"""Linux platform handler."""

from __future__ import annotations

from tlslibhunter.platforms.base import PlatformHandler

SYSTEM_PREFIXES = (
    "/lib/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/local/lib/",
    "/snap/",
)


class LinuxHandler(PlatformHandler):
    def is_system_library(self, name: str, path: str) -> bool:
        if not path:
            return True
        path_lower = path.lower()
        return any(path_lower.startswith(prefix) for prefix in SYSTEM_PREFIXES)

    def get_extraction_order(self) -> list[str]:
        return ["disk_copy", "memory_dump"]
