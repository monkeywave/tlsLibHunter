"""macOS platform handler."""

from __future__ import annotations

from tlslibhunter.platforms.base import PlatformHandler

SYSTEM_PREFIXES = (
    "/System/Library/",
    "/usr/lib/",
    "/Library/Apple/",
)

# Paths that contain system frameworks which are almost never TLS implementations.
# Modules under these prefixes are skipped unless their name matches a TLS-candidate whitelist.
SYSTEM_FRAMEWORK_PREFIXES = (
    "/System/Library/Frameworks/",
    "/System/Library/PrivateFrameworks/",
    "/System/Library/Extensions/",
    "/System/Library/CoreServices/",
    "/System/iOSSupport/",
)


class MacOSHandler(PlatformHandler):
    def is_system_library(self, name: str, path: str) -> bool:
        if not path:
            return True
        return any(path.startswith(prefix) for prefix in SYSTEM_PREFIXES)

    def get_extraction_order(self) -> list[str]:
        return ["disk_copy", "dsc_native", "dyld_cache", "memory_dump"]
