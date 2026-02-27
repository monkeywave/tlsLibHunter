"""Android platform handler."""

from __future__ import annotations

from tlslibhunter.platforms.base import PlatformHandler

SYSTEM_LIB_PREFIXES = (
    "/system/lib64/",
    "/system/lib/",
    "/vendor/lib64/",
    "/vendor/lib/",
    "/apex/com.android.",
    "/apex/",
    "/product/lib64/",
    "/product/lib/",
    "/system_ext/lib64/",
    "/system_ext/lib/",
)

SYSTEM_DATA_PREFIXES = (
    "/data/misc/apexdata/",
    "/data/dalvik-cache/",
    "/data/misc/profiles/",
    "/data/system/",
    "/data/local/",
)


class AndroidHandler(PlatformHandler):
    def is_system_library(self, name: str, path: str) -> bool:
        if not path:
            return True
        for prefix in SYSTEM_LIB_PREFIXES:
            if path.startswith(prefix):
                return True
        return any(path.startswith(prefix) for prefix in SYSTEM_DATA_PREFIXES)

    def is_app_library(self, path: str, package_name: str | None = None) -> bool:
        if not path:
            return False
        if "!" in path:
            return True
        if "/data/app/" in path:
            return True
        if package_name and f"/data/data/{package_name}/" in path:
            return True
        return bool(package_name and "." in package_name and package_name in path)

    def classify(self, name: str, path: str, package_name: str | None = None) -> str:
        if self.is_app_library(path, package_name):
            return "app"
        if self.is_system_library(name, path):
            return "system"
        return "app"

    def get_extraction_order(self) -> list[str]:
        return ["apk_inner", "adb_pull", "apk_extract", "memory_dump"]
