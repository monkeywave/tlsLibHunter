"""Platform detection and handler factory."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tlslibhunter.platforms.base import PlatformHandler

PLATFORM_MAP = {
    "android": "tlslibhunter.platforms.android:AndroidHandler",
    "ios": "tlslibhunter.platforms.ios:IOSHandler",
    "windows": "tlslibhunter.platforms.windows:WindowsHandler",
    "linux": "tlslibhunter.platforms.linux:LinuxHandler",
    "macos": "tlslibhunter.platforms.macos:MacOSHandler",
}


def get_platform_handler(platform: str) -> PlatformHandler:
    """Get the platform handler for a given platform name.

    Args:
        platform: Platform name (android, ios, windows, linux, macos)

    Returns:
        PlatformHandler instance

    Raises:
        ValueError: If platform is unknown
    """
    key = platform.lower()
    if key not in PLATFORM_MAP:
        raise ValueError(f"Unknown platform: {platform!r}. Available: {', '.join(PLATFORM_MAP)}")

    module_path, class_name = PLATFORM_MAP[key].rsplit(":", 1)
    import importlib

    mod = importlib.import_module(module_path)
    cls = getattr(mod, class_name)
    return cls()
