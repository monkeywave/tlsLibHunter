"""Abstract platform handler interface."""

from __future__ import annotations

import abc


class PlatformHandler(abc.ABC):
    """Abstract handler for platform-specific TLS library knowledge."""

    @abc.abstractmethod
    def is_system_library(self, name: str, path: str) -> bool:
        """Check if a library is a system/OS library."""

    @abc.abstractmethod
    def get_extraction_order(self) -> list[str]:
        """Return ordered list of extraction method names to try.

        Returns:
            List like ["disk_copy", "memory_dump"] or
            ["apk_inner", "adb_pull", "apk_extract", "memory_dump"]
        """

    def classify(self, name: str, path: str) -> str:
        """Classify a library as 'system' or 'app'.

        Args:
            name: Library filename
            path: Full library path

        Returns:
            "system" or "app"
        """
        return "system" if self.is_system_library(name, path) else "app"
