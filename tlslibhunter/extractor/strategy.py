"""Extraction strategy - tries extraction methods in platform-specific order."""

from __future__ import annotations

import logging
import os
from typing import Any

from tlslibhunter.extractor.android_extractor import AdbPullExtractor, ApkInnerExtractor
from tlslibhunter.extractor.base import Extractor
from tlslibhunter.extractor.disk_extractor import DiskExtractor
from tlslibhunter.extractor.ios_extractor import IOSExtractor
from tlslibhunter.extractor.memory_extractor import MemoryExtractor
from tlslibhunter.platforms.detection import get_platform_handler
from tlslibhunter.scanner.results import DetectedLibrary, ExtractionResult

logger = logging.getLogger("tlslibhunter.extractor.strategy")

# Map extraction method names to extractor classes
EXTRACTORS: dict[str, type] = {
    "disk_copy": DiskExtractor,
    "apk_inner": ApkInnerExtractor,
    "adb_pull": AdbPullExtractor,
    "apk_extract": AdbPullExtractor,  # Alias; uses same adb pull logic
    "frida_read": IOSExtractor,
    "memory_dump": MemoryExtractor,
}


class ExtractionStrategy:
    """Tries extraction methods in platform-specific order until one succeeds."""

    def __init__(
        self,
        backend: Any,
        session: Any,
        platform: str,
        output_dir: str,
    ):
        self._backend = backend
        self._session = session
        self._platform = platform
        self._output_dir = output_dir
        self._handler = get_platform_handler(platform)

        # Build ordered list of extractors from platform's extraction order
        method_names = self._handler.get_extraction_order()
        self._extractors: list[Extractor] = []
        seen = set()
        for name in method_names:
            if name in EXTRACTORS and name not in seen:
                self._extractors.append(EXTRACTORS[name]())
                seen.add(name)

    def extract(self, library: DetectedLibrary) -> ExtractionResult:
        """Extract a library using the first successful method.

        Args:
            library: Library to extract

        Returns:
            ExtractionResult from the first successful extractor,
            or the last failure if all methods fail.
        """
        output_path = os.path.join(self._output_dir, library.name)
        os.makedirs(self._output_dir, exist_ok=True)

        last_result = ExtractionResult(
            library=library,
            success=False,
            error="No extraction methods available",
        )

        for extractor in self._extractors:
            if not extractor.can_extract(library, self._platform):
                logger.debug(
                    "Skipping %s for %s (not applicable)",
                    extractor.method_name,
                    library.name,
                )
                continue

            logger.info(
                "Trying %s for %s...",
                extractor.method_name,
                library.name,
            )
            result = extractor.extract(
                library,
                output_path,
                backend=self._backend,
                session=self._session,
            )

            if result.success:
                return result

            last_result = result
            logger.debug(
                "%s failed for %s: %s",
                extractor.method_name,
                library.name,
                result.error,
            )

        return last_result
