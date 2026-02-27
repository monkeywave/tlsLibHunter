"""Disk-based library extraction (copy from filesystem)."""

from __future__ import annotations

import logging
import os
import shutil
from typing import Any

from tlslibhunter.extractor.base import Extractor
from tlslibhunter.scanner.results import DetectedLibrary, ExtractionResult

logger = logging.getLogger("tlslibhunter.extractor.disk")


class DiskExtractor(Extractor):
    """Extract libraries by copying from the local filesystem."""

    @property
    def method_name(self) -> str:
        return "disk_copy"

    def can_extract(self, library: DetectedLibrary, platform: str) -> bool:
        if platform in ("android", "ios"):
            return False
        return bool(library.path) and os.path.isfile(library.path)

    def extract(
        self,
        library: DetectedLibrary,
        output_path: str,
        backend: Any = None,
        session: Any = None,
    ) -> ExtractionResult:
        try:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            shutil.copy2(library.path, output_path)
            size = os.path.getsize(output_path)
            logger.info("Copied %s -> %s (%d bytes)", library.path, output_path, size)
            return ExtractionResult(
                library=library,
                success=True,
                output_path=output_path,
                method=self.method_name,
                size_bytes=size,
            )
        except PermissionError:
            msg = f"Permission denied: {library.path}"
            logger.warning(msg)
            return ExtractionResult(library=library, success=False, method=self.method_name, error=msg)
        except Exception as e:
            msg = f"Copy failed: {e}"
            logger.warning(msg)
            return ExtractionResult(library=library, success=False, method=self.method_name, error=msg)
