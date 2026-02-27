"""Android-specific library extraction methods."""

from __future__ import annotations

import logging
import os
import shutil
import zipfile
from typing import Any

from tlslibhunter.extractor.base import Extractor
from tlslibhunter.scanner.results import DetectedLibrary, ExtractionResult

logger = logging.getLogger("tlslibhunter.extractor.android")


class ApkInnerExtractor(Extractor):
    """Extract libraries from APK inner paths (path!inner syntax)."""

    @property
    def method_name(self) -> str:
        return "apk_inner"

    def can_extract(self, library: DetectedLibrary, platform: str) -> bool:
        return platform == "android" and "!" in library.path

    def extract(
        self,
        library: DetectedLibrary,
        output_path: str,
        backend: Any = None,
        session: Any = None,
    ) -> ExtractionResult:
        from tlslibhunter.utils.adb import adb_pull, check_adb

        if not check_adb():
            return ExtractionResult(
                library=library,
                success=False,
                method=self.method_name,
                error="adb not available",
            )

        remote_apk, inner_path = library.path.split("!", 1)
        inner_path = inner_path.lstrip("/")

        # Pull APK to temp location
        tmp_dir = os.path.join(os.path.dirname(output_path), ".tmp_apks")
        os.makedirs(tmp_dir, exist_ok=True)
        local_apk = os.path.join(tmp_dir, os.path.basename(remote_apk))

        if not os.path.exists(local_apk):
            ok, msg = adb_pull(remote_apk, local_apk)
            if not ok:
                return ExtractionResult(
                    library=library,
                    success=False,
                    method=self.method_name,
                    error=f"adb pull failed: {msg}",
                )

        # Extract .so from APK
        try:
            with zipfile.ZipFile(local_apk, "r") as z:
                # Try exact path first
                matched = [e for e in z.namelist() if e == inner_path]
                if not matched:
                    # Fallback: match by basename
                    basename = os.path.basename(inner_path)
                    matched = [e for e in z.namelist() if e.endswith("/" + basename)]

                if not matched:
                    return ExtractionResult(
                        library=library,
                        success=False,
                        method=self.method_name,
                        error=f"'{inner_path}' not found in APK",
                    )

                os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
                with z.open(matched[0]) as src, open(output_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)

                size = os.path.getsize(output_path)
                logger.info("Extracted from APK: %s -> %s (%d bytes)", matched[0], output_path, size)
                return ExtractionResult(
                    library=library,
                    success=True,
                    output_path=output_path,
                    method=self.method_name,
                    size_bytes=size,
                )
        except zipfile.BadZipFile:
            return ExtractionResult(
                library=library,
                success=False,
                method=self.method_name,
                error="Invalid APK (bad zip)",
            )
        except Exception as e:
            return ExtractionResult(
                library=library,
                success=False,
                method=self.method_name,
                error=f"APK extraction failed: {e}",
            )


class AdbPullExtractor(Extractor):
    """Extract libraries via adb pull."""

    @property
    def method_name(self) -> str:
        return "adb_pull"

    def can_extract(self, library: DetectedLibrary, platform: str) -> bool:
        if platform != "android":
            return False
        # Don't try adb pull for APK inner paths
        if "!" in library.path:
            return False
        return bool(library.path)

    def extract(
        self,
        library: DetectedLibrary,
        output_path: str,
        backend: Any = None,
        session: Any = None,
    ) -> ExtractionResult:
        from tlslibhunter.utils.adb import adb_pull, check_adb

        if not check_adb():
            return ExtractionResult(
                library=library,
                success=False,
                method=self.method_name,
                error="adb not available",
            )

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        ok, msg = adb_pull(library.path, output_path)

        if ok and os.path.exists(output_path):
            size = os.path.getsize(output_path)
            logger.info("adb pull: %s -> %s (%d bytes)", library.path, output_path, size)
            return ExtractionResult(
                library=library,
                success=True,
                output_path=output_path,
                method=self.method_name,
                size_bytes=size,
            )
        return ExtractionResult(
            library=library,
            success=False,
            method=self.method_name,
            error=f"adb pull failed: {msg}",
        )
