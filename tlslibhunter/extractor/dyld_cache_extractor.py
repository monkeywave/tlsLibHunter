"""Extract system libraries from the macOS dyld shared cache."""

from __future__ import annotations

import logging
import os
import platform as platform_mod
import pathlib
from typing import Any

from tlslibhunter.extractor.base import Extractor
from tlslibhunter.scanner.results import DetectedLibrary, ExtractionResult

logger = logging.getLogger("tlslibhunter.extractor.dyld_cache")

_SYSTEM_PREFIXES = ("/System/Library/", "/usr/lib/", "/Library/Apple/")

# Warn once if dyldextractor is not installed
_warned_missing = False


def _find_dyld_cache() -> str | None:
    """Locate the dyld shared cache file for the current architecture."""
    arch = platform_mod.machine()
    # Try architecture suffixes in order of likelihood
    if arch == "arm64":
        suffixes = ["arm64e"]
    else:
        suffixes = ["x86_64h", "x86_64"]

    # Cache paths in order: Ventura+ (macOS 13+), then Big Sur/Monterey
    base_dirs = [
        "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
        "/System/Library/dyld",
    ]

    for base_dir in base_dirs:
        for suffix in suffixes:
            path = os.path.join(base_dir, f"dyld_shared_cache_{suffix}")
            if os.path.exists(path):
                return path
    return None


def _has_dyldextractor() -> bool:
    """Check if the dyldextractor package is available."""
    try:
        from DyldExtractor.dyld.dyld_context import DyldContext  # noqa: F401
        return True
    except ImportError:
        return False


class DyldCacheExtractor(Extractor):
    """Extract system libraries from the macOS dyld shared cache.

    Requires the optional `dyldextractor` package:
        pip install dyldextractor
    Or install tlsLibHunter with macOS extras:
        pip install tlsLibHunter[macos]
    """

    @property
    def method_name(self) -> str:
        return "dyld_cache"

    def can_extract(self, library: DetectedLibrary, platform: str) -> bool:
        if platform not in ("macos", "ios"):
            return False

        # Only for system libraries (not on disk)
        if not library.path or not any(
            library.path.startswith(p) for p in _SYSTEM_PREFIXES
        ):
            return False

        # File must NOT exist on disk (i.e., it's in the dyld cache)
        if os.path.isfile(library.path):
            return False

        if not _has_dyldextractor():
            global _warned_missing
            if not _warned_missing:
                logger.warning(
                    "dyldextractor not installed; dyld cache extraction unavailable. "
                    "Install with: pip install dyldextractor"
                )
                _warned_missing = True
            return False

        return True

    def extract(
        self,
        library: DetectedLibrary,
        output_path: str,
        backend: Any = None,
        session: Any = None,
    ) -> ExtractionResult:
        try:
            return self._extract_from_cache(library, output_path)
        except PermissionError:
            msg = f"Permission denied reading dyld cache (try with sudo)"
            logger.warning(msg)
            return ExtractionResult(
                library=library, success=False, method=self.method_name, error=msg
            )
        except Exception as e:
            msg = f"Dyld cache extraction failed: {e}"
            logger.warning(msg)
            return ExtractionResult(
                library=library, success=False, method=self.method_name, error=msg
            )

    def _extract_from_cache(
        self, library: DetectedLibrary, output_path: str
    ) -> ExtractionResult:
        from DyldExtractor.dyld.dyld_context import DyldContext
        from DyldExtractor.macho.macho_context import MachOContext
        from DyldExtractor.extraction_context import ExtractionContext
        from DyldExtractor.converter import (
            slide_info,
            macho_offset,
            linkedit_optimizer,
            stub_fixer,
        )

        cache_path = _find_dyld_cache()
        if not cache_path:
            return ExtractionResult(
                library=library,
                success=False,
                method=self.method_name,
                error="Could not locate dyld shared cache file",
            )

        cache_pathlib = pathlib.Path(cache_path)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(cache_path, "rb") as f:
            dyld_ctx = DyldContext(f)

            # Find the target image by path
            target_image = None
            for image_data in dyld_ctx.images:
                img_path = dyld_ctx.readString(image_data.pathFileOffset)
                img_path = img_path[:-1].decode("utf-8")  # strip null terminator
                if img_path == library.path:
                    target_image = image_data
                    break

            if target_image is None:
                return ExtractionResult(
                    library=library,
                    success=False,
                    method=self.method_name,
                    error=f"Image '{library.path}' not found in dyld cache",
                )

            # Load subcaches if present (macOS 12+)
            sub_cache_files = []
            try:
                sub_cache_files = dyld_ctx.addSubCaches(cache_pathlib)

                # Create writable MachO context
                result = dyld_ctx.convertAddr(target_image.address)
                if result is None:
                    return ExtractionResult(
                        library=library,
                        success=False,
                        method=self.method_name,
                        error=f"Failed to resolve address for '{library.name}' in dyld cache",
                    )
                macho_offset_val, context = result
                macho_ctx = MachOContext(context.fileObject, macho_offset_val, True)

                # Wire up subcache mappings
                if dyld_ctx.hasSubCaches():
                    mappings = dyld_ctx.mappings
                    main_file_map = next(
                        m[0] for m in mappings if m[1] == context
                    )
                    macho_ctx.addSubfiles(
                        main_file_map,
                        ((m, ctx.makeCopy(copyMode=True)) for m, ctx in mappings),
                    )

                # Create a minimal progress bar stub (dyldextractor requires one)
                status_bar = _NullProgressBar()
                extraction_ctx = ExtractionContext(
                    dyld_ctx, macho_ctx, status_bar, logger
                )

                # Run converter pipeline (reverses SharedCacheBuilder optimizations)
                slide_info.processSlideInfo(extraction_ctx)
                linkedit_optimizer.optimizeLinkedit(extraction_ctx)
                stub_fixer.fixStubs(extraction_ctx)

                # Try ObjC fixer (may fail on Python 3.13+ due to capstone/pkg_resources)
                try:
                    from DyldExtractor.converter import objc_fixer
                    objc_fixer.fixObjC(extraction_ctx)
                except Exception:
                    logger.debug("ObjC fixer unavailable, skipping (binary still usable)")

                # Compute final layout and write
                write_procedures = macho_offset.optimizeOffsets(extraction_ctx)

                with open(output_path, "wb") as out_file:
                    for proc in write_procedures:
                        out_file.seek(proc.writeOffset)
                        out_file.write(
                            proc.fileCtx.getBytes(proc.readOffset, proc.size)
                        )

            finally:
                for file in sub_cache_files:
                    file.close()

        size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
        logger.info(
            "Dyld cache extract: %s -> %s (%d bytes)", library.name, output_path, size
        )
        return ExtractionResult(
            library=library,
            success=True,
            output_path=output_path,
            method=self.method_name,
            size_bytes=size,
        )


class _NullProgressBar:
    """Minimal stub satisfying dyldextractor's progress bar interface."""

    def update(self, *args, **kwargs):
        pass

    def finish(self, *args, **kwargs):
        pass

    def __getattr__(self, name):
        return self.update
