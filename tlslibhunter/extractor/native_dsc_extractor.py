"""Extract system libraries from the macOS dyld shared cache using Apple's native dsc_extractor."""

from __future__ import annotations

import contextlib
import ctypes
import json
import logging
import os
import shutil
from typing import Any

from tlslibhunter.extractor.base import Extractor
from tlslibhunter.extractor.dyld_cache_extractor import _SYSTEM_PREFIXES, _find_dyld_cache
from tlslibhunter.scanner.results import DetectedLibrary, ExtractionResult

logger = logging.getLogger("tlslibhunter.extractor.native_dsc")

_DSC_BUNDLE_PATH = "/usr/lib/dsc_extractor.bundle"
_META_FILE = "extraction_meta.json"

# Module-level caches to avoid redundant ctypes loads and filesystem lookups
_cached_dsc_lib: ctypes.CDLL | None = None
_dsc_lib_checked = False


def _get_cache_dir() -> str:
    """Get the cache directory, expanding ~ at runtime."""
    return os.path.join(os.path.expanduser("~"), ".cache", "tlslibhunter", "dsc")


def _load_dsc_extractor() -> ctypes.CDLL | None:
    """Load Apple's dsc_extractor bundle if available (cached after first call)."""
    global _cached_dsc_lib, _dsc_lib_checked
    if _dsc_lib_checked:
        return _cached_dsc_lib
    _dsc_lib_checked = True
    if not os.path.exists(_DSC_BUNDLE_PATH):
        return None
    with contextlib.suppress(OSError):
        _cached_dsc_lib = ctypes.cdll.LoadLibrary(_DSC_BUNDLE_PATH)
    return _cached_dsc_lib


def _is_cache_valid(cache_dir: str, dyld_cache_path: str) -> bool:
    """Check if the extraction cache is still valid (matches current dyld cache mtime)."""
    meta_path = os.path.join(cache_dir, _META_FILE)
    if not os.path.exists(meta_path):
        return False
    try:
        with open(meta_path) as f:
            meta = json.load(f)
        cached_mtime = meta.get("dyld_cache_mtime", 0)
        current_mtime = os.path.getmtime(dyld_cache_path)
        return cached_mtime == current_mtime
    except (OSError, json.JSONDecodeError, KeyError):
        return False


def _write_cache_meta(cache_dir: str, dyld_cache_path: str) -> None:
    """Write metadata about the extraction for cache validation."""
    meta_path = os.path.join(cache_dir, _META_FILE)
    meta = {
        "dyld_cache_path": dyld_cache_path,
        "dyld_cache_mtime": os.path.getmtime(dyld_cache_path),
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f)


def _extract_all_dylibs(dyld_cache_path: str, extraction_dir: str) -> bool:
    """Extract all dylibs from the dyld shared cache using Apple's native extractor.

    Returns True on success, False on failure.
    """
    lib = _load_dsc_extractor()
    if lib is None:
        return False

    func = lib.dyld_shared_cache_extract_dylibs_progress
    func.restype = ctypes.c_int
    # Progress callback is an ObjC block; passing None skips progress reporting
    func.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p]

    cache_bytes = dyld_cache_path.encode("utf-8")
    output_bytes = extraction_dir.encode("utf-8")

    result = func(cache_bytes, output_bytes, None)
    return result == 0


def _find_extracted_dylib(extraction_dir: str, library_path: str) -> str | None:
    """Find the extracted dylib in the cache directory.

    The dsc_extractor preserves the full path structure, so
    /usr/lib/libboringssl.dylib becomes <extraction_dir>/usr/lib/libboringssl.dylib.
    """
    # Strip leading slash to make it relative
    relative_path = library_path.lstrip("/")
    candidate = os.path.join(extraction_dir, relative_path)
    if os.path.isfile(candidate):
        return candidate
    return None


class NativeDscExtractor(Extractor):
    """Extract system libraries from the macOS dyld shared cache using Apple's native dsc_extractor.

    Uses /usr/lib/dsc_extractor.bundle which supports all dyld cache formats
    on the current OS version. Extractions are cached in ~/.cache/tlslibhunter/dsc/
    and reused until the dyld cache changes (e.g., after an OS update).
    """

    @property
    def method_name(self) -> str:
        return "dsc_native"

    def can_extract(self, library: DetectedLibrary, platform: str) -> bool:
        if platform not in ("macos",):
            return False

        if not library.path or not any(library.path.startswith(p) for p in _SYSTEM_PREFIXES):
            return False

        # Only for libraries not on disk (i.e., in the dyld cache)
        if os.path.isfile(library.path):
            return False

        if _load_dsc_extractor() is None:
            return False

        return _find_dyld_cache() is not None

    def extract(
        self,
        library: DetectedLibrary,
        output_path: str,
        backend: Any = None,
        session: Any = None,
    ) -> ExtractionResult:
        try:
            return self._do_extract(library, output_path)
        except PermissionError:
            msg = "Permission denied reading dyld cache (try with sudo)"
            logger.warning(msg)
            return ExtractionResult(library=library, success=False, method=self.method_name, error=msg)
        except Exception as e:
            msg = f"Native dsc extraction failed: {e}"
            logger.warning(msg)
            return ExtractionResult(library=library, success=False, method=self.method_name, error=msg)

    def _do_extract(self, library: DetectedLibrary, output_path: str) -> ExtractionResult:
        dyld_cache_path = _find_dyld_cache()
        if not dyld_cache_path:
            return ExtractionResult(
                library=library,
                success=False,
                method=self.method_name,
                error="Could not locate dyld shared cache file",
            )

        cache_dir = _get_cache_dir()

        # Ensure extraction cache exists and is valid
        os.makedirs(cache_dir, exist_ok=True)

        if not _is_cache_valid(cache_dir, dyld_cache_path):
            logger.info("Extracting dyld shared cache (first run or cache updated). This may take 1-3 minutes...")
            # Clear stale cache
            for entry in os.listdir(cache_dir):
                entry_path = os.path.join(cache_dir, entry)
                if entry == _META_FILE:
                    continue
                if os.path.isdir(entry_path):
                    shutil.rmtree(entry_path)
                else:
                    os.remove(entry_path)

            if not _extract_all_dylibs(dyld_cache_path, cache_dir):
                return ExtractionResult(
                    library=library,
                    success=False,
                    method=self.method_name,
                    error="dsc_extractor returned non-zero exit code",
                )
            _write_cache_meta(cache_dir, dyld_cache_path)
            logger.info("Dyld shared cache extraction complete.")

        # Find the target dylib in the extraction cache
        extracted_path = _find_extracted_dylib(cache_dir, library.path)
        if not extracted_path:
            return ExtractionResult(
                library=library,
                success=False,
                method=self.method_name,
                error=f"Library '{library.path}' not found in extracted cache",
            )

        # Copy to output
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        shutil.copy2(extracted_path, output_path)

        size = os.path.getsize(output_path)
        logger.info(
            "Native dsc extract: %s -> %s (%d bytes)",
            library.name,
            output_path,
            size,
        )
        return ExtractionResult(
            library=library,
            success=True,
            output_path=output_path,
            method=self.method_name,
            size_bytes=size,
        )
