"""Cheap, Frida-free TLS-library confirmation from ``/proc/<pid>/maps`` (root only).

Socket evidence only *marks* a candidate; a mapped TLS library *confirms* it.
For each candidate PID the executable (``r-xp``) file mappings are matched
against the scanner's known TLS library names
(:func:`tlslibhunter.scanner.tls_indicators.is_known_tls_library`) plus the
Android embedded stacks below, and recorded as ``tls_lib:<label>`` evidence.

Confirmation rule (:func:`is_tls_confirmed`):

* Zygote preloads Conscrypt (``/apex/com.android.conscrypt/.../libssl.so``)
  and HttpEngine (``/apex/com.android.tethering/.../libhttpengine.so``) into
  *every* app process (verified on a Pixel 5, Android 14), so such a library
  is labelled ``<apex>/<basename>`` (``conscrypt/libssl.so``,
  ``tethering/libhttpengine.so``) and is *weak*: it confirms a candidate only
  together with a TLS socket (``net:`` evidence) of that process.
* Any other TLS library (``libcronet*.so``, ``libwebviewchromium.so``,
  ``libflutter.so``, an app-bundled ``libssl.so`` ...) is *strong* and
  confirms the candidate on its own.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable

from tlslibhunter.discovery.text import safe_text
from tlslibhunter.scanner.tls_indicators import _extract_stem, is_known_tls_library

EVIDENCE_TLS_LIB = "tls_lib:"
EVIDENCE_NET = "net:"

# Android TLS stacks the generic scanner list does not name by stem.
ANDROID_TLS_STACK_STEMS: frozenset[str] = frozenset(
    {
        "libhttpengine",  # HttpEngine (Cronet in the tethering APEX)
        "stable_cronet_libssl",  # Play-services Cronet's BoringSSL
        "libwebviewchromium",  # WebView (Chromium, BoringSSL)
        "libmonochrome",
        "libmonochrome_64",
        "libchrome",
        "libflutter",  # Flutter engine (BoringSSL)
    }
)

# Libraries under these prefixes are mapped into every app by zygote.
ZYGOTE_PRELOADED_PREFIXES: dict[str, str] = {
    "/apex/com.android.conscrypt/": "conscrypt",
    "/apex/com.android.tethering/": "tethering",
}

_PID_LINE_RE = re.compile(r"^PID (\d+)$")
_MAPS_PERMS_INDEX = 1
_MAPS_PATH_INDEX = 5


def build_maps_scan_script(pids: Iterable[int]) -> str:
    """One-shot (mksh compatible) script printing each PID's executable mappings after ``PID <pid>``.

    PIDs are coerced to int to prevent shell injection; no single quotes (see ``as_root``).
    """
    pid_list = " ".join(str(int(pid)) for pid in pids)
    return f'for p in {pid_list}; do echo "PID $p"; grep r-xp /proc/$p/maps 2>/dev/null; done'


def is_tls_library_name(basename: str) -> bool:
    """True if ``basename`` names a TLS library (scanner list or Android embedded stack)."""
    return is_known_tls_library(basename) or _extract_stem(basename) in ANDROID_TLS_STACK_STEMS


def tls_lib_label(path: str) -> str:
    """Evidence label for a mapped path: ``conscrypt/libssl.so`` for zygote-preloaded ones, else the basename."""
    basename = posixpath.basename(path)
    for prefix, origin in ZYGOTE_PRELOADED_PREFIXES.items():
        if path.startswith(prefix):
            return f"{origin}/{basename}"
    return basename


def _executable_path(line: str) -> str | None:
    """Mapped file path of an executable maps line, else None."""
    columns = line.split(None, _MAPS_PATH_INDEX)
    if len(columns) <= _MAPS_PATH_INDEX or "x" not in columns[_MAPS_PERMS_INDEX]:
        return None
    path = columns[_MAPS_PATH_INDEX].strip()
    return path if path.startswith("/") else None


def _tls_label_of(line: str) -> str | None:
    path = _executable_path(line)
    if path is None or not is_tls_library_name(posixpath.basename(path)):
        return None
    return tls_lib_label(path)


def parse_maps_tls_libs(text: str) -> dict[int, list[str]]:
    """Map PID -> sorted TLS library labels, from :func:`build_maps_scan_script` output."""
    libs: dict[int, set[str]] = {}
    current_pid: int | None = None
    for line in text.splitlines():
        pid_match = _PID_LINE_RE.match(line.strip())
        if pid_match:
            current_pid = int(pid_match.group(1))
            libs.setdefault(current_pid, set())
            continue
        label = _tls_label_of(line)
        if label and current_pid is not None:
            libs[current_pid].add(label)
    return {pid: sorted(labels) for pid, labels in libs.items()}


def tls_lib_evidence(labels: Iterable[str]) -> list[str]:
    """``tls_lib:<label>`` evidence; labels come from device paths, so they are escaped and capped."""
    return [safe_text(EVIDENCE_TLS_LIB + label) for label in labels]


def _is_weak_label(label: str) -> bool:
    return any(label.startswith(origin + "/") for origin in ZYGOTE_PRELOADED_PREFIXES.values())


def is_tls_confirmed(evidence: Iterable[str]) -> bool:
    """Apply the module's confirmation rule to a candidate's evidence list."""
    items = list(evidence)
    labels = [item[len(EVIDENCE_TLS_LIB) :] for item in items if item.startswith(EVIDENCE_TLS_LIB)]
    if any(not _is_weak_label(label) for label in labels):
        return True
    has_socket = any(item.startswith(EVIDENCE_NET) for item in items)
    return bool(labels) and has_socket
