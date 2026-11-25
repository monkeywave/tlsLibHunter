"""Escaping and capping of device-derived strings before they are printed or stored.

Process names (``android:process``), ``dumpsys`` fields, mapped library paths
and probe descriptors are controlled by the app or the device, so they may
carry control characters or ANSI/OSC escape sequences. Everything that reaches
the terminal or an evidence string goes through :func:`safe_text` (or the
stricter :func:`escape_matches` with a whitelist pattern, as for binder
descriptors).

:func:`escape_text` only touches non-printable characters, so valid package
and process names are left unchanged and :func:`safe_text` is idempotent.
"""

from __future__ import annotations

import re

MAX_TEXT_LENGTH = 120
MAX_MESSAGE_LENGTH = 300


def escape_char(char: str) -> str:
    """``char`` as ``\\xNN`` (``\\uNNNN`` / ``\\UNNNNNNNN`` above 0xff / 0xffff)."""
    code = ord(char)
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"


def escape_matches(text: str, unsafe: re.Pattern) -> str:
    """``text`` with every character matched by ``unsafe`` escaped via :func:`escape_char`."""
    return unsafe.sub(lambda match: escape_char(match.group(0)), text)


def escape_text(text: str) -> str:
    """``text`` with non-printable characters (controls, ESC, C1, bidi/format chars) escaped."""
    return "".join(char if char.isprintable() else escape_char(char) for char in text)


def cap(text: str, limit: int = MAX_TEXT_LENGTH) -> str:
    """``text`` truncated to ``limit`` characters."""
    return text[:limit]


def safe_text(text: object, limit: int = MAX_TEXT_LENGTH) -> str:
    """``str(text)`` escaped (:func:`escape_text`) and capped at ``limit`` characters."""
    return cap(escape_text(str(text)), limit)
