"""Backend abstraction for instrumentation engines."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tlslibhunter.backends.base import Backend


def get_backend(name: str = "frida") -> Backend:
    """Get a backend instance by name.

    Args:
        name: Backend name ("frida" is currently the only option).

    Returns:
        Backend instance.

    Raises:
        ValueError: If backend name is unknown.
    """
    if name == "frida":
        from tlslibhunter.backends.frida_backend import FridaBackend

        return FridaBackend()
    raise ValueError(f"Unknown backend: {name!r}. Available: frida")
