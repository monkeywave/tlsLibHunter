"""``discover --probe``: learn delegates from the binder interfaces an app calls.

``dumpsys activity oom`` only shows bindings that raise a process's priority,
so it misses many hand-offs. The probe attaches a small Frida agent
(``probe_agent.js``, built from ``agent/probe``) to the running target that
reports each binder interface descriptor the app transacts with
(``BinderProxy.transact``) and its outgoing TLS sockets. Descriptors are mapped
to the serving package with the data-driven prefixes in
``binder_descriptors.json``; generic system interfaces are ignored.

Descriptors come from the target process and are untrusted: they are escaped
and capped before they reach evidence strings or the profile.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from tlslibhunter.discovery.text import MAX_MESSAGE_LENGTH, MAX_TEXT_LENGTH, cap, escape_char, escape_matches, safe_text
from tlslibhunter.discovery.topology import validate_package_name

logger = logging.getLogger("tlslibhunter.discovery.probe")

PROBE_AGENT_FILE = Path(__file__).with_name("probe_agent.js")
DESCRIPTOR_MAP_FILE = Path(__file__).with_name("binder_descriptors.json")

EVIDENCE_BINDER = "handoff:binder:"
MAX_EVIDENCE_LENGTH = MAX_TEXT_LENGTH
LAUNCH_WAIT_SECONDS = 3.0

MESSAGE_BINDER = "binder"
MESSAGE_NET = "net"

_UNSAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._$/-]")


@dataclass
class ProbeResult:
    """What the probe saw: binder interface descriptors and the number of TLS socket events."""

    descriptors: set[str] = field(default_factory=set)
    net_events: int = 0


@dataclass(frozen=True)
class DescriptorMap:
    """Descriptor prefix -> serving package (None: known hand-off, package varies) plus ignored prefixes."""

    packages: Mapping[str, str | None]
    ignore: tuple[str, ...]


# --------------------------------------------------------------------------- descriptor mapping


@lru_cache(maxsize=1)
def load_descriptor_map() -> DescriptorMap:
    """The prefix map shipped in ``binder_descriptors.json``."""
    data = json.loads(DESCRIPTOR_MAP_FILE.read_text(encoding="utf-8"))
    return DescriptorMap(packages=dict(data["packages"]), ignore=tuple(data["ignore"]))


def longest_prefix(descriptor: str, prefixes: Iterable[str]) -> str | None:
    """The longest of ``prefixes`` that ``descriptor`` starts with, or None."""
    matches = [prefix for prefix in prefixes if descriptor.startswith(prefix)]
    return max(matches, key=len) if matches else None


def descriptor_to_package(descriptor: str, known_map: Mapping[str, str | None] | None = None) -> str | None:
    """Package serving ``descriptor`` per the prefix map (default: the shipped one), or None."""
    packages = load_descriptor_map().packages if known_map is None else known_map
    prefix = longest_prefix(descriptor, packages)
    return packages[prefix] if prefix is not None else None


def is_known_descriptor(descriptor: str, descriptor_map: DescriptorMap | None = None) -> bool:
    """True if ``descriptor`` matches a prefix of the map (with or without a package)."""
    packages = (descriptor_map or load_descriptor_map()).packages
    return longest_prefix(descriptor, packages) is not None


def is_ignored_descriptor(descriptor: str, descriptor_map: DescriptorMap | None = None) -> bool:
    """True for generic system interfaces (unless the map names the descriptor explicitly)."""
    descriptor_map = descriptor_map or load_descriptor_map()
    if is_known_descriptor(descriptor, descriptor_map):
        return False
    return longest_prefix(descriptor, descriptor_map.ignore) is not None


# --------------------------------------------------------------------------- evidence


def escape_descriptor(descriptor: str) -> str:
    """``descriptor`` with every character outside ``[A-Za-z0-9._$/-]`` as ``\\xNN`` (``\\uNNNN``)."""
    return escape_matches(descriptor, _UNSAFE_CHARS_RE)


def _escape_char(match: re.Match) -> str:
    """Kept for compatibility; see :func:`~tlslibhunter.discovery.text.escape_char`."""
    return escape_char(match.group(0))


def binder_evidence(descriptor: str) -> str:
    """``handoff:binder:<descriptor>``, escaped and capped at :data:`MAX_EVIDENCE_LENGTH`."""
    return cap(EVIDENCE_BINDER + escape_descriptor(descriptor))


def probe_package_evidence(result: ProbeResult, descriptor_map: DescriptorMap | None = None) -> dict[str, list[str]]:
    """Package -> sorted ``handoff:binder:`` evidence, for descriptors that map to a package."""
    packages = (descriptor_map or load_descriptor_map()).packages
    evidence: dict[str, list[str]] = {}
    for descriptor in sorted(result.descriptors):
        package = descriptor_to_package(descriptor, packages)
        if package:
            evidence.setdefault(package, []).append(binder_evidence(descriptor))
    return evidence


def unmapped_descriptors(result: ProbeResult, descriptor_map: DescriptorMap | None = None) -> list[str]:
    """Escaped, capped, sorted descriptors that are neither ignored nor mapped to a package."""
    descriptor_map = descriptor_map or load_descriptor_map()
    return sorted(
        cap(escape_descriptor(descriptor))
        for descriptor in result.descriptors
        if not is_ignored_descriptor(descriptor, descriptor_map)
        and not descriptor_to_package(descriptor, descriptor_map.packages)
    )


# --------------------------------------------------------------------------- agent messages


def record_message(result: ProbeResult, message: dict[str, Any]) -> None:
    """Fold one Frida script message into ``result``; anything unexpected is logged and dropped."""
    if message.get("type") != "send":
        logger.debug("probe agent: %s", safe_text(message.get("description") or message, MAX_MESSAGE_LENGTH))
        return
    payload = message.get("payload")
    if not isinstance(payload, dict):
        return
    kind = payload.get("type")
    if kind == MESSAGE_BINDER and isinstance(payload.get("descriptor"), str):
        result.descriptors.add(payload["descriptor"])
    elif kind == MESSAGE_NET:
        result.net_events += 1
    else:
        logger.debug("probe agent: %s", safe_text(payload, MAX_MESSAGE_LENGTH))


def load_probe_agent() -> str:
    """Source of the bundled probe agent (``probe_agent.js``)."""
    return PROBE_AGENT_FILE.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- Frida session


def running_pid(device: Any, package: str) -> int | None:
    """PID of ``package``'s main process per Frida's application list, or None."""
    apps = device.enumerate_applications(identifiers=[package])
    pids = [app.pid for app in apps if app.identifier == package and app.pid]
    return pids[0] if pids else None


def running_or_launched_pid(device: Any, package: str, launch: Callable[[], None] | None = None) -> int:
    """PID of the running ``package``; if it is not running, ``launch()`` it and look again."""
    pid = running_pid(device, package)
    if pid is None and launch:
        launch()
        pid = running_pid(device, package)
    if pid is None:
        raise RuntimeError(f"'{package}' is not running (its launcher may hand off to another app's process)")
    return pid


def _open_session(device: Any, target: str, spawn: bool, launch: Callable | None, before_attach: Callable | None):
    """Attach to (or spawn) ``target``; returns ``(session, pid_to_resume_or_None)``."""
    if spawn:
        pid = device.spawn([target])
        return device.attach(pid), pid
    pid = running_or_launched_pid(device, target, launch)
    if before_attach:
        before_attach(pid)
    return device.attach(pid), None


def _detach_quietly(session: Any) -> None:
    try:
        session.detach()
    except Exception as e:  # already gone: nothing to clean up
        logger.debug("probe detach: %s", e)


def _resume_quietly(device: Any, pid: int) -> None:
    """Resume a spawned process; a spawned target must never stay suspended."""
    try:
        device.resume(pid)
    except Exception as e:
        logger.debug("probe resume of PID %d: %s", pid, e)


def _load_agent(session: Any, result: ProbeResult) -> None:
    script = session.create_script(load_probe_agent())
    script.on("message", lambda message, data: record_message(result, message))
    script.load()


def run_probe(
    device: Any,
    target: str,
    duration: float,
    spawn: bool = False,
    *,
    launch: Callable[[], None] | None = None,
    before_attach: Callable[[int], None] | None = None,
    sleep: Callable = time.sleep,
) -> ProbeResult:
    """Run the probe agent in ``target`` for ``duration`` seconds and return what it saw.

    Attaches to the running target (``launch()`` starts it if it is not running;
    ``before_attach(pid)`` runs first, e.g. to thaw it) or, with ``spawn``,
    spawns it and resumes it right after the agent loaded.
    """
    result = ProbeResult()
    session, spawned_pid = _open_session(device, target, spawn, launch, before_attach)
    try:
        try:
            _load_agent(session, result)
        finally:
            if spawned_pid is not None:
                _resume_quietly(device, spawned_pid)
        sleep(duration)
    finally:
        _detach_quietly(session)
    return result


# --------------------------------------------------------------------------- launching (adb runner)


def launch_command(package: str) -> str:
    """``monkey`` launch of ``package``'s launcher activity; raises ValueError on a shell-unsafe name."""
    return f"monkey -p {shlex.quote(validate_package_name(package))} 1"


def launch_app(runner: Callable[[str], str], package: str, sleep: Callable = time.sleep) -> None:
    """Launch ``package`` via ``monkey`` (through the adb runner) and give it time to start."""
    runner(launch_command(package))
    sleep(LAUNCH_WAIT_SECONDS)
