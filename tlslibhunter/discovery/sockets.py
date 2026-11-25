"""Pure parsers for Android socket state (``/proc/net/*`` and ``/proc/<pid>/fd``).

``/proc/net/{tcp,tcp6,udp,udp6}`` lists every socket with its owning UID and
inode, but not the owning PID. The PID comes from ``ls -l /proc/<pid>/fd``,
whose ``socket:[<inode>]`` links map inodes back to processes. Nothing here
talks to the device; :func:`build_fd_scan_script` only builds the shell script
(run it via ``su -c``).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass

DEFAULT_TLS_PORTS = (443, 853)

_TCP_TIME_WAIT = "06"
_IPV4_HEX_LEN = 8
_IPV6_HEX_LEN = 32
_IPV6_WORD_HEX_LEN = 8
# Columns after splitting a /proc/net row on whitespace.
_COL_LOCAL, _COL_REMOTE, _COL_STATE, _COL_UID, _COL_INODE = 1, 2, 3, 7, 9

# A trailing process name ("PID 568 com.app:proc") is tolerated.
_PID_LINE_RE = re.compile(r"^PID (\d+)(?:\s.*)?$")
_SOCKET_LINK_RE = re.compile(r"socket:\[(\d+)\]")


@dataclass(frozen=True)
class SocketEntry:
    """One socket row of ``/proc/net/{tcp,tcp6,udp,udp6}``."""

    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    uid: int
    inode: int

    @property
    def transport(self) -> str:
        """``tcp`` or ``udp`` (drops the ``6`` of ``tcp6``/``udp6``)."""
        return self.protocol.rstrip("6")


def _little_endian_word_bytes(hex_word: str) -> bytes:
    """Bytes of a 32-bit word the kernel printed in host (little-endian) order."""
    return bytes.fromhex(hex_word)[::-1]


def _decode_ipv6(hex_addr: str) -> str:
    words = [hex_addr[i : i + _IPV6_WORD_HEX_LEN] for i in range(0, _IPV6_HEX_LEN, _IPV6_WORD_HEX_LEN)]
    address = ipaddress.IPv6Address(b"".join(_little_endian_word_bytes(word) for word in words))
    mapped = address.ipv4_mapped
    return str(mapped) if mapped else str(address)


def decode_address(hex_addr: str) -> str:
    """Decode a /proc/net hex address; IPv4-mapped IPv6 is rendered as dotted IPv4."""
    if len(hex_addr) == _IPV4_HEX_LEN:
        return str(ipaddress.IPv4Address(_little_endian_word_bytes(hex_addr)))
    if len(hex_addr) == _IPV6_HEX_LEN:
        return _decode_ipv6(hex_addr)
    raise ValueError(f"unexpected address length: {hex_addr!r}")


def _decode_endpoint(field: str) -> tuple[str, int]:
    hex_addr, hex_port = field.split(":")
    return decode_address(hex_addr), int(hex_port, 16)


def _parse_row(line: str, protocol: str) -> SocketEntry | None:
    columns = line.split()
    if len(columns) <= _COL_INODE or not columns[0].endswith(":"):
        return None
    try:
        local_addr, local_port = _decode_endpoint(columns[_COL_LOCAL])
        remote_addr, remote_port = _decode_endpoint(columns[_COL_REMOTE])
        uid, inode = int(columns[_COL_UID]), int(columns[_COL_INODE])
    except ValueError:
        return None
    return SocketEntry(protocol, local_addr, local_port, remote_addr, remote_port, columns[_COL_STATE], uid, inode)


def _is_live(entry: SocketEntry) -> bool:
    """False for inode-0 sockets (TIME_WAIT/orphans) and TCP TIME_WAIT rows."""
    if entry.inode == 0:
        return False
    return not (entry.transport == "tcp" and entry.state == _TCP_TIME_WAIT)


def parse_proc_net(text: str, protocol: str) -> list[SocketEntry]:
    """Parse ``/proc/net/<protocol>`` text; header, malformed and dead rows are skipped."""
    entries = (_parse_row(line, protocol) for line in text.splitlines())
    return [entry for entry in entries if entry is not None and _is_live(entry)]


def is_remote_tls_port(entry: SocketEntry, ports: Iterable[int] = DEFAULT_TLS_PORTS) -> bool:
    """True if the socket talks to a TLS/QUIC/DoT port (443, 853 by default)."""
    return entry.remote_port in tuple(ports)


def is_connected_udp(entry: SocketEntry) -> bool:
    """True for a UDP socket bound to a remote peer (``connect()``-ed, e.g. QUIC)."""
    return entry.transport == "udp" and entry.remote_port != 0


def socket_evidence(entry: SocketEntry) -> str:
    """Short evidence tag, e.g. ``net:tcp:443``, ``net:udp-connected:443``, ``net:udp-unconnected``."""
    if entry.transport == "tcp":
        return f"net:tcp:{entry.remote_port}"
    if is_connected_udp(entry):
        return f"net:udp-connected:{entry.remote_port}"
    return "net:udp-unconnected"


def build_fd_scan_script(pids: Iterable[int]) -> str:
    """One-shot (mksh compatible) script listing each PID's fds after a ``PID <pid>`` line.

    PIDs are coerced to int to prevent shell injection.
    """
    pid_list = " ".join(str(int(pid)) for pid in pids)
    return f'for p in {pid_list}; do echo "PID $p"; ls -l /proc/$p/fd 2>/dev/null; done'


def _add_owner(inode_map: dict[int, list[int]], inode: int, pid: int) -> None:
    owners = inode_map.setdefault(inode, [])
    if pid not in owners:
        owners.append(pid)


def parse_fd_socket_listing(text: str) -> dict[int, list[int]]:
    """Map socket inode -> PIDs holding it, from :func:`build_fd_scan_script` output."""
    inode_map: dict[int, list[int]] = {}
    current_pid: int | None = None
    for line in text.splitlines():
        pid_match = _PID_LINE_RE.match(line.strip())
        if pid_match:
            current_pid = int(pid_match.group(1))
            continue
        socket_match = _SOCKET_LINK_RE.search(line)
        if socket_match and current_pid is not None:
            _add_owner(inode_map, int(socket_match.group(1)), current_pid)
    return inode_map


def owners_by_pid(entries: Iterable[SocketEntry], inode_map: dict[int, list[int]]) -> dict[int, list[SocketEntry]]:
    """Group socket entries by every PID that holds their inode; unowned entries are dropped."""
    by_pid: dict[int, list[SocketEntry]] = {}
    for entry in entries:
        for pid in inode_map.get(entry.inode, []):
            by_pid.setdefault(pid, []).append(entry)
    return by_pid
