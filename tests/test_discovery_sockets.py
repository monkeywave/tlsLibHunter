"""Tests for /proc/net and /proc/<pid>/fd socket parsers.

Fixtures follow the real kernel format (addresses in host little-endian order).
"""

import pytest

from tlslibhunter.discovery import sockets
from tlslibhunter.discovery.sockets import SocketEntry

PROC_NET_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0F02000A:A1B2 4EB9FA8E:01BB 01 00000000:00000000 02:0000A1B2 00000000 10156        0 223344 2 0000000000000000 20 4 30 10 -1
   2: 0F02000A:A1B3 4EB9FA8E:01BB 06 00000000:00000000 03:00001770 00000000     0        0 0 3 0000000000000000
   3: 0F02000A:A1B4 08080808:0355 01 00000000:00000000 02:0000A1B2 00000000 10156        0 223345 2 0000000000000000 20 4 30 10 -1
   4: 0F02000A:A1B5 08080808:01BB 06 00000000:00000000 03:00001770 00000000 10156        0 223346 3 0000000000000000
"""  # noqa: E501 (verbatim kernel format)

PROC_NET_UDP6 = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  120: 0000000000000000FFFF00000F02000A:9C40 0000000000000000FFFF00004EB9FA8E:01BB 01 00000000:00000000 00:00000000 00000000 10156        0 556677 2 0000000000000000 0
  121: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 10156        0 556678 2 0000000000000000 0
  122: B80D012000000000000000000000000:0000 garbage
  123: 00000000000000000000000000000000:0044 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 0 2 0000000000000000 0
"""  # noqa: E501 (verbatim kernel format)

PROC_NET_TCP6_NATIVE = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: B80D0120000000000000000002000000:C350 B80D0120000000000000000001000000:01BB 01 00000000:00000000 00:00000000 00000000 10301        0 778899 1 0000000000000000 20 4 30 10 -1
"""  # noqa: E501 (verbatim kernel format)

FD_LISTING = """\
PID 568
total 0
lr-x------ 1 u0_a156 u0_a156 64 2026-11-25 10:00 0 -> /dev/null
lrwx------ 1 u0_a156 u0_a156 64 2026-11-25 10:00 37 -> socket:[223344]
lrwx------ 1 u0_a156 u0_a156 64 2026-11-25 10:00 38 -> socket:[556677]
lrwx------ 1 u0_a156 u0_a156 64 2026-11-25 10:00 39 -> socket:[556677]
PID 26820
lrwx------ 1 u0_a156 u0_a156 64 2026-11-25 10:00 51 -> socket:[556677]
lrwx------ 1 u0_a156 u0_a156 64 2026-11-25 10:00 52 -> anon_inode:[eventpoll]
PID 9999
"""


def tcp_entries():
    return sockets.parse_proc_net(PROC_NET_TCP, "tcp")


def udp6_entries():
    return sockets.parse_proc_net(PROC_NET_UDP6, "udp6")


class TestDecodeAddress:
    def test_ipv4_little_endian(self):
        assert sockets.decode_address("0100007F") == "127.0.0.1"

    def test_ipv4_mapped_ipv6_rendered_dotted(self):
        assert sockets.decode_address("0000000000000000FFFF00004EB9FA8E") == "142.250.185.78"

    def test_native_ipv6(self):
        assert sockets.decode_address("B80D0120000000000000000001000000") == "2001:db8::1"

    def test_invalid_length_raises(self):
        with pytest.raises(ValueError):
            sockets.decode_address("ABC")


class TestParseProcNet:
    def test_parses_tcp_row(self):
        assert tcp_entries()[1] == SocketEntry("tcp", "10.0.2.15", 41394, "142.250.185.78", 443, "01", 10156, 223344)

    def test_skips_header_time_wait_and_inode_zero(self):
        assert [entry.inode for entry in tcp_entries()] == [12345, 223344, 223345]

    def test_udp6_v4_mapped_to_443(self):
        entry = udp6_entries()[0]
        assert (entry.local_addr, entry.local_port) == ("10.0.2.15", 40000)
        assert (entry.remote_addr, entry.remote_port) == ("142.250.185.78", 443)
        assert entry.transport == "udp"

    def test_udp6_skips_malformed_and_inode_zero(self):
        assert [entry.inode for entry in udp6_entries()] == [556677, 556678]

    def test_udp_state_06_is_not_treated_as_time_wait(self):
        text = "  0: 0100007F:0035 00000000:0000 06 00000000:00000000 00:00000000 00000000 0 0 4242 2 0 0\n"
        assert [entry.inode for entry in sockets.parse_proc_net(text, "udp")] == [4242]

    def test_native_tcp6(self):
        entry = sockets.parse_proc_net(PROC_NET_TCP6_NATIVE, "tcp6")[0]
        assert (entry.local_addr, entry.remote_addr, entry.remote_port) == ("2001:db8::2", "2001:db8::1", 443)

    def test_empty_text(self):
        assert sockets.parse_proc_net("", "tcp") == []


class TestPortAndUdpPredicates:
    def test_remote_tls_port_defaults(self):
        listening, https, dot = tcp_entries()
        assert not sockets.is_remote_tls_port(listening)
        assert sockets.is_remote_tls_port(https)
        assert sockets.is_remote_tls_port(dot)

    def test_remote_tls_port_custom_ports(self):
        assert not sockets.is_remote_tls_port(tcp_entries()[2], ports=(443,))

    def test_connected_udp(self):
        connected, unconnected = udp6_entries()
        assert sockets.is_connected_udp(connected)
        assert not sockets.is_connected_udp(unconnected)

    def test_tcp_is_never_connected_udp(self):
        assert not sockets.is_connected_udp(tcp_entries()[1])


class TestSocketEvidence:
    def test_tcp(self):
        assert sockets.socket_evidence(tcp_entries()[1]) == "net:tcp:443"

    def test_udp_connected(self):
        assert sockets.socket_evidence(udp6_entries()[0]) == "net:udp-connected:443"

    def test_udp_unconnected(self):
        assert sockets.socket_evidence(udp6_entries()[1]) == "net:udp-unconnected"


class TestBuildFdScanScript:
    def test_for_loop_over_pids(self):
        script = sockets.build_fd_scan_script([568, 26820])
        assert script == 'for p in 568 26820; do echo "PID $p"; ls -l /proc/$p/fd 2>/dev/null; done'

    def test_rejects_non_integer_pid(self):
        with pytest.raises(ValueError):
            sockets.build_fd_scan_script(["568; reboot"])


class TestParseFdSocketListing:
    def test_maps_inodes_to_pids(self):
        assert sockets.parse_fd_socket_listing(FD_LISTING) == {223344: [568], 556677: [568, 26820]}

    def test_socket_lines_before_any_pid_are_ignored(self):
        text = "lrwx------ 1 u0 u0 64 2026-11-25 10:00 3 -> socket:[1]\nPID 7\n"
        assert sockets.parse_fd_socket_listing(text) == {}

    def test_pid_line_with_trailing_process_name(self):
        text = "PID 568 com.google.android.googlequicksearchbox:search\nlrwx------ 1 r r 64 d 3 -> socket:[42]\n"
        assert sockets.parse_fd_socket_listing(text) == {42: [568]}

    def test_pid_prefixed_word_is_not_a_pid_line(self):
        text = "PID 7\nPIDX 9\nlrwx------ 1 r r 64 d 3 -> socket:[5]\n"
        assert sockets.parse_fd_socket_listing(text) == {5: [7]}


class TestOwnersByPid:
    def test_groups_entries_by_owning_pids(self):
        inode_map = sockets.parse_fd_socket_listing(FD_LISTING)
        by_pid = sockets.owners_by_pid(tcp_entries() + udp6_entries(), inode_map)
        assert [entry.inode for entry in by_pid[568]] == [223344, 556677]
        assert [entry.inode for entry in by_pid[26820]] == [556677]
        assert set(by_pid) == {568, 26820}
