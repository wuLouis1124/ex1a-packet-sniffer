"""显示筛选和 HTTP 起始行的离线验收样本。"""

import struct
import unittest

from packet_filter import FILTERS, matches_filter, parse_endpoint_filter
from packet_parser import PacketInfo, parse_packet


def parse_tcp(payload, *, port=48123, fragment=0):
    # 直接构造 IPv4 报文。TCP 带 4 字节选项，应用数据从第 24 字节之后开始。
    tcp = struct.pack("!HHIIBBHHH", 49152, port, 1, 0, 0x60, 0x18, 4096, 0, 0)
    segment = tcp + b"\x01" * 4 + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 1, fragment,
                     64, 6, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    return parse_packet(ip + segment, 228)


class PacketFilterTests(unittest.TestCase):
    def test_endpoint_filter_includes_both_directions_and_requires_same_peer(self):
        local = ("10.207.93.201", 54286)
        peer = ("192.0.2.1", 60040)
        for source, destination in ((local, peer), (peer, local)):
            packet = PacketInfo(network_protocol="IPv4", transport_protocol="UDP",
                                source=source[0], source_port=source[1],
                                destination=destination[0], destination_port=destination[1])
            for ip, port in ((local[0], ""), ("", "60040"), (local[0], "54286"), ("", "")):
                self.assertTrue(matches_filter(packet, "UDP", parse_endpoint_filter(ip, port)))
            self.assertFalse(matches_filter(packet, "全部", parse_endpoint_filter(local[0], "60040")))
            self.assertFalse(matches_filter(packet, "TCP", parse_endpoint_filter(local[0], "")))

    def test_ipv6_text_and_port_boundaries(self):
        packet = PacketInfo(network_protocol="IPv6", source="fe80::1", source_port=0)
        scoped = parse_endpoint_filter(" FE80:0:0:0:0:0:0:1%12 ", "0000")
        self.assertTrue(matches_filter(packet, "全部", scoped))
        self.assertEqual(parse_endpoint_filter("", "65535").port, 65535)
        for ip, port in (("10.2", ""), ("ff02::xx", ""), ("", "65536"), ("", "-1"),
                         ("", "1.2"), ("", "５３"), ("", "1" * 10000)):
            with self.subTest(ip=ip, port=port[:16]), self.assertRaises(ValueError):
                parse_endpoint_filter(ip, port)

    def test_http_on_nonstandard_port_matches_three_protocol_layers(self):
        info = parse_tcp(b"GET /demo?example=value HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertEqual(info.protocol, "IPv4 / TCP / HTTP")
        self.assertEqual({f for f in FILTERS if matches_filter(info, f)},
                         {"全部", "IPv4", "TCP", "HTTP"})
        self.assertIn("GET", info.summary)
        self.assertNotIn("example=value", str(info.details) + info.summary)

    def test_recognizes_response_and_common_request_forms(self):
        for line, value in (
            (b"HTTP/1.1 200 OK\r\n", "200"),
            (b"HTTP/1.0 204 \r\n", "204"),
            (b"OPTIONS * HTTP/1.1\r\n", "OPTIONS"),
            (b"CONNECT [::1]:443 HTTP/1.1\r\n", "CONNECT"),
            (b"GET http://localhost:8080/demo HTTP/1.1\r\n", "GET"),
        ):
            with self.subTest(line=line):
                parsed = parse_tcp(line)
                self.assertEqual(parsed.application_protocol, "HTTP")
                self.assertIn(value, parsed.summary)

    def test_ordinary_port_does_not_override_message_framing(self):
        for data in (
            b"GET / HTTP/1.1", b"GET / HTTP/1.1\n", b"GET / HTTP/2.0\r\n",
            b"GET * HTTP/1.1\r\n", b"GET /a b HTTP/1.1\r\n",
            b"GET /test%zz HTTP/1.1\r\n", b"GET /test#anchor HTTP/1.1\r\n",
            b"HTTP/1.1 999 Nope\r\n", b"HTTP/1.1 20 OK\r\n",
            b"TCP data\r\nGET / HTTP/1.1\r\n",
            b"\x16\x03\x03\x00\x08GET / HTTP/1.1\r\n",
            b"GET /" + b"x" * 8192 + b" HTTP/1.1\r\n",
        ):
            with self.subTest(data=data[:30]):
                info = parse_tcp(data, port=80)
                self.assertEqual(info.application_protocol, "")
                self.assertTrue(matches_filter(info, "TCP"))
                self.assertFalse(matches_filter(info, "HTTP"))
        first_fragment = parse_tcp(b"GET / HTTP/1.1\r\n", fragment=0x2000)
        self.assertFalse(matches_filter(first_fragment, "HTTP"))

    def test_ipv6_udp_and_icmp_exact_matching(self):
        for transport in ("UDP", "ICMPv6"):
            info = PacketInfo(network_protocol="IPv6", transport_protocol=transport)
            self.assertEqual({f for f in FILTERS if matches_filter(info, f)},
                             {"全部", "IPv6", transport})
        self.assertFalse(matches_filter(PacketInfo(), ""))
        self.assertTrue(matches_filter(PacketInfo(), "全部"))


if __name__ == "__main__":
    unittest.main()
