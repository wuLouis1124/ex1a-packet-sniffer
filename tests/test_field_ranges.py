"""用已知报文验证 GUI 可高亮字段的帧内绝对位置。"""

import struct
import unittest

from packet_parser import parse_packet
from tests.test_packet_parser import ethernet, ipv4, ipv6, tcp, udp


class FieldRangeTests(unittest.TestCase):
    def test_double_vlan_and_variable_ipv4_tcp_headers(self):
        options = bytes.fromhex("01 01 01 00")
        request = b"GET /GET/HTTP/1.1 HTTP/1.1\r\n"
        segment = tcp(options=options) + request
        tags = bytes.fromhex("00 15 81 00 00 2a 08 00")
        frame = ethernet(tags + ipv4(segment, 6, options=options), 0x88A8)
        info = parse_packet(frame, 1)
        self.assertEqual(info.field_ranges, {
            "目的 MAC": (0, 6), "源 MAC": (6, 6), "VLAN 1 ID": (14, 2),
            "VLAN 2 ID": (18, 2), "以太网类型": (20, 2),
            "IPv4 头部长度": (22, 1), "IPv4 总长度": (24, 2), "TTL": (30, 1),
            "IPv4 协议号": (31, 1), "源地址": (34, 4), "目的地址": (38, 4),
            "源端口": (46, 2), "目的端口": (48, 2), "TCP 序号": (50, 4),
            "TCP 确认号": (54, 4), "TCP 头部长度": (58, 1), "TCP 标志": (59, 1),
            "TCP 窗口": (60, 2), "请求方法": (70, 3), "HTTP 版本": (88, 8),
        })
        self.assertEqual(frame[88:96], b"HTTP/1.1")

    def test_ipv6_loopback_and_raw_udp(self):
        body = ipv6(udp(b""))
        for link_type, prefix in ((0, struct.pack("<I", 24)), (12, b""), (229, b"")):
            with self.subTest(link_type=link_type):
                info = parse_packet(prefix + body, link_type)
                offset = len(prefix)
                self.assertEqual(info.field_ranges, {
                    "IPv6 载荷长度": (offset + 4, 2), "IPv6 下一头部": (offset + 6, 1),
                    "Hop Limit": (offset + 7, 1), "源地址": (offset + 8, 16),
                    "目的地址": (offset + 24, 16), "源端口": (offset + 40, 2),
                    "目的端口": (offset + 42, 2), "UDP 声明长度": (offset + 44, 2),
                })

    def test_echo_fields_in_icmp_and_icmpv6(self):
        echo = bytes.fromhex("00 00 12 34 ab cd 01 02")
        for body, name, start in ((ipv4(echo, 1), "ICMP", 20),
                                  (ipv6(b"\x81" + echo[1:], 58), "ICMPv6", 40)):
            with self.subTest(name=name):
                ranges = parse_packet(body, 12).field_ranges
                self.assertEqual(ranges[name + " 类型"], (start, 1))
                self.assertEqual(ranges[name + " 代码"], (start + 1, 1))
                self.assertEqual(ranges["回显标识符"], (start + 4, 2))
                self.assertEqual(ranges["回显序号"], (start + 6, 2))
                self.assertNotIn("源端口", ranges)

    def test_http_response_and_truncated_fields(self):
        frame = ethernet(ipv4(tcp() + b"HTTP/1.1 204 No Content\r\n", 6))
        ranges = parse_packet(frame, 1).field_ranges
        self.assertEqual(ranges["HTTP 版本"], (54, 8))
        self.assertEqual(ranges["响应状态码"], (63, 3))
        for size in range(len(frame)):
            with self.subTest(size=size):
                ranges = parse_packet(frame[:size], 1).field_ranges
                self.assertNotIn("响应状态码", ranges)
                if size < 54:
                    self.assertNotIn("源端口", ranges)
                for offset, length in ranges.values():
                    self.assertGreaterEqual(offset, 0)
                    self.assertGreater(length, 0)
                    self.assertLessEqual(offset + length, size)
