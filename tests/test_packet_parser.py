"""用已知协议字段构造离线样本，验证地址、端口与异常数据边界。

这些测试不依赖 Npcap，不访问网络，也不读取真实抓包文件。
"""

import ipaddress
import struct
import unittest

from packet_parser import parse_packet


def ethernet(payload, ethertype=0x0800):
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ethertype) + payload


def ipv4(payload, protocol=17, *, options=b"", fragment=0, total_length=None):
    header_size = 20 + len(options)
    total_length = header_size + len(payload) if total_length is None else total_length
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | (header_size // 4), 0, total_length, 0x1234, fragment,
        64, protocol, 0,
        ipaddress.IPv4Address("192.0.2.10").packed,
        ipaddress.IPv4Address("198.51.100.20").packed,
    )
    return header + options + payload


def ipv6(payload, next_header=17):
    return struct.pack(
        "!IHBB16s16s", 6 << 28, len(payload), next_header, 64,
        ipaddress.IPv6Address("2001:db8::10").packed,
        ipaddress.IPv6Address("2001:db8::20").packed,
    ) + payload


def udp(payload=b"example", *, length=None):
    length = 8 + len(payload) if length is None else length
    return struct.pack("!HHHH", 40000, 5353, length, 0) + payload


def tcp(*, options=b"", header_words=None):
    words = (20 + len(options)) // 4 if header_words is None else header_words
    return struct.pack("!HHIIBBHHH", 49152, 443, 12345, 23456, words << 4, 0x18, 4096, 0, 0) + options


class PacketParserTests(unittest.TestCase):
    def test_mdns_fields_and_ranges_in_ipv4_vlan_query_and_ipv6_response(self):
        question = b"\x03lab\x05local\x00" + struct.pack("!HH", 1, 1)
        # 响应中的资源记录复用问题里的 lab.local 名称。
        answer = b"\xc0\x0c" + struct.pack("!HHIH4s", 1, 1, 60, 4, bytes([192, 0, 2, 1]))
        for version, flags, answer_count in ((4, 0, 0), (6, 0x8400, 1)):
            dns = struct.pack("!6H", 0, flags, 1, answer_count, 0, 0) + question
            if answer_count:
                dns += answer
            segment = struct.pack("!4H", 5353, 5353, 8 + len(dns), 0) + dns
            if version == 4:
                ip = bytearray(ipv4(segment))
                ip[16:20] = ipaddress.ip_address("224.0.0.251").packed
                frame = ethernet(struct.pack("!HH", 123, 0x0800) + ip, 0x8100)
                dns_start = 18 + 20 + 8
            else:
                ip = bytearray(ipv6(segment))
                ip[24:40] = ipaddress.ip_address("ff02::fb").packed
                frame = ethernet(ip, 0x86DD)
                dns_start = 14 + 40 + 8
            parsed = parse_packet(frame, 1)
            self.assertEqual(parsed.protocol, f"IPv{version} / UDP / mDNS")
            fields = dict(parsed.details)
            self.assertEqual(fields["mDNS 消息类型"], "响应" if answer_count else "查询")
            self.assertEqual(fields["mDNS 问题数"], "1")
            self.assertEqual(fields["mDNS 回答数"], str(answer_count))
            for label, relative, expected in (
                ("mDNS 消息类型", 2, bytes([flags >> 8])),
                ("mDNS 问题数", 4, b"\x00\x01"),
                ("mDNS 回答数", 6, answer_count.to_bytes(2, "big")),
            ):
                offset, size = parsed.field_ranges[label]
                self.assertEqual(offset, dns_start + relative)
                self.assertEqual(frame[offset:offset + size], expected)

    def test_mdns_respects_fragment_capture_and_udp_length_boundaries(self):
        dns = struct.pack("!6H", 0, 0, 1, 0, 0, 0) + b"\x00\x00\x01\x00\x01"
        for fragment, cut, udp_length in ((0x2000, 0, 8 + len(dns)),
                                          (0, 1, 8 + len(dns)), (0, 0, 8)):
            segment = struct.pack("!4H", 5353, 5353, udp_length, 0) + dns
            ip = bytearray(ipv4(segment, fragment=fragment))
            ip[16:20] = ipaddress.ip_address("224.0.0.251").packed
            parsed = parse_packet(bytes(ip[:len(ip) - cut]), 228)
            self.assertEqual(parsed.protocol, "IPv4 / UDP")
            self.assertNotIn("mDNS 消息类型", parsed.field_ranges)

    def assert_endpoints(self, parsed, version, transport, source, destination, ports):
        self.assertEqual(parsed.network_protocol, version)
        self.assertEqual(parsed.transport_protocol, transport)
        self.assertEqual(parsed.source, source)
        self.assertEqual(parsed.destination, destination)
        self.assertEqual((parsed.source_port, parsed.destination_port), ports)

    def test_ethernet_ipv4_udp_fields_are_network_byte_order(self):
        parsed = parse_packet(ethernet(ipv4(udp())), 1)
        self.assert_endpoints(
            parsed, "IPv4", "UDP", "192.0.2.10", "198.51.100.20", (40000, 5353)
        )
        self.assertFalse(parsed.notes)

    def test_ipv4_and_tcp_options_change_header_offsets(self):
        segment = tcp(options=b"\x01\x01\x01\x01") + b"payload"
        parsed = parse_packet(ethernet(ipv4(segment, 6, options=b"\x01\x01\x01\x01")), 1)
        self.assert_endpoints(
            parsed, "IPv4", "TCP", "192.0.2.10", "198.51.100.20", (49152, 443)
        )
        self.assertFalse(parsed.notes)

    def test_direct_ipv6_transport_headers(self):
        for protocol, name, segment, ports in (
            (17, "UDP", udp(), (40000, 5353)),
            (6, "TCP", tcp(), (49152, 443)),
        ):
            with self.subTest(transport=name):
                parsed = parse_packet(ethernet(ipv6(segment, protocol), 0x86DD), 1)
                self.assert_endpoints(
                    parsed, "IPv6", name, "2001:db8::10", "2001:db8::20", ports
                )
                self.assertFalse(parsed.notes)

    def test_icmp_has_no_tcp_or_udp_ports(self):
        for frame, network, transport in (
            (ethernet(ipv4(bytes.fromhex("0800000012340001"), 1)), "IPv4", "ICMP"),
            (ethernet(ipv6(bytes.fromhex("8000000012340001"), 58), 0x86DD), "IPv6", "ICMPv6"),
        ):
            with self.subTest(transport=transport):
                parsed = parse_packet(frame, 1)
                self.assertEqual(parsed.network_protocol, network)
                self.assertEqual(parsed.transport_protocol, transport)
                self.assertIsNone(parsed.source_port)
                self.assertIsNone(parsed.destination_port)
                self.assertFalse(parsed.notes)

    def test_vlan_tag_does_not_shift_ip_fields_incorrectly(self):
        frame = ethernet(struct.pack("!HH", 42, 0x0800) + ipv4(udp()), 0x8100)
        parsed = parse_packet(frame, 1)
        self.assert_endpoints(
            parsed, "IPv4", "UDP", "192.0.2.10", "198.51.100.20", (40000, 5353)
        )
        self.assertFalse(parsed.notes)

    def test_short_icmp_echo_header_is_reported(self):
        for frame in (
            ethernet(ipv4(bytes.fromhex("08000000"), 1)),
            ethernet(ipv6(bytes.fromhex("80000000"), 58), 0x86DD),
        ):
            with self.subTest(frame=frame.hex()):
                parsed = parse_packet(frame, 1)
                self.assertTrue(parsed.notes)
                self.assertIsNone(parsed.source_port)
                self.assertIsNone(parsed.destination_port)

    def test_npcap_loopback_family_values(self):
        # DLT_NULL 的 IPv6 值是 24，不能误用 Windows sockaddr 的 AF_INET6=23。
        for family, body, network in ((2, ipv4(udp()), "IPv4"), (24, ipv6(udp()), "IPv6")):
            with self.subTest(family=family):
                parsed = parse_packet(struct.pack("<I", family) + body, 0)
                self.assertEqual(parsed.network_protocol, network)
                self.assertEqual(parsed.transport_protocol, "UDP")
                self.assertEqual((parsed.source_port, parsed.destination_port), (40000, 5353))
                self.assertFalse(parsed.notes)
        unknown = parse_packet(struct.pack("<I", 23) + ipv6(udp()), 0)
        self.assertNotEqual(unknown.network_protocol, "IPv6")
        self.assertTrue(unknown.notes)

    def test_raw_and_explicit_ip_link_types(self):
        for link_type, body, network in (
            (12, ipv4(udp()), "IPv4"), (12, ipv6(udp()), "IPv6"),
            (228, ipv4(udp()), "IPv4"), (229, ipv6(udp()), "IPv6"),
        ):
            with self.subTest(link_type=link_type, network=network):
                parsed = parse_packet(body, link_type)
                self.assertEqual(parsed.network_protocol, network)
                self.assertEqual(parsed.transport_protocol, "UDP")
                self.assertEqual((parsed.source_port, parsed.destination_port), (40000, 5353))
                self.assertFalse(parsed.notes)

    def test_ethernet_padding_is_not_a_transport_header(self):
        # IP 总长只有 20 字节，后面的字节属于帧尾填充，不能读出伪造的端口。
        frame = ethernet(ipv4(b"", 6) + tcp())
        parsed = parse_packet(frame, 1)
        self.assertIsNone(parsed.source_port)
        self.assertIsNone(parsed.destination_port)
        self.assertTrue(parsed.notes)

    def test_noninitial_fragment_is_not_read_as_ports(self):
        frame = ethernet(ipv4(udp(), 17, fragment=1))
        parsed = parse_packet(frame, 1)
        self.assertEqual(parsed.network_protocol, "IPv4")
        self.assertIsNone(parsed.source_port)
        self.assertIsNone(parsed.destination_port)
        self.assertTrue(parsed.notes)

    def test_first_udp_fragment_can_contain_header_of_larger_datagram(self):
        # 首片只含 UDP 头和 8 字节数据，UDP 总长包含后续分片的数据。
        frame = ethernet(ipv4(udp(b"12345678", length=40), 17, fragment=0x2000))
        parsed = parse_packet(frame, 1)
        self.assertEqual(parsed.transport_protocol, "UDP")
        self.assertEqual((parsed.source_port, parsed.destination_port), (40000, 5353))
        self.assertTrue(parsed.notes)

    def test_ipv6_extension_header_is_explicitly_left_unparsed(self):
        extension = bytes([17, 0]) + b"\x00" * 6
        parsed = parse_packet(ethernet(ipv6(extension + udp(), 0), 0x86DD), 1)
        self.assertEqual(parsed.network_protocol, "IPv6")
        self.assertIsNone(parsed.source_port)
        self.assertIsNone(parsed.destination_port)
        self.assertTrue(parsed.notes)

    def test_invalid_ipv4_ihl_and_total_length_are_reported(self):
        invalid_ihl = bytearray(ipv4(udp()))
        invalid_ihl[0] = 0x44
        for body in (bytes(invalid_ihl), ipv4(udp(), total_length=19)):
            with self.subTest(body=body.hex()):
                parsed = parse_packet(ethernet(body), 1)
                self.assertTrue(parsed.notes)

    def test_invalid_tcp_header_lengths_are_reported(self):
        for words in (4, 15):
            with self.subTest(header_words=words):
                parsed = parse_packet(ethernet(ipv4(tcp(header_words=words), 6)), 1)
                self.assertTrue(parsed.notes)

    def test_invalid_unfragmented_udp_lengths_are_reported(self):
        for length in (0, 7, 100):
            with self.subTest(udp_length=length):
                parsed = parse_packet(ethernet(ipv4(udp(length=length))), 1)
                self.assertTrue(parsed.notes)

    def test_declared_ip_version_must_match_the_actual_header(self):
        for link_type, data in ((1, ethernet(ipv6(udp()), 0x0800)), (228, ipv6(udp()))):
            with self.subTest(link_type=link_type):
                parsed = parse_packet(data, link_type)
                self.assertTrue(parsed.notes)
                self.assertIsNone(parsed.source_port)
                self.assertIsNone(parsed.destination_port)

    def test_unknown_link_and_ethernet_types_are_reported(self):
        for data, link_type in ((ipv4(udp()), 9999), (ethernet(b"unknown", 0x88B5), 1)):
            with self.subTest(link_type=link_type):
                parsed = parse_packet(data, link_type)
                self.assertTrue(parsed.notes)
                self.assertIsNone(parsed.source_port)
                self.assertIsNone(parsed.destination_port)

    def test_every_short_prefix_returns_a_result_instead_of_raising(self):
        frames = (
            (ethernet(ipv4(udp())), 1),
            (ethernet(ipv4(tcp(), 6, options=b"\x01\x01\x01\x01")), 1),
            (ethernet(ipv6(udp()), 0x86DD), 1),
            (struct.pack("<I", 24) + ipv6(tcp(), 6), 0),
            (ethernet(struct.pack("!HH", 42, 0x0800) + ipv4(udp()), 0x8100), 1),
        )
        for frame_index, (frame, link_type) in enumerate(frames):
            for end in range(len(frame)):
                with self.subTest(frame=frame_index, prefix_length=end):
                    parsed = parse_packet(frame[:end], link_type)
                    self.assertTrue(parsed.notes, "截断样本应带有提示")


if __name__ == "__main__":
    unittest.main()
