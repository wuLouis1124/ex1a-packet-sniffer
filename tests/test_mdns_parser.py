"""使用合成 UDP 载荷验证 mDNS 报头识别。"""

import struct
import unittest

from mdns_parser import MdnsHeader, parse_mdns


NAME = b"\x06sample\x05local\x00"
QUESTION = NAME + struct.pack("!HH", 1, 1)
ANSWER = NAME + struct.pack("!HHIH4s", 1, 1, 120, 4, bytes((192, 0, 2, 10)))
IPV4 = ("192.0.2.10", "224.0.0.251")
IPV6 = ("fe80::10", "ff02::fb")


class MdnsParserTests(unittest.TestCase):
    def test_multicast_query_accepts_legacy_and_standard_source_ports(self):
        for endpoints in (IPV4, IPV6):
            for source_port, identifier in ((5353, 0), (49152, 0x1234)):
                with self.subTest(endpoints=endpoints, source_port=source_port):
                    payload = struct.pack("!6H", identifier, 0, 1, 0, 0, 0) + QUESTION
                    self.assertEqual(parse_mdns(payload, *endpoints, source_port, 5353),
                                     MdnsHeader(False, 1, 0))

    def test_multicast_response_uses_qr_bit_and_answer_count(self):
        payload = struct.pack("!6H", 0, 0x8400, 0, 1, 0, 0) + ANSWER
        for endpoints in (IPV4, IPV6):
            with self.subTest(endpoints=endpoints):
                self.assertEqual(parse_mdns(payload, *endpoints, 5353, 5353),
                                 MdnsHeader(True, 0, 1))
                self.assertIsNone(parse_mdns(payload, *endpoints, 49152, 5353))

    def test_known_answer_continuation_is_still_a_query(self):
        payload = struct.pack("!6H", 0, 0, 0, 1, 0, 0) + ANSWER
        self.assertEqual(parse_mdns(payload, *IPV4, 5353, 5353), MdnsHeader(False, 0, 1))

    def test_unrelated_addresses_and_ports_are_skipped(self):
        payload = struct.pack("!6H", 0, 0, 1, 0, 0, 0) + QUESTION
        for endpoints in (
            (*IPV4, 5353, 53),
            (*IPV4, 0, 5353),
            ("192.0.2.10", "192.0.2.1", 5353, 5353),
            ("fe80::10", "ff02::1", 5353, 5353),
            ("fe80::10", "224.0.0.251", 5353, 5353),
            ("224.0.0.251", "224.0.0.251", 5353, 5353),
        ):
            with self.subTest(endpoints=endpoints):
                self.assertIsNone(parse_mdns(payload, *endpoints))

    def test_short_empty_or_inconsistent_payloads_are_skipped(self):
        for size in range(12):
            with self.subTest(header_size=size):
                self.assertIsNone(parse_mdns(bytes(size), *IPV4, 5353, 5353))
        for payload in (
            bytes(12),
            b"an unrelated application message",
            struct.pack("!6H", 0, 0, 1, 0, 0, 0) + bytes(4),
            struct.pack("!6H", 0, 0, 0, 0, 1, 1) + bytes(21),
            struct.pack("!6H", 0, 0x8400, 0, 65535, 0, 0) + ANSWER,
            struct.pack("!6H", 0, 0x8400, 1, 0, 0, 0) + QUESTION,
        ):
            with self.subTest(payload=payload):
                self.assertIsNone(parse_mdns(payload, *IPV4, 5353, 5353))

    def test_nonstandard_opcode_and_nonzero_rcode_are_skipped(self):
        for flags in (1 << 11, 3):
            with self.subTest(flags=flags):
                payload = struct.pack("!6H", 0, flags, 1, 0, 0, 0) + QUESTION
                self.assertIsNone(parse_mdns(payload, *IPV4, 5353, 5353))


if __name__ == "__main__":
    unittest.main()
