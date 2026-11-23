r"""使用本机 UDP 流量验证抓包，不访问外部服务器。

运行：.venv\Scripts\python.exe -m unittest discover -s tests -v
需要 Windows、已安装的 Npcap，以及访问抓包驱动的权限。
"""

import os
import socket
import time
import unittest
import uuid

from npcap_api import CaptureSession, list_adapters
from packet_parser import parse_packet


@unittest.skipUnless(os.name == "nt", "本项目当前使用 Windows Npcap")
class CaptureIntegrationTests(unittest.TestCase):
    def test_local_udp_bytes_and_close(self):
        self._check_local_udp(socket.AF_INET, "127.0.0.1", "IPv4")

    def test_local_ipv6_udp_fields(self):
        self._check_local_udp(socket.AF_INET6, "::1", "IPv6")

    def _check_local_udp(self, family, host, network_protocol):
        adapter = next(item for item in list_adapters() if item.is_loopback)
        payload = b"sniffer1a-test\x00" + uuid.uuid4().bytes
        found = None
        with socket.socket(family, socket.SOCK_DGRAM) as receiver:
            receiver.bind((host, 0))
            receiver.settimeout(2)
            with CaptureSession(adapter.name) as capture:
                with socket.socket(family, socket.SOCK_DGRAM) as sender:
                    sender.bind((host, 0))
                    source_port = sender.getsockname()[1]
                    sender.sendto(payload, receiver.getsockname())
                self.assertEqual(receiver.recv(1024), payload)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    packet = capture.read_packet()
                    if packet is not None and packet.data.endswith(payload):
                        found = packet
                        break
                    time.sleep(0.01)
                self.assertIsNotNone(found, "未抓到已确认在本机收到的 UDP 数据")
                self.assertEqual(found.original_length, len(found.data))
                self.assertLess(abs(found.timestamp - time.time()), 5)
                self.assertEqual(found.link_type, capture.link_type)
                parsed = parse_packet(found.data, found.link_type)
                self.assertEqual(parsed.network_protocol, network_protocol)
                self.assertEqual(parsed.transport_protocol, "UDP")
                self.assertEqual(parsed.source, host)
                self.assertEqual(parsed.destination, host)
                self.assertEqual(parsed.source_port, source_port)
                self.assertEqual(parsed.destination_port, receiver.getsockname()[1])
                self.assertEqual(parsed.notes, [])

        # 句柄关闭后，已返回的数据仍可用；再次读取应给出清楚的错误。
        self.assertIsInstance(found.data, bytes)
        self.assertTrue(found.data.endswith(payload))
        with self.assertRaisesRegex(RuntimeError, "关闭"):
            capture.read_packet()
        capture.close()  # 重复关闭不应触发底层重复释放。

    def test_invalid_interface_reports_error(self):
        with self.assertRaisesRegex(RuntimeError, "打开网卡失败"):
            with CaptureSession(r"\Device\NPF_{00000000-0000-0000-0000-000000000000}"):
                self.fail("无效接口不应成功打开")


if __name__ == "__main__":
    unittest.main()
