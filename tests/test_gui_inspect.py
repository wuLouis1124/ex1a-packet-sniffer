"""用离线构造的以太网帧检查窗口的显示筛选、字段选择和字节定位。"""

import struct
import unittest
from unittest.mock import patch

from PySide6.QtCore import QEvent, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from npcap_api import RawPacket
from packet_parser import parse_packet
from sniffer_gui import SnifferWindow


def ethernet_ipv4(payload, protocol):
    ethernet = bytes.fromhex("001122334455 66778899aabb 0800")
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, protocol, 0,
        bytes([192, 0, 2, 10]), bytes([198, 51, 100, 20]),
    )
    return ethernet + header + payload


class GuiInspectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(["test", "-platform", "offscreen"])

    def setUp(self):
        with patch("sniffer_gui.list_adapters", return_value=[]):
            self.window = SnifferWindow()
        self.addCleanup(self.close_window)
        self.window.show()
        udp = struct.pack("!HHHH", 40000, 53, 8, 0)
        self.udp_frame = ethernet_ipv4(udp, 17)
        self.add_frame(self.udp_frame)
        tcp = struct.pack("!HHIIHHHH", 40000, 80, 1, 0, 0x5018, 4096, 0, 0)
        request = b"GET /" + b"x" * 1200 + b" HTTP/1.1\r\n\r\n"
        self.http_frame = ethernet_ipv4(tcp + request, 6)
        self.add_frame(self.http_frame)
        self.app.processEvents()

    def close_window(self):
        self.window.close()
        self.window.deleteLater()
        self.app.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    def add_frame(self, frame):
        packet = RawPacket(1, len(frame), frame, 1)
        self.window.add_record(packet, parse_packet(frame, packet.link_type))

    def click_field(self, name):
        fields = self.window.details
        item, = fields.findItems(name + "  ", Qt.MatchFlag.MatchStartsWith)
        fields.scrollToItem(item)
        QTest.mouseClick(fields.viewport(), Qt.MouseButton.LeftButton,
                         pos=fields.visualItemRect(item).center())

    def highlighted(self):
        return [selection.cursor.selectedText() for selection in self.window.raw_text.extraSelections()]

    def test_mouse_and_keyboard_selection_reveal_exact_bytes(self):
        self.click_field("目的地址")
        self.assertEqual(self.highlighted(), ["c6 33", "64 14"])
        QTest.keyClick(self.window.details, Qt.Key.Key_Down)
        self.assertEqual(self.highlighted(), ["9c 40"])
        self.click_field("捕获长度")
        self.assertEqual(self.highlighted(), [])

        self.click_field("源端口")
        self.window.table.selectRow(1)
        self.assertEqual(self.highlighted(), [])
        self.click_field("HTTP 版本")
        self.assertEqual(bytes.fromhex(" ".join(self.highlighted())), b"HTTP/1.1")
        raw = self.window.raw_text
        first_selection = raw.extraSelections()[0]
        self.assertGreater(raw.verticalScrollBar().value(), 0)
        self.assertTrue(raw.viewport().rect().intersects(raw.cursorRect(first_selection.cursor)))

    def test_combined_filters_and_recovery_on_existing_and_new_rows(self):
        window = self.window
        window.ip_input.setText("192.0.2.10")
        self.assertEqual(window.count_label.text(), "显示 2 / 已抓取 2")
        window.port_input.setText("53")
        self.assertEqual(window.count_label.text(), "显示 0 / 已抓取 2")
        window.ip_input.setText("198.51.100.20")
        self.assertEqual(window.count_label.text(), "显示 1 / 已抓取 2")
        self.assertFalse(window.table.isRowHidden(0))
        window.filter_box.setCurrentText("HTTP")
        self.assertEqual(window.count_label.text(), "显示 0 / 已抓取 2")
        window.port_input.setText("80")
        self.assertFalse(window.table.isRowHidden(1))
        self.click_field("源端口")
        self.assertEqual(self.highlighted(), ["9c 40"])

        window.port_input.setText("70000")
        self.assertTrue(window.filter_error.isVisible())
        self.assertIn("端口", window.filter_error.text())
        self.assertEqual(window.details.toPlainText(), "")
        self.assertEqual(window.raw_text.toPlainText(), "")
        self.assertEqual(self.highlighted(), [])
        self.add_frame(self.http_frame)
        self.assertEqual(window.count_label.text(), "显示 0 / 已抓取 3")
        window.port_input.clear()
        self.assertFalse(window.filter_error.isVisible())
        self.assertEqual(window.count_label.text(), "显示 2 / 已抓取 3")

        window.ip_input.setText("192.0.")
        self.assertIn("IP", window.filter_error.text())
        self.assertEqual(window.count_label.text(), "显示 0 / 已抓取 3")
        window.ip_input.clear()
        window.filter_box.setCurrentText("全部")
        self.assertEqual(window.count_label.text(), "显示 3 / 已抓取 3")
        window.port_input.setText("53")
        self.add_frame(self.udp_frame)
        self.assertEqual(window.count_label.text(), "显示 2 / 已抓取 4")

    def test_mdns_query_filter_and_field_bytes(self):
        # 对 printer.local 的 A 记录查询，发往 IPv4 mDNS 组播地址。
        frame = bytes.fromhex("""
            01005e0000fb 66778899aabb 0800
            4500 003b 0000 0000 ff11 18ac c000020a e00000fb
            14e9 14e9 0027 0000
            0000 0000 0001 0000 0000 0000
            07 7072696e746572 05 6c6f63616c 00 0001 0001
        """)
        self.window.filter_box.setCurrentText("mDNS")
        self.window.ip_input.setText("224.0.0.251")
        self.window.port_input.setText("5353")
        self.add_frame(frame)
        self.assertEqual(self.window.count_label.text(), "显示 1 / 已抓取 3")
        self.assertEqual(self.window.table.currentRow(), 2)
        self.click_field("目的端口")
        self.assertEqual(self.highlighted(), ["14 e9"])
        self.click_field("mDNS 问题数")
        self.assertEqual(self.highlighted(), ["00 01"])
