"""通过窗口的开始、停止和筛选按钮核对一次本机 HTTP 交换。"""

import os
import socket
import time
import unittest

from PySide6.QtCore import QEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from sniffer_gui import SnifferWindow


@unittest.skipUnless(os.name == "nt", "需要 Windows Npcap 回环接口")
class GuiCaptureTests(unittest.TestCase):
    def test_loopback_http_in_table_details_and_filters(self):
        # 离屏窗口也走和双击启动相同的 Qt 事件与抓包代码。
        self.app = QApplication.instance() or QApplication(["test", "-platform", "offscreen"])
        window = SnifferWindow()
        def dispose_window():
            window.close()
            window.deleteLater()
            self.app.sendPostedEvents(None, QEvent.Type.DeferredDelete)

        self.addCleanup(dispose_window)
        window.show()
        index = window.adapters.findData(r"\Device\NPF_Loopback")
        self.assertGreaterEqual(index, 0, window.status.text())
        window.adapters.setCurrentIndex(index)
        window.start_button.click()
        self.assertTrue(window.timer.isActive(), window.status.text())

        request = b"GET /demo HTTP/1.1\r\nHost: localhost\r\n\r\n"
        response = b"HTTP/1.1 204 No Content\r\n\r\n"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(2)
            port = listener.getsockname()[1]
            window.capture.limit_to_local_tcp_port(port)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(2)
                    client.sendall(request)
                    with peer.makefile("rb") as stream:
                        self.assertEqual(stream.read(len(request)), request)
                    peer.sendall(response)
                    with client.makefile("rb") as stream:
                        self.assertEqual(stream.read(len(response)), response)

        def http_rows():
            return [row for row, (_, info) in enumerate(window.records)
                    if info.application_protocol == "HTTP"
                    and port in (info.source_port, info.destination_port)]

        deadline = time.monotonic() + 4
        while len(http_rows()) < 2 and time.monotonic() < deadline:
            QTest.qWait(40)
        window.stop_button.click()
        self.assertFalse(window.timer.isActive())
        rows = http_rows()
        self.assertGreaterEqual(len(rows), 2, window.status.text())
        total = len(window.records)
        for choice, visible in [("HTTP", True), ("UDP", False), ("TCP", True), ("全部", True)]:
            window.filter_box.setCurrentText(choice)
            for row in rows:
                self.assertEqual(not window.table.isRowHidden(row), visible, choice)
            self.assertEqual(len(window.records), total)
        summaries = set()
        for row in rows:
            window.table.selectRow(row)
            raw, info = window.records[row]
            summaries.add(info.summary)
            self.assertIn(str(port), window.details.toPlainText())
            self.assertIn(raw.data[:4].hex(" "), window.raw_text.toPlainText())
        self.assertTrue(any("GET" in summary for summary in summaries), summaries)
        self.assertTrue(any("204" in summary for summary in summaries), summaries)
