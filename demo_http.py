"""用本机一次已知的 GET/200 交换，检查嗅探器的抓包、协议识别和显示筛选。"""

from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
from threading import Thread
import time

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from sniffer_gui import SnifferWindow


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"Lab 1A OK\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def send_local_http(before_request=None) -> tuple[int, int]:
    """临时使用系统分配的本机端口，收到一次请求后关闭服务器。"""
    with HTTPServer(("127.0.0.1", 0), LabHandler) as server:
        server.timeout = 2
        port = server.server_port
        if before_request is not None:
            before_request(port)
        worker = Thread(target=server.handle_request, daemon=True)
        worker.start()
        client = HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            client.request("GET", "/lab-check")
            response = client.getresponse()
            if response.read() != b"Lab 1A OK\n":
                raise RuntimeError("收到的正文与实验消息不一致")
            return port, response.status
        finally:
            client.close()
            worker.join(timeout=2)


def run_demo(window: SnifferWindow) -> None:
    index = window.adapters.findData(r"\Device\NPF_Loopback")
    if index < 0:
        window.status.setText("未找到 Npcap 回环接口，请检查 Npcap 安装。")
        return
    window.adapters.setCurrentIndex(index)
    window.filter_box.setCurrentText("HTTP")
    window.start_capture()
    if window.capture is None:
        return  # 窗口已显示具体的打开失败原因。
    try:
        port, status = send_local_http(window.capture.limit_to_local_tcp_port)
    except (OSError, RuntimeError, HTTPException) as error:
        window.stop_capture(f"本机 HTTP 测试失败。{error}")
        return
    deadline = time.monotonic() + 3
    capture = window.capture
    timer = QTimer(window)

    def check():
        if window.capture is not capture:
            timer.stop()
            return
        req = res = None
        for row, (_, info) in enumerate(window.records):
            if info.application_protocol != "HTTP":
                continue
            fields = dict(info.details)
            if info.destination_port == port and fields.get("请求方法") == "GET":
                req = row
            if info.source_port == port and fields.get("响应状态码") == str(status):
                res = row
        if req is not None and res is not None:
            timer.stop()
            window.stop_capture(f"本机验收通过。第 {req + 1} 行是 GET，第 {res + 1} 行是响应 {status}。")
            window.table.selectRow(req)
        elif time.monotonic() >= deadline:
            timer.stop()
            window.stop_capture(f"本机端口 {port} 已返回 {status}，抓包窗口未同时识别出请求和响应。")

    timer.timeout.connect(check)
    timer.start(40)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SnifferWindow()
    window.show()
    QTimer.singleShot(0, lambda: run_demo(window))
    sys.exit(app.exec())
