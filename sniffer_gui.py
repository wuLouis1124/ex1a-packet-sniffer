"""实验 1A 图形界面。显示筛选只控制表格中的行，采集记录仍可切换查看。"""

from contextlib import ExitStack
from datetime import datetime
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QFontDatabase, QTextCursor
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QGroupBox, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
    QPlainTextEdit, QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QTextEdit, QVBoxLayout, QWidget,
)

from npcap_api import CaptureSession, RawPacket, list_adapters
from packet_filter import FILTERS, matches_filter, parse_endpoint_filter
from packet_parser import PacketInfo, format_endpoint, parse_packet


PACKET_LIMIT = 100


def hex_dump(data: bytes) -> str:
    """左侧为字节偏移，右侧每行最多 16 个字节。"""
    return "\n".join(
        f"{offset:04x}   {data[offset:offset + 16].hex(' ')}"
        for offset in range(0, len(data), 16)
    )


class FieldList(QListWidget):
    def toPlainText(self) -> str:
        """获取当前包的字段文本，保持与原详情视图相同的读取方式。"""
        return "\n".join(self.item(index).text() for index in range(self.count()))


class SnifferWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("网络嗅探器 · 实验 1A")
        self.resize(1100, 720)
        self.records: list[tuple[RawPacket, PacketInfo]] = []
        self.resources = ExitStack()
        self.capture = None
        self.timer = QTimer(self)
        self.timer.setInterval(35)
        self.timer.timeout.connect(self.read_available)

        self.adapters = QComboBox()
        self.start_button = QPushButton("开始抓包")
        self.stop_button = QPushButton("停止")
        self.stop_button.setEnabled(False)
        self.filter_box = QComboBox()
        self.filter_box.addItems(FILTERS)
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("源或目的 IP")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("源或目的端口")
        self.endpoint_filter = parse_endpoint_filter("", "")
        self.filter_error = QLabel()
        self.filter_error.setWordWrap(True)
        self.filter_error.hide()
        self.count_label = QLabel()
        self.status = QLabel("请选择网卡。")
        self.status.setWordWrap(True)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("网卡"))
        controls.addWidget(self.adapters, 1)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        filters = QHBoxLayout()
        filters.addWidget(QLabel("显示协议"))
        filters.addWidget(self.filter_box)
        filters.addWidget(QLabel("IP"))
        filters.addWidget(self.ip_input, 2)
        filters.addWidget(QLabel("端口"))
        filters.addWidget(self.port_input, 1)
        filters.addWidget(QLabel("同时填写 IP 和端口时，匹配同一端。"))

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["编号", "时间", "源", "目的", "协议", "字节数", "信息"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().hide()
        header = self.table.horizontalHeader()
        for column, width in enumerate((46, 105, 180, 180, 145, 65)):
            header.resizeSection(column, width)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        self.details = FieldList()
        self.raw_text = QPlainTextEdit()
        self.raw_text.setReadOnly(True)
        self.raw_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.raw_text.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        details_area = QSplitter(Qt.Orientation.Horizontal)
        for title, viewer in (("协议字段（选择字段可定位字节）", self.details),
                              ("原始字节（十六进制）", self.raw_text)):
            group = QGroupBox(title)
            QVBoxLayout(group).addWidget(viewer)
            details_area.addWidget(group)
        details_area.setSizes([540, 490])
        panes = QSplitter(Qt.Orientation.Vertical)
        panes.addWidget(self.table)
        panes.addWidget(details_area)
        panes.setSizes([360, 250])

        footer = QHBoxLayout()
        footer.addWidget(self.status, 1)
        footer.addWidget(self.count_label)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.addLayout(controls)
        layout.addLayout(filters)
        layout.addWidget(self.filter_error)
        layout.addWidget(QLabel(f"每次最多抓取 {PACKET_LIMIT} 个包。重新开始会替换当前列表。"))
        layout.addWidget(panes, 1)
        layout.addLayout(footer)
        self.setCentralWidget(body)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(lambda: self.stop_capture("已停止。"))
        self.filter_box.currentTextChanged.connect(self.apply_filter)
        self.ip_input.textChanged.connect(self.apply_filter)
        self.port_input.textChanged.connect(self.apply_filter)
        self.table.itemSelectionChanged.connect(self.show_details)
        self.details.itemSelectionChanged.connect(self.highlight_field)
        self.update_count()
        self.load_adapters()

    def load_adapters(self):
        try:
            devices = list_adapters()
        except (OSError, RuntimeError) as error:
            self.status.setText(str(error))
            self.start_button.setEnabled(False)
            return
        for adapter in devices:
            self.adapters.addItem(f"{adapter.description or adapter.name}（{adapter.connection_status}）", adapter.name)
        for index, adapter in enumerate(devices):
            if adapter.flags & 0x08 and adapter.connection_status == "已连接":
                self.adapters.setCurrentIndex(index)
                break
        if not devices:
            self.status.setText("未找到可用网卡，请检查 Npcap 后重新打开。")
            self.start_button.setEnabled(False)

    def start_capture(self):
        if self.capture is not None or self.adapters.currentIndex() < 0:
            return
        try:
            self.capture = self.resources.enter_context(CaptureSession(self.adapters.currentData()))
        except (OSError, RuntimeError) as error:
            self.status.setText(str(error))
            return
        self.records.clear()
        self.table.setRowCount(0)
        self.show_details()
        self.update_count()
        self.adapters.setEnabled(False)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status.setText(f"正在抓包（{self.capture.link_name}）  {self.capture.warning}".strip())
        self.timer.start()

    def stop_capture(self, reason):
        self.timer.stop()
        self.resources.close()
        self.capture = None
        self.adapters.setEnabled(True)
        self.start_button.setEnabled(self.adapters.count() > 0)
        self.stop_button.setEnabled(False)
        self.status.setText(reason)

    def read_available(self):
        if self.capture is None:
            return
        # 每轮最多处理 12 个包，然后把控制权交回 Qt，让停止按钮保持响应。
        try:
            for _ in range(12):
                packet = self.capture.read_packet()
                if packet is None:
                    break
                info = parse_packet(packet.data, packet.link_type)
                self.add_record(packet, info)
                if len(self.records) >= PACKET_LIMIT:
                    self.stop_capture(f"已收到 {PACKET_LIMIT} 个包，抓包已停止。")
                    break
        except Exception as error:
            self.stop_capture(f"抓包已停止。{error}")

    def add_record(self, packet, info):
        row = len(self.records)
        self.records.append((packet, info))
        self.table.insertRow(row)
        clock = datetime.fromtimestamp(packet.timestamp).strftime("%H:%M:%S.%f")[:-3]
        source = format_endpoint(info.source, info.source_port)
        destination = format_endpoint(info.destination, info.destination_port)
        values = (str(row + 1), clock, source, destination, info.protocol,
                  str(packet.original_length), info.summary or " / ".join(info.notes))
        for column, value in enumerate(values):
            cell = QTableWidgetItem(value)
            cell.setToolTip(value)
            self.table.setItem(row, column, cell)
        visible = self.record_visible(info)
        self.table.setRowHidden(row, not visible)
        if visible and not self.table.selectedItems():
            self.table.selectRow(row)
        self.update_count()

    def record_visible(self, info):
        return self.endpoint_filter is not None and matches_filter(
            info, self.filter_box.currentText(), self.endpoint_filter,
        )

    def apply_filter(self):
        try:
            self.endpoint_filter = parse_endpoint_filter(self.ip_input.text(), self.port_input.text())
            self.filter_error.clear()
        except ValueError as error:
            self.endpoint_filter = None
            self.filter_error.setText(str(error))
        self.filter_error.setVisible(self.endpoint_filter is None)
        first_visible = -1
        for row, (_, info) in enumerate(self.records):
            visible = self.record_visible(info)
            self.table.setRowHidden(row, not visible)
            if visible and first_visible == -1:
                first_visible = row
        current = self.table.currentRow()
        if first_visible == -1:
            self.table.clearSelection()
            self.show_details()
        elif not self.table.selectedItems() or current < 0 or self.table.isRowHidden(current):
            self.table.selectRow(first_visible)
        self.update_count()

    def update_count(self):
        visible = sum(not self.table.isRowHidden(row) for row in range(self.table.rowCount()))
        self.count_label.setText(f"显示 {visible} / 已抓取 {len(self.records)}")

    def show_details(self):
        self.raw_text.setExtraSelections([])
        self.details.clear()
        row = self.table.currentRow()
        if row < 0 or row >= len(self.records) or self.table.isRowHidden(row) or not self.table.selectedItems():
            self.raw_text.clear()
            return
        packet, info = self.records[row]
        fields = [
            ("链路层", info.link_protocol), ("协议", info.protocol),
            ("原始长度", f"{packet.original_length} 字节"), ("捕获长度", f"{len(packet.data)} 字节"),
        ]
        if info.source or info.destination:
            fields.extend([("源地址", info.source), ("目的地址", info.destination)])
        if info.source_port is not None:
            fields.append(("源端口", str(info.source_port)))
        if info.destination_port is not None:
            fields.append(("目的端口", str(info.destination_port)))
        fields.extend(info.details)
        fields.extend(("提示", note) for note in info.notes)
        self.raw_text.setPlainText(hex_dump(packet.data))
        for name, value in fields:
            item = QListWidgetItem(f"{name}  {value}")
            item.setToolTip(item.text())
            if name in info.field_ranges:
                item.setData(Qt.ItemDataRole.UserRole, info.field_ranges[name])
            self.details.addItem(item)

    def highlight_field(self):
        items = self.details.selectedItems()
        span = items[0].data(Qt.ItemDataRole.UserRole) if items else None
        if not span:
            self.raw_text.setExtraSelections([])
            return
        start, length = span
        end = start + length
        row = self.table.currentRow()
        if row < 0 or row >= len(self.records) or not 0 <= start < end <= len(self.records[row][0].data):
            self.raw_text.setExtraSelections([])
            return

        document = self.raw_text.document()
        palette = self.raw_text.palette()
        selections = []
        # 每行分别选两个十六进制字符及其间空格，跳过下一行的地址栏。
        for offset in range(start // 16 * 16, end, 16):
            block = document.findBlockByNumber(offset // 16)
            first_hex = block.position() + len(f"{offset:04x}   ")
            first = first_hex + 3 * (max(start, offset) - offset)
            last = first_hex + 3 * (min(end, offset + 16) - offset) - 1
            cursor = QTextCursor(document)
            cursor.setPosition(first)
            cursor.setPosition(last, QTextCursor.MoveMode.KeepAnchor)
            selection = QTextEdit.ExtraSelection()
            selection.cursor = cursor
            selection.format.setBackground(palette.highlight())
            selection.format.setForeground(palette.highlightedText())
            selections.append(selection)
        self.raw_text.setExtraSelections(selections)
        cursor = QTextCursor(document)
        cursor.setPosition(selections[0].cursor.selectionStart())
        self.raw_text.setTextCursor(cursor)
        self.raw_text.ensureCursorVisible()

    def closeEvent(self, event):
        self.stop_capture("已停止。")
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    font = QFont(app.font())
    font.setFamilies(["Inter", "Microsoft YaHei UI", font.family()])
    app.setFont(font)
    window = SnifferWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
