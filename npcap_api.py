"""Npcap 接口封装：列出网卡，以及读取原始数据包。

接口依据：https://npcap.com/guide/wpcap/pcap_findalldevs.html
"""

import ctypes as ct
from dataclasses import dataclass
import os
from pathlib import Path
import socket
import sys

PCAP_ERRBUF_SIZE = 256
PCAP_IF_LOOPBACK = 0x01
PCAP_IF_CONNECTION_STATUS = 0x30
SNAPSHOT_LENGTH = 65535


class _PcapAddress(ct.Structure):
    pass


_PcapAddress._fields_ = [
    ("next", ct.POINTER(_PcapAddress)),
    ("addr", ct.c_void_p),
    ("netmask", ct.c_void_p),
    ("broadaddr", ct.c_void_p),
    ("dstaddr", ct.c_void_p),
]


class _PcapInterface(ct.Structure):
    pass


_PcapInterface._fields_ = [
    ("next", ct.POINTER(_PcapInterface)),
    ("name", ct.c_char_p),
    ("description", ct.c_char_p),
    ("addresses", ct.POINTER(_PcapAddress)),
    ("flags", ct.c_uint),
]


class _SockaddrIPv4(ct.Structure):
    _fields_ = [
        ("family", ct.c_ushort),
        ("port", ct.c_ushort),
        ("address", ct.c_ubyte * 4),
        ("padding", ct.c_ubyte * 8),
    ]


class _SockaddrIPv6(ct.Structure):
    _fields_ = [
        ("family", ct.c_ushort),
        ("port", ct.c_ushort),
        ("flowinfo", ct.c_uint32),
        ("address", ct.c_ubyte * 16),
        ("scope_id", ct.c_uint32),
    ]


class _Timeval(ct.Structure):
    # Windows Winsock 的 timeval 使用两个 32 位 long，64 位 Python 也一样。
    _fields_ = [("seconds", ct.c_long), ("microseconds", ct.c_long)]


class _PacketHeader(ct.Structure):
    _fields_ = [
        ("timestamp", _Timeval),
        ("captured_length", ct.c_uint32),
        ("original_length", ct.c_uint32),
    ]


class _BpfProgram(ct.Structure):
    _fields_ = [("length", ct.c_uint), ("instructions", ct.c_void_p)]


@dataclass(frozen=True)
class RawPacket:
    timestamp: float
    original_length: int
    data: bytes
    link_type: int


@dataclass(frozen=True)
class Adapter:
    """拷贝到 Python 中的网卡信息，不保留 Npcap 分配的内存指针。"""

    name: str
    description: str
    addresses: tuple[str, ...]
    flags: int

    @property
    def is_loopback(self) -> bool:
        return bool(self.flags & PCAP_IF_LOOPBACK)

    @property
    def connection_status(self) -> str:
        return {
            0x00: "连接状态未知",
            0x10: "已连接",
            0x20: "未连接",
            0x30: "不适用（例如回环接口）",
        }[self.flags & PCAP_IF_CONNECTION_STATUS]


def _load_library() -> ct.CDLL:
    if sys.platform != "win32":
        raise RuntimeError("本实验当前使用 Windows + Npcap 环境。")
    system_dir = "System32" if ct.sizeof(ct.c_void_p) == 8 else "SysWOW64"
    directory = Path(os.environ.get("SystemRoot", r"C:\Windows")) / system_dir / "Npcap"
    path = directory / "wpcap.dll"
    if not path.is_file():
        raise RuntimeError("未找到 Npcap，请先安装并运行环境检查。")
    with os.add_dll_directory(str(directory)):
        library = ct.CDLL(str(path))

    # 告诉 ctypes：C 函数接收什么参数、返回什么类型。
    library.pcap_findalldevs.argtypes = [
        ct.POINTER(ct.POINTER(_PcapInterface)),
        ct.POINTER(ct.c_char),
    ]
    library.pcap_findalldevs.restype = ct.c_int
    library.pcap_freealldevs.argtypes = [ct.POINTER(_PcapInterface)]
    library.pcap_freealldevs.restype = None
    # Windows 默认使用本地代码页，显式选择 UTF-8 后才能统一解码中文描述。
    library.pcap_init.argtypes = [ct.c_uint, ct.POINTER(ct.c_char)]
    library.pcap_init.restype = ct.c_int
    error = ct.create_string_buffer(PCAP_ERRBUF_SIZE)
    if library.pcap_init(1, error) != 0:  # PCAP_CHAR_ENC_UTF_8
        message = error.value.decode("utf-8", errors="replace")
        raise RuntimeError(f"Npcap 初始化失败：{message}")
    return library


def _read_addresses(first: ct.POINTER(_PcapAddress)) -> tuple[str, ...]:
    result = []
    current = first
    while current:
        entry = current.contents
        if entry.addr:
            # 先读地址族，再决定怎样解释这段内存；不能全部当作 IPv4。
            family = ct.cast(entry.addr, ct.POINTER(ct.c_ushort)).contents.value
            if family == socket.AF_INET:
                value = ct.cast(entry.addr, ct.POINTER(_SockaddrIPv4)).contents
                result.append(socket.inet_ntop(socket.AF_INET, bytes(value.address)))
            elif family == socket.AF_INET6:
                value = ct.cast(entry.addr, ct.POINTER(_SockaddrIPv6)).contents
                address = socket.inet_ntop(socket.AF_INET6, bytes(value.address))
                if value.scope_id:
                    address += f"%{value.scope_id}"
                result.append(address)
        current = entry.next
    return tuple(result)


def list_adapters() -> list[Adapter]:
    """获取网卡信息，并在返回之前释放 Npcap 的列表内存。"""
    library = _load_library()
    first = ct.POINTER(_PcapInterface)()
    error = ct.create_string_buffer(PCAP_ERRBUF_SIZE)
    if library.pcap_findalldevs(ct.byref(first), error) != 0:
        message = error.value.decode("utf-8", errors="replace")
        raise RuntimeError(f"获取网卡列表失败：{message}")

    result = []
    try:
        current = first
        while current:
            entry = current.contents
            result.append(Adapter(
                name=(entry.name or b"").decode("utf-8", errors="replace"),
                description=(entry.description or b"").decode("utf-8", errors="replace"),
                addresses=_read_addresses(entry.addresses),
                flags=entry.flags,
            ))
            current = entry.next
    finally:
        if first:
            library.pcap_freealldevs(first)
    return result


class CaptureSession:
    """一次抓包会话。使用 with，保证正常停止或报错后都关闭句柄。"""

    def __init__(self, adapter_name: str):
        self.adapter_name = adapter_name
        self._handle = None
        self._library = _load_library()
        self.link_type = -1
        self.link_name = "未知"
        self.warning = ""
        library = self._library
        library.pcap_open_live.argtypes = [
            ct.c_char_p, ct.c_int, ct.c_int, ct.c_int, ct.POINTER(ct.c_char)
        ]
        library.pcap_open_live.restype = ct.c_void_p
        library.pcap_setnonblock.argtypes = [ct.c_void_p, ct.c_int, ct.POINTER(ct.c_char)]
        library.pcap_setnonblock.restype = ct.c_int
        library.pcap_next_ex.argtypes = [
            ct.c_void_p,
            ct.POINTER(ct.POINTER(_PacketHeader)),
            ct.POINTER(ct.POINTER(ct.c_ubyte)),
        ]
        library.pcap_next_ex.restype = ct.c_int
        library.pcap_datalink.argtypes = [ct.c_void_p]
        library.pcap_datalink.restype = ct.c_int
        library.pcap_datalink_val_to_name.argtypes = [ct.c_int]
        library.pcap_datalink_val_to_name.restype = ct.c_char_p
        library.pcap_geterr.argtypes = [ct.c_void_p]
        library.pcap_geterr.restype = ct.c_char_p
        library.pcap_close.argtypes = [ct.c_void_p]
        library.pcap_close.restype = None

    def __enter__(self):
        if self._handle:
            raise RuntimeError("这个抓包会话已经打开。")
        error = ct.create_string_buffer(PCAP_ERRBUF_SIZE)
        # promisc=0：使用普通模式；100 是底层缓冲区超时，单位为毫秒。
        self._handle = self._library.pcap_open_live(
            self.adapter_name.encode("utf-8"), SNAPSHOT_LENGTH, 0, 100, error
        )
        if not self._handle:
            raise RuntimeError(f"打开网卡失败：{error.value.decode('utf-8', errors='replace')}")
        self.warning = error.value.decode("utf-8", errors="replace")
        try:
            # 非阻塞读取：即使没有流量，外层循环也能检查时间并正常停止。
            error.value = b""
            if self._library.pcap_setnonblock(self._handle, 1, error) != 0:
                raise RuntimeError(f"设置读取模式失败：{error.value.decode('utf-8', errors='replace')}")
            self.link_type = self._library.pcap_datalink(self._handle)
            if self.link_type < 0:
                raise RuntimeError("无法获取接口的链路层格式。")
            name = self._library.pcap_datalink_val_to_name(self.link_type)
            self.link_name = name.decode("ascii", errors="replace") if name else "未知"
        except BaseException:
            self.close()
            raise
        return self

    def limit_to_local_tcp_port(self, port: int) -> None:
        """验收时，只接收这次本机测试连接，避免其他会话占满采集列表。"""
        if not self._handle or not 1 <= port <= 65535:
            raise ValueError("需要已打开的接口和有效的 TCP 端口")
        lib = self._library
        prog_ptr = ct.POINTER(_BpfProgram)
        lib.pcap_compile.argtypes = [ct.c_void_p, prog_ptr, ct.c_char_p, ct.c_int, ct.c_uint32]
        lib.pcap_compile.restype = ct.c_int
        lib.pcap_setfilter.argtypes = [ct.c_void_p, prog_ptr]
        lib.pcap_setfilter.restype = ct.c_int
        lib.pcap_freecode.argtypes = [prog_ptr]
        lib.pcap_freecode.restype = None
        expr = f"ip and src host 127.0.0.1 and dst host 127.0.0.1 and tcp port {port}".encode("ascii")
        program = _BpfProgram()
        if lib.pcap_compile(self._handle, ct.byref(program), expr, 1, 0xffffffff):
            raise RuntimeError("无法编译本机测试端口过滤条件")
        try:
            if lib.pcap_setfilter(self._handle, ct.byref(program)):
                raise RuntimeError("无法应用本机测试端口过滤条件")
        finally:
            lib.pcap_freecode(ct.byref(program))

    def read_packet(self) -> RawPacket | None:
        """读取一个包；暂时没有包时返回 None，不阻塞等待。"""
        if not self._handle:
            raise RuntimeError("抓包会话尚未打开或已经关闭。")
        header = ct.POINTER(_PacketHeader)()
        data = ct.POINTER(ct.c_ubyte)()
        result = self._library.pcap_next_ex(self._handle, ct.byref(header), ct.byref(data))
        if result == 0:
            return None
        if result == -2:
            raise EOFError("抓包已经结束。")
        if result != 1:
            message = self._library.pcap_geterr(self._handle) or b"Unknown error"
            raise RuntimeError(f"读取失败：{message.decode('utf-8', errors='replace')}")
        if not header:
            raise RuntimeError("Npcap 返回了空的数据包头。")

        info = header.contents
        size = info.captured_length
        if size > SNAPSHOT_LENGTH or size > info.original_length or (size and not data):
            raise RuntimeError("Npcap 返回的数据包长度异常，已停止读取。")
        if not 0 <= info.timestamp.microseconds < 1_000_000:
            raise RuntimeError("Npcap 返回的时间戳格式异常，已停止读取。")

        # 库的内部缓冲区会复用，必须在读取下一个包之前复制成 Python bytes。
        return RawPacket(
            timestamp=info.timestamp.seconds + info.timestamp.microseconds / 1_000_000,
            original_length=info.original_length,
            data=ct.string_at(data, size) if size else b"",
            link_type=self.link_type,
        )

    def close(self) -> None:
        if self._handle:
            self._library.pcap_close(self._handle)
            self._handle = None

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
