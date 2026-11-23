"""读取发往标准 IPv4 / IPv6 组播地址的 mDNS 报头（RFC 6762）。

调用方传入完整 UDP 载荷。本模块只识别组播查询和组播响应，读取报头
中的声明计数；单播应答、域名和资源记录内容超出本实验的解析范围。
"""

from dataclasses import dataclass
from ipaddress import ip_address
import struct


_GROUPS = {ip_address("224.0.0.251"), ip_address("ff02::fb")}
_HEADER = struct.Struct("!6H")


@dataclass(frozen=True)
class MdnsHeader:
    is_response: bool
    questions: int
    answers: int


def parse_mdns(payload: bytes, source: str, destination: str,
               source_port: int, destination_port: int) -> MdnsHeader | None:
    if destination_port != 5353 or not 1 <= source_port <= 65535 or len(payload) < _HEADER.size:
        return None
    try:
        sender = ip_address(source)
        group = ip_address(destination)
    except ValueError:
        return None
    if group not in _GROUPS or sender.version != group.version or sender.is_multicast:
        return None

    _, flags, questions, answers, authorities, additional = _HEADER.unpack_from(payload)
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF
    if opcode != 0 or rcode != 0:
        return None
    is_response = bool(flags & 0x8000)
    if is_response and source_port != 5353:
        return None

    # 最短域名只有 1 字节（根标签）。问题另需 4 字节，资源记录另需 10 字节。
    records = answers + authorities + additional
    minimum_body = questions * 5 + records * 11
    if minimum_body == 0 or len(payload) - _HEADER.size < minimum_body:
        return None
    if is_response and records == 0:
        return None
    return MdnsHeader(is_response, questions, answers)
