"""从原始字节解析基础协议，不依赖抓包驱动，不做流/分片重组。

依据：IPv4 RFC 791、IPv6 RFC 8200、TCP RFC 9293、UDP RFC 768。
link_type 接收 Npcap pcap_datalink() 返回的实时 DLT 值。
"""

from dataclasses import dataclass, field
import ipaddress
import re
import struct

from mdns_parser import parse_mdns


@dataclass
class PacketInfo:
    link_protocol: str = "未知"
    network_protocol: str = ""
    transport_protocol: str = ""
    source: str = ""
    destination: str = ""
    source_port: int | None = None
    destination_port: int | None = None
    summary: str = ""
    details: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    application_protocol: str = ""
    # 字段名 -> (从帧首起算的字节偏移, 长度)。位字段指向包含它的字节。
    field_ranges: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def protocol(self) -> str:
        layers = [self.network_protocol, self.transport_protocol, self.application_protocol]
        return " / ".join(layer for layer in layers if layer) or self.link_protocol


class _ParseError(ValueError):
    pass


def _require(data: bytes, size: int, label: str) -> None:
    if len(data) < size:
        raise _ParseError(f"{label}不完整：至少需要 {size} 字节，当前只有 {len(data)} 字节")


def _u16(data: bytes, offset: int) -> int:
    # 网络字节序是大端：例如 01 28 表示 0x0128，也就是 296。
    return struct.unpack_from("!H", data, offset)[0]


def format_endpoint(address: str, port: int | None) -> str:
    if not address:
        return "未解析"
    if port is None:
        return address
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def _transport_name(number: int, version: int) -> str:
    names = {6: "TCP", 17: "UDP", 1 if version == 4 else 58: "ICMP" if version == 4 else "ICMPv6"}
    return names.get(number, "")


# 标准 HTTP/1.0、1.1 请求或响应的第一行（RFC 9112 第 3、4 节）。
# 只检查 TCP 载荷开头最多 8192 字节，保留方法/状态码供显示。
_REQUEST_LINE = re.compile(
    rb"(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) ([\x21-\x7e]+) (HTTP/1\.[01])"
)
_RESPONSE_LINE = re.compile(rb"(HTTP/1\.[01]) ([1-5][0-9]{2}) [\t\x20-\x7e\x80-\xff]*")
# origin-form 的路径以及可选查询，仅接受 URI 字符和完整的百分号编码。
_PATH_QUERY = rb"(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*"
_WEB_TARGET = re.compile(
    rb"(?:/" + _PATH_QUERY + rb"|https?://(?:[A-Za-z0-9.\-]+|\[[A-Fa-f0-9:.]+\])"
    rb"(?::[0-9]+)?(?:[/?]" + _PATH_QUERY + rb")?)", re.IGNORECASE
)
_CONNECT_TARGET = re.compile(rb"(?:[A-Za-z0-9.\-]+|\[[A-Fa-f0-9:.]+\]):[0-9]+")


def _read_http_start_line(segment: bytes, offset: int, result: PacketInfo, start: int) -> None:
    end = segment.find(b"\r\n", offset, offset + 8192)
    if end < 0:
        return
    line = segment[offset:end]
    response = _RESPONSE_LINE.fullmatch(line)
    if response:
        version, status = response.groups()
        label, value = "响应状态码", status
        version_offset, value_offset = response.start(1), response.start(2)
    else:
        request = _REQUEST_LINE.fullmatch(line)
        if not request:
            return
        method, target, version = request.groups()
        if method == b"CONNECT":
            valid_target = _CONNECT_TARGET.fullmatch(target)
        elif target == b"*":
            valid_target = method == b"OPTIONS"
        else:
            valid_target = _WEB_TARGET.fullmatch(target)
        if not valid_target:
            return
        label, value = "请求方法", method
        version_offset, value_offset = request.start(3), request.start(1)
    version_text = version.decode("ascii")
    value_text = value.decode("ascii")
    result.application_protocol = "HTTP"
    result.details.extend([("HTTP 版本", version_text), (label, value_text)])
    line_start = start + offset
    result.field_ranges["HTTP 版本"] = (line_start + version_offset, len(version))
    result.field_ranges[label] = (line_start + value_offset, len(value))
    result.summary = f"{version_text} {label} {value_text}"


def _parse_transport(data: bytes, number: int, version: int, declared_length: int,
                     fragmented: bool, result: PacketInfo, start: int) -> None:
    name = _transport_name(number, version)
    result.transport_protocol = name
    if not name:
        result.notes.append(f"暂未解析 IP 协议号 {number} 的上层内容")
        return

    if name == "TCP":
        _require(data, 20, "TCP 头部")
        header_length = (data[12] >> 4) * 4
        if header_length < 20:
            raise _ParseError("TCP 头部长度字段不合法：小于 20 字节")
        _require(data, header_length, "TCP 头部及选项")
        result.source_port, result.destination_port = struct.unpack_from("!HH", data)
        sequence, acknowledgement = struct.unpack_from("!II", data, 4)
        flags = [label for mask, label in (
            (0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"), (0x10, "ACK"),
            (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN"),
        ) if data[13] & mask]
        flag_text = ", ".join(flags) or "无"
        result.details.extend([
            ("TCP 头部长度", str(header_length)), ("TCP 标志", flag_text),
            ("TCP 序号", str(sequence)), ("TCP 确认号", str(acknowledgement)),
            ("TCP 窗口", str(_u16(data, 14))),
        ])
        result.field_ranges.update({
            "源端口": (start, 2), "目的端口": (start + 2, 2),
            "TCP 序号": (start + 4, 4), "TCP 确认号": (start + 8, 4),
            "TCP 头部长度": (start + 12, 1), "TCP 标志": (start + 13, 1),
            "TCP 窗口": (start + 14, 2),
        })
        result.summary = f"标志 {flag_text}，序号 {sequence}，确认号 {acknowledgement}"
        if not fragmented and header_length < len(data):
            _read_http_start_line(data, header_length, result, start)
    elif name == "UDP":
        _require(data, 8, "UDP 头部")
        length = _u16(data, 4)
        if length < 8:
            raise _ParseError("UDP 长度字段不合法：小于 8 字节；未支持 IPv6 巨型数据报")
        if not fragmented and length > declared_length:
            raise _ParseError("UDP 声明长度超出 IP 载荷范围")
        result.source_port, result.destination_port = struct.unpack_from("!HH", data)
        result.details.append(("UDP 声明长度", str(length)))
        result.field_ranges.update({
            "源端口": (start, 2), "目的端口": (start + 2, 2), "UDP 声明长度": (start + 4, 2),
        })
        result.summary = f"UDP 声明长度 {length} 字节（包含 8 字节 UDP 头部）"
        if not fragmented and length > len(data):
            result.notes.append("UDP 数据未完整捕获")
        elif not fragmented and result.destination_port == 5353:
            header = parse_mdns(data[8:length], result.source, result.destination,
                                result.source_port, result.destination_port)
            if header:
                dns_start = start + 8
                kind = "响应" if header.is_response else "查询"
                result.application_protocol = "mDNS"
                result.details.extend([
                    ("mDNS 消息类型", kind), ("mDNS 问题数", str(header.questions)),
                    ("mDNS 回答数", str(header.answers)),
                ])
                result.field_ranges.update({
                    "mDNS 消息类型": (dns_start + 2, 1), "mDNS 问题数": (dns_start + 4, 2),
                    "mDNS 回答数": (dns_start + 6, 2),
                })
                result.summary = f"mDNS {kind}，问题 {header.questions}，回答 {header.answers}"
    else:
        _require(data, 4, f"{name} 通用头部")
        kind, code = data[0], data[1]
        descriptions = (
            {0: "回显应答", 3: "目的不可达", 8: "回显请求", 11: "超时"}
            if version == 4 else
            {1: "目的不可达", 2: "数据包过大", 3: "超时", 128: "回显请求", 129: "回显应答",
             133: "路由器请求", 134: "路由器通告", 135: "邻居请求", 136: "邻居通告"}
        )
        description = descriptions.get(kind, "其他类型")
        result.details.extend([(f"{name} 类型", str(kind)), (f"{name} 代码", str(code))])
        result.field_ranges.update({f"{name} 类型": (start, 1), f"{name} 代码": (start + 1, 1)})
        result.summary = f"{description}，类型 {kind}，代码 {code}"
        echo_types = (0, 8) if version == 4 else (128, 129)
        if kind in echo_types:
            _require(data, 8, f"{name} 回显头部")
            result.details.extend([("回显标识符", str(_u16(data, 4))), ("回显序号", str(_u16(data, 6)))])
            result.field_ranges.update({"回显标识符": (start + 4, 2), "回显序号": (start + 6, 2)})


def _parse_ipv4(data: bytes, result: PacketInfo, start: int) -> None:
    result.network_protocol = "IPv4"
    _require(data, 20, "IPv4 头部")
    if data[0] >> 4 != 4:
        raise _ParseError("链路层标记为 IPv4，但 IP 版本字段不匹配")
    header_length = (data[0] & 0x0F) * 4
    if header_length < 20:
        raise _ParseError("IPv4 头部长度字段不合法：小于 20 字节")
    total_length = _u16(data, 2)
    if total_length < header_length:
        raise _ParseError("IPv4 总长度小于头部长度")
    result.source = str(ipaddress.IPv4Address(data[12:16]))
    result.destination = str(ipaddress.IPv4Address(data[16:20]))
    result.details.extend([
        ("IPv4 头部长度", str(header_length)), ("IPv4 总长度", str(total_length)),
        ("TTL", str(data[8])), ("IPv4 协议号", str(data[9])),
    ])
    result.field_ranges.update({
        "IPv4 头部长度": (start, 1), "IPv4 总长度": (start + 2, 2),
        "TTL": (start + 8, 1), "IPv4 协议号": (start + 9, 1),
        "源地址": (start + 12, 4), "目的地址": (start + 16, 4),
    })
    _require(data, header_length, "IPv4 头部及选项")
    if len(data) < total_length:
        result.notes.append(f"IPv4 报文截断：声明 {total_length} 字节，捕获到 {len(data)} 字节")

    fragment = _u16(data, 6)
    fragment_offset = (fragment & 0x1FFF) * 8
    more_fragments = bool(fragment & 0x2000)
    if fragment_offset:
        result.transport_protocol = _transport_name(data[9], 4)
        result.notes.append(f"IPv4 后续分片，偏移 {fragment_offset} 字节；本步骤不重组、不读取端口")
        return
    if more_fragments:
        result.notes.append("IPv4 首个分片；只解析本片已有的头部，尚未重组完整数据")

    # 按 IP 总长度收窄范围，不能把以太网末尾的填充当成 TCP/UDP 数据。
    payload = data[header_length:min(total_length, len(data))]
    _parse_transport(payload, data[9], 4, total_length - header_length, more_fragments, result,
                     start + header_length)


def _parse_ipv6(data: bytes, result: PacketInfo, start: int) -> None:
    result.network_protocol = "IPv6"
    _require(data, 40, "IPv6 基础头部")
    if data[0] >> 4 != 6:
        raise _ParseError("链路层标记为 IPv6，但 IP 版本字段不匹配")
    payload_length = _u16(data, 4)
    next_header = data[6]
    result.source = str(ipaddress.IPv6Address(data[8:24]))
    result.destination = str(ipaddress.IPv6Address(data[24:40]))
    result.details.extend([
        ("IPv6 载荷长度", str(payload_length)), ("IPv6 下一头部", str(next_header)),
        ("Hop Limit", str(data[7])),
    ])
    result.field_ranges.update({
        "IPv6 载荷长度": (start + 4, 2), "IPv6 下一头部": (start + 6, 1),
        "Hop Limit": (start + 7, 1), "源地址": (start + 8, 16), "目的地址": (start + 24, 16),
    })
    if len(data) < 40 + payload_length:
        result.notes.append("IPv6 报文截断：捕获字节不足以覆盖声明的载荷")
    if next_header == 59:
        result.summary = "IPv6 无下一头部"
        return
    if next_header in {0, 43, 44, 50, 51, 60, 135, 139, 140}:
        result.notes.append(f"IPv6 扩展头（类型 {next_header}）暂未解析，保留地址，不猜测端口")
        return
    payload = data[40:min(40 + payload_length, len(data))]
    _parse_transport(payload, next_header, 6, payload_length, False, result, start + 40)


def parse_packet(data: bytes, link_type: int) -> PacketInfo:
    """返回已确认的协议字段；截断、未知或不支持的格式以 notes 说明。"""
    result = PacketInfo()
    try:
        if link_type == 1:  # DLT_EN10MB
            result.link_protocol = "Ethernet"
            _require(data, 14, "以太网头部")
            result.details.extend([
                ("目的 MAC", data[0:6].hex(":")), ("源 MAC", data[6:12].hex(":")),
            ])
            result.field_ranges.update({"目的 MAC": (0, 6), "源 MAC": (6, 6)})
            kind, offset = _u16(data, 12), 14
            tags = 0
            while kind in {0x8100, 0x88A8, 0x9100}:
                if tags == 2:
                    raise _ParseError("超过两层的 VLAN 标签暂未支持")
                _require(data, offset + 4, "VLAN 标签")
                label = f"VLAN {tags + 1} ID"
                result.details.append((label, str(_u16(data, offset) & 0x0FFF)))
                result.field_ranges[label] = (offset, 2)
                kind = _u16(data, offset + 2)
                offset += 4
                tags += 1
            result.details.append(("以太网类型", f"0x{kind:04x}"))
            result.field_ranges["以太网类型"] = (offset - 2, 2)
        elif link_type == 0:  # Npcap NULL 回环头，不是 sockaddr 的地址族布局。
            result.link_protocol = "Loopback"
            _require(data, 4, "回环头部")
            family = int.from_bytes(data[:4], "little")
            kind = {2: 0x0800, 24: 0x86DD, 28: 0x86DD, 30: 0x86DD}.get(family)
            if kind is None:
                result.notes.append(f"回环地址族 {family} 暂未支持")
                return result
            offset = 4
        elif link_type in {12, 228, 229}:  # Windows DLT_RAW, DLT_IPV4, DLT_IPV6
            result.link_protocol = "Raw IP"
            _require(data, 1, "IP 数据")
            kind = {228: 0x0800, 229: 0x86DD}.get(link_type)
            if kind is None:
                kind = {4: 0x0800, 6: 0x86DD}.get(data[0] >> 4)
            offset = 0
        else:
            result.link_protocol = f"链路类型 {link_type}"
            result.notes.append("当前尚未支持这种链路层格式")
            return result

        if kind == 0x0800:
            _parse_ipv4(data[offset:], result, offset)
        elif kind == 0x86DD:
            _parse_ipv6(data[offset:], result, offset)
        elif kind == 0x0806:
            result.network_protocol = "ARP"
            result.notes.append("已识别 ARP 类型，本步骤暂未解析其字段")
        else:
            result.notes.append("当前尚未支持该网络层协议")
    except _ParseError as error:
        result.notes.append(str(error))
    return result
