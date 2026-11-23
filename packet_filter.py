"""对已解析的协议字段进行显示筛选。一个包可以匹配多个协议层。"""

from dataclasses import dataclass
from ipaddress import ip_address

from packet_parser import PacketInfo


FILTERS = ("全部", "IPv4", "IPv6", "TCP", "UDP", "ICMP", "ICMPv6", "HTTP", "mDNS")


@dataclass(frozen=True)
class EndpointFilter:
    ip: str | None = None
    port: int | None = None

    def matches(self, address: str, port: int | None) -> bool:
        return (self.ip is None or self.ip == address) and (self.port is None or self.port == port)


def parse_endpoint_filter(ip_text: str, port_text: str) -> EndpointFilter:
    address = ip_text.strip()
    port_number = None
    if address:
        try:
            parsed_ip = ip_address(address)
        except ValueError:
            raise ValueError("请输入完整的 IPv4 或 IPv6 地址，例如 10.207.93.201 或 fe80::1。") from None
        # 捕获自单张网卡，IPv6 的区域编号不在报文内。用地址字节统一输入格式。
        address = str(ip_address(parsed_ip.packed))
    port_text = port_text.strip()
    if port_text:
        digits = port_text.lstrip("0") or "0"
        if not port_text.isascii() or not port_text.isdecimal() or len(digits) > 5:
            raise ValueError("端口须为 0 到 65535 之间的整数。")
        port_number = int(digits)
        if port_number > 65535:
            raise ValueError("端口须为 0 到 65535 之间的整数。")
    return EndpointFilter(address or None, port_number)


def matches_filter(info: PacketInfo, choice: str, endpoint: EndpointFilter | None = None) -> bool:
    if choice != "全部":
        layers = (info.network_protocol, info.transport_protocol, info.application_protocol)
        if choice not in FILTERS or choice not in layers:
            return False
    if endpoint is None:
        return True
    return (endpoint.matches(info.source, info.source_port)
            or endpoint.matches(info.destination, info.destination_port))
