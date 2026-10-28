from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, Ether
from scapy.layers.inet6 import IPv6ExtHdrFragment

from .network import Device


@dataclass(frozen=True)
class PacketInfo:
    timestamp: str
    direction: str
    protocol: str
    source: str
    source_port: int | None
    destination: str
    destination_port: int | None
    bytes: int
    captured_bytes: int
    source_domains: tuple[str, ...] = ()
    destination_domains: tuple[str, ...] = ()
    source_domain_source: str | None = None
    destination_domain_source: str | None = None

    def json(self):
        return asdict(self)


def packet_info(packet, device: Device):
    """Read L2/L3/L4 headers only. Never inspect application payloads."""
    if packet.haslayer(Ether):
        # Use outer layers: an ICMP error may contain a quoted IP/TCP packet.
        layer = packet[Ether].payload
        while layer.name in ("802.1Q", "802_1AD"):
            layer = layer.payload
        ethernet = packet[Ether]
    else:
        layer, ethernet = packet, None
    if isinstance(layer, (IP, IPv6)):
        src, dst = layer.src, layer.dst
        transport = layer.payload
        if isinstance(layer, IPv6):
            while transport.name.startswith("IPv6 Extension Header"):
                if isinstance(transport, IPv6ExtHdrFragment) and transport.offset:
                    break
                transport = transport.payload
        fragmented = isinstance(layer, IP) and layer.frag != 0
        fragmented |= isinstance(transport, IPv6ExtHdrFragment) and transport.offset != 0
        if not fragmented and isinstance(transport, (TCP, UDP)):
            proto = "TCP" if isinstance(transport, TCP) else "UDP"
            sport, dport = transport.sport, transport.dport
        else:
            number = layer.proto if isinstance(layer, IP) else layer.nh
            proto = "FRAGMENT" if fragmented else (
                "ICMP" if isinstance(transport, ICMP) else
                "ICMPv6" if transport.__class__.__name__.startswith("ICMPv6") else f"IP/{number}"
            )
            sport = dport = None
    elif isinstance(layer, ARP):
        src, dst, proto = layer.psrc, layer.pdst, "ARP"
        sport = dport = None
    else:
        src = ethernet.src if ethernet else "?"
        dst = ethernet.dst if ethernet else "?"
        proto = f"L2/0x{ethernet.type:04x}" if ethernet else "OTHER"
        sport = dport = None

    # An explicit IP wins over a router's MAC (the router forwards many hosts).
    if src == device.ip:
        direction = "TX"
    elif dst == device.ip:
        direction = "RX"
    elif ethernet and device.mac and ethernet.src.lower() == device.mac:
        direction = "TX"
    elif ethernet and device.mac and ethernet.dst.lower() == device.mac:
        direction = "RX"
    else:
        return None
    size = getattr(packet, "wirelen", None) or len(packet)
    return PacketInfo(
        datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat(timespec="microseconds"),
        direction, proto, src, sport, dst, dport, size, len(packet),
    )


def endpoint(address, port, domains=(), evidence=None):
    ip_endpoint = address if port is None else (
        f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    )
    if not domains:
        return ip_endpoint
    names = " / ".join(domains[:2]) + (f" / +{len(domains) - 2}" if len(domains) > 2 else "")
    named_endpoint = names if port is None else f"{names}:{port}"
    hint = " DNS?" if evidence == "dns" else " ECH outer?" if evidence == "tls_sni_outer" else ""
    return f"{named_endpoint} [{ip_endpoint}{hint}]"


def human_bytes(value):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
        value /= 1024


class Statistics:
    def __init__(self):
        self.packets = Counter()
        self.bytes = Counter()
        self.protocols = Counter()
        self.peers = Counter()
        self.peer_packets = Counter()
        self.recent = deque(maxlen=12)
        self.rates = deque()
        self.last_time = None
        self.other_peers = 0

    def add(self, info, now):
        self.packets[info.direction] += 1
        self.bytes[info.direction] += info.bytes
        self.protocols[info.protocol] += 1
        peer = (info.protocol, info.destination, info.destination_port,
                info.destination_domains, info.destination_domain_source) if info.direction == "TX" else (
            info.protocol, info.source, info.source_port, info.source_domains, info.source_domain_source
        )
        # Bound memory for long sessions and port scans. Full detail stays in JSONL.
        if peer in self.peers or len(self.peers) < 10000:
            self.peers[peer] += info.bytes
            self.peer_packets[peer] += 1
        else:
            self.other_peers += info.bytes
        self.recent.append(info)
        self.rates.append((now, info.direction, info.bytes))
        self.last_time = now

    def rate(self, now):
        while self.rates and self.rates[0][0] < now - 1:
            self.rates.popleft()
        rates = Counter()
        for _, direction, size in self.rates:
            rates[direction] += size
        return rates
