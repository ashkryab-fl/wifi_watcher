from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr, srp


@dataclass(frozen=True)
class Network:
    interface: str
    ip: str
    mac: str
    subnet: IPv4Network
    gateway: str


@dataclass(frozen=True)
class Device:
    ip: str
    mac: str
    label: str = ""
    name: str = ""


def interfaces():
    """Prefer real LAN interfaces over VPN routes on macOS."""
    candidates = []
    for iface in conf.ifaces.values():
        name = iface.network_name
        if name.startswith(("lo", "utun", "tun", "ipsec", "awdl", "llw", "ap")):
            continue
        try:
            address = IPv4Address(get_if_addr(name))
            if not address.is_unspecified and not address.is_loopback and not address.is_link_local:
                candidates.append(name)
        except (OSError, ValueError):
            continue
    return sorted(set(candidates))


def network_info(interface, gateway=None, subnet=None):
    ip = get_if_addr(interface)
    if ip == "0.0.0.0":
        raise ValueError(f"Інтерфейс {interface} не має IPv4-адреси.")
    routes = [r for r in conf.route.routes if str(r[3]) == interface]
    direct = [
        IPv4Network((int(r[0]), str(IPv4Address(r[1]))))
        for r in routes if r[1] and r[1] != 0xffffffff and r[2] == "0.0.0.0"
        and int(IPv4Address(ip)) & r[1] == r[0]
    ]
    lan = IPv4Network(subnet, strict=False) if subnet else max(
        direct, key=lambda n: n.prefixlen, default=None
    )
    if lan is None:
        raise ValueError("Не вдалося визначити підмережу; додай --subnet 192.168.0.0/24.")
    gateways = [r[2] for r in routes if r[0] == 0 and r[2] != "0.0.0.0"]
    router = str(IPv4Address(gateway)) if gateway else (gateways[0] if gateways else "")
    if not router:
        raise ValueError("Не вдалося визначити роутер; додай --gateway 192.168.0.1.")
    if IPv4Address(ip) not in lan or IPv4Address(router) not in lan:
        raise ValueError("Mac і роутер мають бути у вибраній локальній підмережі.")
    if lan.num_addresses > 1024:
        raise ValueError("Для пошуку обери --subnet з максимум 1024 адресами.")
    return Network(interface, ip, get_if_hwaddr(interface).lower(), lan, router)


def discover(network):
    """Active ARP responses, not stale cache entries or DHCP leases."""
    answers, _ = srp(
        Ether(src=network.mac, dst="ff:ff:ff:ff:ff:ff") /
        ARP(hwsrc=network.mac, psrc=network.ip,
            pdst=[str(ip) for ip in network.subnet.hosts() if str(ip) != network.ip]),
        iface=network.interface, timeout=2, retry=1, inter=0.005, verbose=False,
    )
    devices = {network.ip: Device(network.ip, network.mac, "цей комп’ютер")}
    for sent, reply in answers:
        if not reply.haslayer(ARP):
            continue
        address, mac = reply[ARP].psrc, reply[ARP].hwsrc.lower()
        if address != sent[ARP].pdst or IPv4Address(address) not in network.subnet:
            continue
        if int(mac.split(":")[0], 16) & 1 or mac == "00:00:00:00:00:00":
            continue
        label = "роутер" if address == network.gateway else ""
        devices[address] = Device(address, mac, label)
    return sorted(devices.values(), key=lambda d: int(IPv4Address(d.ip)))
