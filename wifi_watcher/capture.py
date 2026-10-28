"""Passive capture and opt-in, single-device IPv4 Ethernet relay."""

import threading
import time

from scapy.all import ARP, IP, AsyncSniffer, Ether, conf, srp


class Capture:
    def __init__(self, network, device, gateway, relay, on_packet):
        self.network = network
        self.device = device
        self.gateway = gateway
        self.relay = relay
        self.on_packet = on_packet
        self.stopped = threading.Event()
        self.ready = threading.Event()
        self.lock = threading.Lock()
        self.socket = None
        self.sniffer = None
        self.poisoner = None
        self.prober = None
        self.poisoned = False
        self.error = None
        self.forwarded = 0
        self.guardian = None
        self.cleanup_errors = []
        self.peer_activity = {}
        self.intercept_port = None

    def send(self, packet):
        with self.lock:
            self.socket.send(packet)

    def handle(self, packet):
        try:
            if self.relay:
                frame = relay_frame(packet, self.network.mac, self.device, self.gateway)
                if frame is None:
                    # Kernel/proxy reply already reverse-translated by pf.
                    if (self.intercept_port is not None and packet.haslayer(Ether) and packet.haslayer(IP)
                            and packet.src.lower() == self.network.mac and packet.dst.lower() == self.device.mac
                            and packet[IP].dst == self.device.ip):
                        self.on_packet(packet)
                    return
                # Valid forwarded traffic proves this peer is still reachable,
                # even when a phone in power saving mode ignores ARP probes.
                self.peer_activity[packet.src.lower()] = time.monotonic()
                # Ordinary relay forwards before logging, bypassing OS routing.
                # HTTPS mode delegates forwarding/redirection to the kernel.
                if self.intercept_port is None:
                    self.send(frame)
                    self.forwarded += 1
                elif packet.src.lower() == self.gateway.mac:
                    return  # Count RX once, when the kernel sends it to the device.
            self.on_packet(packet)
        except Exception as error:
            self.error = error
            self.stopped.set()

    def arp_pair(self, restore=False):
        own = self.network.mac
        target, router = self.device, self.gateway
        return [
            Ether(src=router.mac if restore else own, dst=target.mac) /
            ARP(op=2, psrc=router.ip, hwsrc=router.mac if restore else own,
                pdst=target.ip, hwdst=target.mac),
            Ether(src=target.mac if restore else own, dst=router.mac) /
            ARP(op=2, psrc=target.ip, hwsrc=target.mac if restore else own,
                pdst=router.ip, hwdst=router.mac),
        ]

    def poison(self):
        try:
            while not self.stopped.is_set():
                # Mark before either send, so a partial failure still restores both.
                self.poisoned = True
                for packet in self.arp_pair():
                    self.send(packet)
                self.stopped.wait(2)
        except Exception as error:
            self.error = error
            self.stopped.set()

    def probe_answers(self, requests):
        # Scapy's ARP matching checks sender IP, not the reply recipient. On
        # macOS the receive socket also sees our concurrent ARP announcements.
        # Filter before matching so they cannot consume a genuine peer reply.
        own = self.network.mac.lower()
        answers, _ = srp(requests, iface=self.network.interface, timeout=.8, verbose=False,
                         filter=f"arp and arp[6:2] = 2 and ether dst {own} and not ether src {own}")
        queried = {request[ARP].pdst for request in requests}
        expected = {self.device.ip: self.device.mac, self.gateway.ip: self.gateway.mac}
        actual = {}
        for _, reply in answers:
            if not reply.haslayer(Ether) or not reply.haslayer(ARP):
                continue
            arp = reply[ARP]
            if (arp.op != 2 or arp.psrc not in queried or arp.pdst != self.network.ip
                    or reply[Ether].dst.lower() != own or arp.hwdst.lower() != own
                    or reply[Ether].src.lower() == own or arp.hwsrc.lower() == own):
                continue
            mac = arp.hwsrc.lower()
            if mac != expected[arp.psrc].lower():
                raise RuntimeError(f"IP/MAC девайса або роутера змінився: {arp.psrc}, "
                                   f"очікувався {expected[arp.psrc]}, отримано {mac}. Пересилання зупинено.")
            actual[arp.psrc] = mac
        return actual

    def probe(self):
        missed = {self.device.ip: 0, self.gateway.ip: 0}
        try:
            while not self.stopped.wait(3):
                expected = {self.device.ip: self.device.mac, self.gateway.ip: self.gateway.mac}
                requests = [Ether(src=self.network.mac, dst=mac) /
                            ARP(hwsrc=self.network.mac, psrc=self.network.ip, pdst=address)
                            for address, mac in expected.items()]
                actual = self.probe_answers(requests)
                now = time.monotonic()
                missing = [address for address, mac in expected.items() if missed[address] >= 1
                           and address not in actual and now - self.peer_activity.get(mac, float('-inf')) >= 15]
                if missing:
                    # Some Wi-Fi peers ignore unicast ARP; retry using the same
                    # broadcast discovery format before declaring them absent.
                    retry = [Ether(src=self.network.mac, dst="ff:ff:ff:ff:ff:ff") /
                             ARP(hwsrc=self.network.mac, psrc=self.network.ip, pdst=address)
                             for address in missing]
                    actual.update(self.probe_answers(retry))
                for address, mac in expected.items():
                    reachable = actual.get(address) == mac or now - self.peer_activity.get(mac, float('-inf')) < 15
                    missed[address] = 0 if reachable else missed[address] + 1
                if any(count >= 3 for count in missed.values()):
                    raise RuntimeError("Девайс або роутер не відповідає на ARP. Пересилання зупинено.")
        except Exception as error:
            self.error = error
            self.stopped.set()

    def start(self):
        try:
            if self.relay:
                self.socket = conf.L2socket(iface=self.network.interface)
                from .guardian import Guardian
                self.guardian = Guardian(self.network, self.device, self.gateway)
                self.guardian.intercept_port = self.intercept_port
                self.guardian.start()
                expression = (
                    f"ip and ether dst {self.network.mac} and "
                    f"((ether src {self.device.mac} and src host {self.device.ip}) or "
                    f"(ether src {self.gateway.mac} and dst host {self.device.ip}))"
                )
                if self.intercept_port is not None:
                    # The kernel forwards in this mode. Observe only the device
                    # side, including replies synthesized by the HTTPS proxy.
                    expression = (f"ip and ((ether dst {self.network.mac} and "
                                  f"((ether src {self.device.mac} and src host {self.device.ip}) or "
                                  f"(ether src {self.gateway.mac} and dst host {self.device.ip}))) or "
                                  f"(ether src {self.network.mac} and ether dst {self.device.mac} and dst host {self.device.ip}))")
            else:
                expression = f"ether host {self.device.mac} or host {self.device.ip}"
            self.sniffer = AsyncSniffer(
                iface=self.network.interface, filter=expression,
                prn=self.handle, store=False, started_callback=self.ready.set,
            )
            self.sniffer.start()
            if not self.ready.wait(4):
                raise RuntimeError(str(getattr(self.sniffer, "exception", None) or
                                       "Захоплення не запустилося за 4 секунди."))
            if self.relay:
                self.poisoner = threading.Thread(target=self.poison, daemon=True)
                self.poisoner.start()
                self.prober = threading.Thread(target=self.probe, daemon=True)
                self.prober.start()
        except BaseException:
            self.close()
            raise

    def check(self):
        if self.guardian:
            self.guardian.pulse()
        if self.error:
            raise RuntimeError(f"Захоплення/пересилання зупинилося: {self.error}")
        if self.sniffer and not self.sniffer.running:
            error = getattr(self.sniffer, "exception", None)
            raise RuntimeError(f"Захоплення несподівано зупинилося: {error or 'невідома причина'}")

    def close(self):
        self.stopped.set()
        if self.poisoner:
            self.poisoner.join(timeout=3)
        if self.prober:
            self.prober.join(timeout=2)
        errors = list(self.cleanup_errors)
        if self.poisoned:
            # Keep forwarding until peers have received the real MAC addresses.
            for _ in range(5):
                for packet in self.arp_pair(restore=True):
                    try:
                        self.send(packet)
                    except Exception as error:
                        errors.append(str(error))
                time.sleep(0.1)
            self.poisoned = False
        if self.sniffer and self.sniffer.running:
            try:
                self.sniffer.stop()
            except Exception as error:
                errors.append(str(error))
        if self.socket:
            try:
                self.socket.close()
            except Exception as error:
                errors.append(str(error))
            self.socket = None
        if self.guardian:
            errors.extend(self.guardian.close(disarm=not errors))
            self.guardian = None
        self.cleanup_errors = list(errors)
        return errors


def relay_frame(packet, local_mac, device, gateway):
    """Only forward IPv4 between one verified host and its gateway."""
    if not isinstance(packet, Ether) or not isinstance(packet.payload, IP):
        return None
    if packet.dst.lower() != local_mac:
        return None
    ip = packet.payload
    if packet.src.lower() == device.mac and ip.src == device.ip:
        destination = gateway.mac
    elif packet.src.lower() == gateway.mac and ip.dst == device.ip:
        destination = device.mac
    else:
        return None
    # Serialize the original network bytes verbatim: no TTL/checksum/NAT changes.
    return Ether(dst=destination, src=local_mac, type=packet.type) / bytes(packet.payload)
