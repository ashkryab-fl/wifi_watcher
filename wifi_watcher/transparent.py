"""Scoped macOS pf redirection. Owned and restored by the ARP guardian."""

import fcntl
import re
import subprocess
import sys
import uuid
from ipaddress import IPv4Address, IPv4Network


def redirect_rules(network, device, port):
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,31}", network.interface):
        raise ValueError("Некоректний мережевий інтерфейс.")
    target, subnet = IPv4Address(device.ip), IPv4Network(network.subnet)
    if target not in subnet or not 1024 <= int(port) <= 65535:
        raise ValueError("Некоректні параметри HTTPS-перехоплення.")
    return (f"rdr pass on {network.interface} inet proto tcp from {target} "
            f"to ! {subnet} port {{ 80, 443 }} -> 127.0.0.1 port {int(port)}\n"
            # Transparent mode cannot decode QUIC. Reject it for this device
            # so browsers can fall back to HTTPS over the intercepted TCP path.
            f"block return in quick on {network.interface} inet proto udp from {target} "
            f"to ! {subnet} port 443\n")


class TransparentNetwork:
    def __init__(self, network, device, port, directory):
        self.rules = redirect_rules(network, device, port)
        self.directory = directory
        self.anchor = "com.apple/wifi-watcher-" + uuid.uuid4().hex
        self.token = None
        self.original = {}
        self.loaded = False
        self.lock = None

    def run(self, *args, input=None):
        result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=4)
        if result.returncode:
            raise RuntimeError(f"{args[0]}: {result.stderr.strip()[-1000:]}")
        return result.stdout + "\n" + result.stderr

    def start(self):
        if sys.platform != "darwin":
            raise ValueError("HTTPS-перехоплення зараз підтримує лише macOS.")
        # Forwarding is global: don't let two guardians save/restore each
        # other's intermediate settings.
        self.lock = (self.directory / "https.lock").open("a")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Інший HTTPS-сеанс уже змінює мережу цього Mac.") from None
        rules = self.run("/sbin/pfctl", "-sn")
        if not re.search(r'rdr-anchor\s+"com\.apple/\*"', rules):
            raise RuntimeError("У pf немає системного rdr-anchor com.apple/*. Налаштування не змінено.")
        filters = self.run("/sbin/pfctl", "-sr")
        if not re.search(r'^\s*anchor\s+"com\.apple/\*"', filters, re.MULTILINE):
            raise RuntimeError("У pf немає системного filter anchor com.apple/*. Налаштування не змінено.")
        # Syntax check before any host mutation. Never reload /etc/pf.conf.
        self.run("/sbin/pfctl", "-n", "-a", self.anchor, "-f", "-", input=self.rules)
        # Wi-Fi partial RX checksum metadata can remain stale after pf rdr.
        # TCP then drops correctly checksummed packets before the listener.
        # Keep checksum validation, but compute it in software for the session.
        # The guardian restores this host-wide setting on every cleanup path.
        for name, value in (("net.inet.ip.forwarding", "1"), ("net.inet.ip.redirect", "0"),
                            ("net.link.generic.system.hwcksum_rx", "0")):
            original = self.run("/usr/sbin/sysctl", "-n", name).strip()
            if original not in ("0", "1"):
                raise RuntimeError("Не вдалося прочитати " + name)
            self.original[name] = (original, value)
            if original != value:
                self.run("/usr/sbin/sysctl", "-w", f"{name}={value}")
        # Mark before load so a partial failure still removes our own anchor.
        self.loaded = True
        self.run("/sbin/pfctl", "-a", self.anchor, "-f", "-", input=self.rules)
        result = self.run("/sbin/pfctl", "-E")
        token = re.search(r"Token\s*:\s*(\d+)", result)
        if not token:
            raise RuntimeError("pf не повернув токен увімкнення; перевір стан pf вручну.")
        self.token = token[1]

    def close(self):
        errors = []
        if self.loaded:
            try:
                # Loading an empty anchor removes only our rules. Never use
                # -F all/states, which could disrupt unrelated host sessions.
                self.run("/sbin/pfctl", "-a", self.anchor, "-f", "-", input="")
                self.loaded = False
            except Exception as error:
                errors.append(str(error))
        if self.token:
            try:
                self.run("/sbin/pfctl", "-X", self.token)
                self.token = None
            except Exception as error:
                errors.append(str(error))
        for name, (original, applied) in list(self.original.items()):
            try:
                current = self.run("/usr/sbin/sysctl", "-n", name).strip()
                if current == applied and original != applied:
                    self.run("/usr/sbin/sysctl", "-w", f"{name}={original}")
                elif current != applied:
                    errors.append(f"{name} змінив інший процес; значення не перезаписано.")
                del self.original[name]
            except Exception as error:
                errors.append(str(error))
        if self.lock:
            self.lock.close()
            self.lock = None
        return errors
