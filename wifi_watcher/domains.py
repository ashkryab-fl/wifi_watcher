"""Passive domain hints from visible DNS, TLS SNI and HTTP Host headers.

No reverse DNS requests, TLS decryption, or application content logging.
"""

import re
from collections import OrderedDict
from dataclasses import replace
from ipaddress import ip_address

from scapy.all import DNS, TCP, UDP
from scapy.packet import Padding


LIMIT = 65536


def payload_bytes(transport):
    data = bytes(transport.payload)
    padding = transport.payload.getlayer(Padding)
    if padding is not None:
        size = len(bytes(padding))
        if size:
            data = data[:-size]
    return data


def hostname(value):
    try:
        name = bytes(value).decode("ascii") if isinstance(value, (bytes, bytearray, memoryview)) else str(value)
        name = name.rstrip(".").lower()
        if not name or len(name) > 253:
            return None
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
               for part in name.split(".")):
            return None
        try:
            ip_address(name)
            return None
        except ValueError:
            return name
    except (UnicodeError, ValueError):
        return None


class Prefix:
    """Bounded TCP prefix, tolerating reordering and duplicate segments."""

    def __init__(self, sequence):
        self.sequence = sequence
        self.data = bytearray()
        self.pending = {}

    def add(self, sequence, data):
        offset = (sequence - self.sequence) & 0xffffffff
        if offset >= LIMIT or offset + len(data) > LIMIT:
            raise ValueError("TCP prefix exceeds limit")
        if offset > len(self.data):
            if len(self.pending) >= 32 or sum(map(len, self.pending.values())) + len(data) > LIMIT:
                raise ValueError("Too many out-of-order segments")
            self.pending[offset] = data
        else:
            self.append(offset, data)
        while self.pending and min(self.pending) <= len(self.data):
            offset = min(self.pending)
            self.append(offset, self.pending.pop(offset))
        return bytes(self.data)

    def append(self, offset, data):
        overlap = min(len(data), len(self.data) - offset)
        if self.data[offset:offset + overlap] != data[:overlap]:
            raise ValueError("Conflicting TCP retransmission")
        self.data.extend(data[overlap:])


def client_hello_name(body):
    """Parse RFC 6066 server_name; flag a visible ECH outer name explicitly."""
    try:
        if len(body) < 35 or body[34] > 32:
            return None
        position = 35 + body[34]  # legacy_version, random, session_id
        cipher_length = int.from_bytes(body[position:position + 2], "big")
        if cipher_length < 2 or cipher_length % 2:
            return None
        position += 2 + cipher_length
        position += 1 + body[position]  # compression methods
        if position == len(body):
            return None
        extensions_length = int.from_bytes(body[position:position + 2], "big")
        position += 2
        end = position + extensions_length
        if end != len(body):
            return None
        names = []
        ech = False
        while position + 4 <= end:
            kind = int.from_bytes(body[position:position + 2], "big")
            size = int.from_bytes(body[position + 2:position + 4], "big")
            position += 4
            extension = body[position:position + size]
            if len(extension) != size:
                return None
            position += size
            if kind == 0xfe0d:
                ech = True
            if kind != 0:
                continue
            if len(extension) < 2 or int.from_bytes(extension[:2], "big") != len(extension) - 2:
                return None
            cursor = 2
            while cursor + 3 <= len(extension):
                name_type = extension[cursor]
                length = int.from_bytes(extension[cursor + 1:cursor + 3], "big")
                cursor += 3
                if cursor + length > len(extension):
                    return None
                if name_type == 0:
                    names.append(hostname(extension[cursor:cursor + length]))
                cursor += length
            if cursor != len(extension):
                return None
        if position == end and len(names) == 1 and names[0]:
            return names[0], "tls_sni_outer" if ech else "tls_sni"
    except (IndexError, ValueError):
        return None
    return None


def inspect_prefix(data):
    """Return (finished, name/evidence); never parse HTTP bodies or TLS data."""
    if not data:
        return False, None
    if data[0] == 22:
        position = 0
        handshake = bytearray()
        while position + 5 <= len(data):
            size = int.from_bytes(data[position + 3:position + 5], "big")
            if data[position:position + 2] != b"\x16\x03" or not 0 < size <= 18432:
                return True, None
            if position + 5 + size > len(data):
                return False, None
            handshake.extend(data[position + 5:position + 5 + size])
            position += 5 + size
            if len(handshake) >= 4:
                length = int.from_bytes(handshake[1:4], "big")
                if handshake[0] != 1 or length > LIMIT - 4:
                    return True, None
                if len(handshake) >= length + 4:
                    return True, client_hello_name(handshake[4:length + 4])
        return False, None
    methods = (b"GET ", b"HEAD ", b"POST ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
    if any(method.startswith(data) for method in methods):
        return False, None
    if not data.startswith(methods):
        return True, None
    header_end = data.find(b"\r\n\r\n")
    if header_end < 0:
        return (len(data) >= 16384), None
    if header_end > 16384:
        return True, None
    hosts = [line.split(b":", 1)[1].strip() for line in data[:header_end].split(b"\r\n")[1:]
             if line.lower().startswith(b"host:")]
    if len(hosts) == 1:
        host = hosts[0]
        if b":" in host:
            host, port = host.rsplit(b":", 1)
            if not port.isdigit():
                return True, None
        name = hostname(host)
        if name:
            return True, (name, "http_host")
    return True, None


class DomainTracker:
    def __init__(self):
        self.dns = OrderedDict()
        self.flows = OrderedDict()
        self.prefixes = OrderedDict()

    @staticmethod
    def key(info):
        return tuple(sorted(((info.source, info.source_port), (info.destination, info.destination_port))))

    def learn_dns(self, packet, now):
        # Only ordinary UDP DNS responses. Encrypted DNS is never queried/decrypted.
        if not packet.haslayer(UDP) or packet[UDP].sport != 53:
            return
        try:
            dns = DNS(payload_bytes(packet[UDP]))
            if dns.qr != 1 or dns.rcode != 0:
                return
            answers = list(dns.an)[:128]
            for question in list(dns.qd)[:8]:
                query = hostname(question.qname)
                if not query:
                    continue
                reachable = {query: 86400}
                for _ in range(16):
                    changed = False
                    for answer in answers:
                        owner = hostname(answer.rrname)
                        alias = hostname(answer.rdata) if answer.type == 5 else None
                        if owner in reachable and alias and alias not in reachable:
                            reachable[alias] = min(reachable[owner], int(answer.ttl))
                            changed = True
                    if not changed:
                        break
                for answer in answers:
                    owner = hostname(answer.rrname)
                    if answer.type not in (1, 28) or owner not in reachable or answer.rclass != 1:
                        continue
                    address = str(ip_address(answer.rdata))
                    ttl = min(int(answer.ttl), reachable[owner], 86400)
                    if ttl <= 0:
                        continue
                    entries = {name: expires for name, expires in self.dns.get(address, {}).items() if expires > now}
                    # Retain ambiguity rather than guessing one site on a shared IP.
                    if query in entries or len(entries) < 16:
                        entries[query] = now + ttl
                    self.dns[address] = entries
                    self.dns.move_to_end(address)
                    while len(self.dns) > 4096:
                        self.dns.popitem(last=False)
        except (AttributeError, ValueError, TypeError, IndexError, OverflowError):
            return

    def dns_names(self, address, now):
        names = self.dns.get(address, {})
        names = {name: expires for name, expires in names.items() if expires > now}
        if names:
            self.dns[address] = names
            return tuple(sorted(names))
        self.dns.pop(address, None)
        return ()

    def enrich(self, packet, info):
        try:
            return self._enrich(packet, info)
        except Exception:
            # Malformed optional hints must never stop packet forwarding.
            return info

    def _enrich(self, packet, info):
        now = float(packet.time)
        if info.protocol == "UDP":
            self.learn_dns(packet, now)
        # Age state even for streams that never reveal a name.
        for cache, timeout in ((self.flows, 3600), (self.prefixes, 30)):
            while cache and now - next(iter(cache.values()))[0] > timeout:
                cache.popitem(last=False)
        key = self.key(info) if info.protocol == "TCP" else None
        if info.protocol == "TCP":
            tcp = packet[TCP]
            if info.direction == "TX":
                if tcp.flags.S and not tcp.flags.A:
                    self.flows.pop(key, None)
                    self.prefixes[key] = (now, Prefix((tcp.seq + 1) & 0xffffffff))
                payload = payload_bytes(tcp)
                if payload and key not in self.flows:
                    _, prefix = self.prefixes.get(key, (now, Prefix(tcp.seq)))
                    try:
                        data = prefix.add((tcp.seq + int(tcp.flags.S)) & 0xffffffff, payload)
                        finished, found = inspect_prefix(data)
                    except ValueError:
                        finished, found = True, None
                    if finished:
                        self.prefixes.pop(key, None)
                        # A negative result also avoids parsing encrypted data again.
                        self.flows[key] = (now, found)
                    else:
                        self.prefixes[key] = (now, prefix)
                        self.prefixes.move_to_end(key)
            if key in self.flows:
                _, found = self.flows[key]
                self.flows[key] = (now, found)
                self.flows.move_to_end(key)
            while len(self.flows) > 4096:
                self.flows.popitem(last=False)
            while len(self.prefixes) > 128:
                self.prefixes.popitem(last=False)
        found = self.flows.get(key, (now, None))[1] if key is not None else None
        source = self.dns_names(info.source, now)
        destination = self.dns_names(info.destination, now)
        source_evidence = "dns" if source else None
        destination_evidence = "dns" if destination else None
        if found:
            name, evidence = found
            if info.direction == "TX":
                destination, destination_evidence = (name,), evidence
            else:
                source, source_evidence = (name,), evidence
        result = replace(info, source_domains=source, destination_domains=destination,
                         source_domain_source=source_evidence, destination_domain_source=destination_evidence)
        if key is not None and (packet[TCP].flags.F or packet[TCP].flags.R):
            self.flows.pop(key, None)
            self.prefixes.pop(key, None)
        return result
