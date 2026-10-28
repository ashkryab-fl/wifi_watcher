import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

from wifi_watcher.display import packet_line
from wifi_watcher.domains import DomainTracker, Prefix, hostname, inspect_prefix
from wifi_watcher.metadata import Statistics, packet_info
from wifi_watcher.network import Device


DEVICE = Device("192.168.0.50", "02:00:00:00:00:50")
ROUTER = "02:00:00:00:00:01"
PEER = "198.51.100.10"


def tcp(payload=b"", *, incoming=False, port=51000, seq=100, flags="PA"):
    src, dst = (PEER, DEVICE.ip) if incoming else (DEVICE.ip, PEER)
    sport, dport = (443, port) if incoming else (port, 443)
    packet = Ether(src=ROUTER if incoming else DEVICE.mac, dst=DEVICE.mac if incoming else ROUTER) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, flags=flags) / Raw(payload)
    packet.time = 1000
    return packet


def dns(name, address=PEER, ttl=60, extra=None, cname=None):
    records = []
    owner = cname or name
    if cname:
        records.append(DNSRR(rrname=name, type="CNAME", ttl=ttl, rdata=cname))
    records.append(DNSRR(rrname=owner, type="AAAA" if ":" in address else "A", ttl=ttl, rdata=address))
    if extra:
        records.append(DNSRR(rrname="unrelated.example", ttl=60, rdata=extra))
    packet = Ether(src=ROUTER, dst=DEVICE.mac) / IP(src="192.0.2.53", dst=DEVICE.ip) / UDP(sport=53, dport=53000) / DNS(qr=1, qd=DNSQR(qname=name), an=records)
    packet.time = 1000
    return packet


def hello(name="www.example.com", *, ech=False, two_records=False):
    name = name.encode("ascii")
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    value = len(entry).to_bytes(2, "big") + entry
    extension = b"\x00\x00" + len(value).to_bytes(2, "big") + value
    if ech:
        extension += b"\xfe\x0d\x00\x01\x00"
    body = b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00" + len(extension).to_bytes(2, "big") + extension
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = lambda content: b"\x16\x03\x01" + len(content).to_bytes(2, "big") + content
    return record(handshake[:17]) + record(handshake[17:]) if two_records else record(handshake)


class DomainTests(unittest.TestCase):
    def setUp(self):
        self.tracker = DomainTracker()

    def enrich(self, packet):
        return self.tracker.enrich(packet, packet_info(packet, DEVICE))

    def test_dns_name_shown_and_evidence_recorded(self):
        self.enrich(dns("WWW.Example.COM."))
        info = self.enrich(tcp())
        self.assertEqual(info.destination_domains, ("www.example.com",))
        self.assertEqual(info.destination_domain_source, "dns")
        self.assertIn("www.example.com:443", packet_line(info))
        self.assertIn("DNS?", packet_line(info))
        self.assertEqual(info.destination, PEER)

    def test_dns_alias_maps_original_site_not_only_cdn_name(self):
        self.enrich(dns("www.example.com", cname="edge.cdn.example", extra="203.0.113.99"))
        self.assertEqual(self.enrich(tcp()).destination_domains, ("www.example.com",))
        self.assertEqual(self.tracker.dns_names("203.0.113.99", 1000), ())

    def test_shared_ip_retains_multiple_dns_candidates(self):
        self.enrich(dns("a.example"))
        self.enrich(dns("b.example"))
        info = self.enrich(tcp())
        self.assertEqual(info.destination_domains, ("a.example", "b.example"))
        self.assertEqual(info.destination_domain_source, "dns")

    def test_dns_ttl_expires(self):
        self.enrich(dns("short.example", ttl=2))
        packet = tcp()
        packet.time = 1003
        self.assertEqual(self.enrich(packet).destination_domains, ())

    def test_zero_ttl_not_cached(self):
        self.enrich(dns("uncached.example", ttl=0))
        self.assertEqual(self.enrich(tcp()).destination_domains, ())

    def test_ipv6_dns_record(self):
        self.enrich(dns("ipv6.example", address="2001:db8::10"))
        self.assertEqual(self.tracker.dns_names("2001:db8::10", 1000), ("ipv6.example",))

    def test_sni_propagates_to_both_directions_of_only_its_flow(self):
        info = self.enrich(tcp(hello("secure.example")))
        self.assertEqual(info.destination_domains, ("secure.example",))
        self.assertEqual(info.destination_domain_source, "tls_sni")
        incoming = self.enrich(tcp(b"encrypted", incoming=True))
        self.assertEqual(incoming.source_domains, ("secure.example",))
        self.assertIsNone(incoming.destination_domain_source)
        self.assertEqual(self.enrich(tcp(b"encrypted", port=51001)).destination_domains, ())

    def test_shared_cdn_ip_separate_connections_keep_their_names(self):
        self.enrich(tcp(hello("one.example"), port=51000))
        self.enrich(tcp(hello("two.example"), port=51001))
        first = self.enrich(tcp(b"ciphertext", incoming=True, port=51000))
        second = self.enrich(tcp(b"ciphertext", incoming=True, port=51001))
        self.assertEqual(first.source_domains, ("one.example",))
        self.assertEqual(second.source_domains, ("two.example",))
        stats = Statistics()
        stats.add(first, 1)
        stats.add(second, 1)
        self.assertEqual(len(stats.peers), 2)

    def test_sni_overrides_dns_hint_without_changing_other_connections(self):
        self.enrich(dns("possible.example"))
        self.enrich(tcp(hello("actual.example")))
        self.assertEqual(self.enrich(tcp(b"data", incoming=True)).source_domains, ("actual.example",))
        other = self.enrich(tcp(port=52000))
        self.assertEqual(other.destination_domains, ("possible.example",))
        self.assertEqual(other.destination_domain_source, "dns")

    def test_segmented_client_hello_with_out_of_order_and_retransmission(self):
        content = hello("split.example", two_records=True)
        self.enrich(tcp(seq=99, flags="S"))
        self.assertEqual(self.enrich(tcp(content[:7], seq=100)).destination_domains, ())
        self.enrich(tcp(content[30:], seq=130))
        self.enrich(tcp(content[:7], seq=100))
        info = self.enrich(tcp(content[7:30], seq=107))
        self.assertEqual(info.destination_domains, ("split.example",))

    def test_tcp_sequence_wrap(self):
        content = hello("wrap.example")
        self.enrich(tcp(seq=0xfffffffd, flags="S"))
        self.enrich(tcp(content[:10], seq=0xfffffffe))
        info = self.enrich(tcp(content[10:], seq=8))
        self.assertEqual(info.destination_domains, ("wrap.example",))

    def test_ethernet_padding_is_not_treated_as_initial_tcp_data(self):
        packet = Ether(bytes(tcp(seq=99, flags="S")) + bytes(6))
        self.enrich(packet)
        info = self.enrich(tcp(hello("padded.example"), seq=100))
        self.assertEqual(info.destination_domains, ("padded.example",))

    def test_new_syn_clears_name_for_reused_tuple(self):
        self.enrich(tcp(hello("old.example")))
        info = self.enrich(tcp(seq=2000, flags="S"))
        self.assertEqual(info.destination_domains, ())

    def test_rst_clears_flow_after_labeling_final_packet(self):
        self.enrich(tcp(hello("done.example")))
        self.assertEqual(self.enrich(tcp(incoming=True, flags="R")).source_domains, ("done.example",))
        self.assertEqual(self.enrich(tcp()).destination_domains, ())

    def test_idle_flow_name_expires(self):
        self.enrich(tcp(hello("old.example")))
        packet = tcp(b"ciphertext", incoming=True)
        packet.time = 4601
        self.assertEqual(self.enrich(packet).source_domains, ())

    def test_ech_outer_sni_marked_as_uncertain(self):
        info = self.enrich(tcp(hello("public.example", ech=True)))
        self.assertEqual(info.destination_domains, ("public.example",))
        self.assertEqual(info.destination_domain_source, "tls_sni_outer")
        self.assertIn("ECH outer?", packet_line(info))

    def test_http_host_with_port_no_url_or_cookie_logged(self):
        content = b"GET /private/path HTTP/1.1\r\nHost: plain.example:8080\r\nCookie: top-secret\r\n\r\nprivate body"
        info = self.enrich(tcp(content))
        self.assertEqual(info.destination_domains, ("plain.example",))
        self.assertEqual(info.destination_domain_source, "http_host")
        self.assertNotIn("private", json.dumps(info.json()))
        self.assertNotIn("top-secret", json.dumps(info.json()))

    def test_unknown_traffic_falls_back_to_ip(self):
        info = self.enrich(tcp(b"\x17\x03\x03encrypted"))
        self.assertEqual(info.destination_domains, ())
        self.assertIn(PEER + ":443", packet_line(info))

    def test_invalid_names_and_terminal_control_sequences_rejected(self):
        for value in (b"bad\x1b[2J.example", b"bad\n.example", b"a..example", b"-bad.example", b"1.2.3.4", b"a" * 64 + b".example"):
            self.assertIsNone(hostname(value))
        self.assertIsNone(inspect_prefix(b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n")[1])

    def test_bad_dns_does_not_stop_metadata(self):
        packet = Ether(src=ROUTER, dst=DEVICE.mac) / IP(src="192.0.2.53", dst=DEVICE.ip) / UDP(sport=53, dport=53000) / Raw(b"\xff")
        self.assertEqual(self.enrich(packet).protocol, "UDP")

    def test_oversized_and_conflicting_prefixes_rejected(self):
        prefix = Prefix(100)
        prefix.add(100, b"abc")
        with self.assertRaises(ValueError):
            prefix.add(101, b"different")
        with self.assertRaises(ValueError):
            Prefix(100).add(100, bytes(65537))

    def test_malformed_tls_lengths_ignored(self):
        for content in (b"\x16\x03\x01\xff\xff", b"\x16\x03\x01\x00\x04\x01\xff\xff\xff", hello()[:-2]):
            self.assertIsNone(inspect_prefix(content)[1])

    def test_pcap_end_to_end_logs_domain_without_request_content(self):
        with tempfile.TemporaryDirectory() as temp:
            capture = Path(temp) / "domains.pcap"
            log = Path(temp) / "domains.jsonl"
            wrpcap(str(capture), [dns("candidate.example"), tcp(hello("actual.example")), tcp(b"encrypted-private-payload", incoming=True)])
            result = subprocess.run([sys.executable, "-m", "wifi_watcher", "--read", str(capture), "--target", DEVICE.ip, "--log", str(log), "--plain"], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            text = log.read_text()
            packets = [json.loads(line) for line in text.splitlines() if json.loads(line)["type"] == "packet"]
            self.assertEqual(packets[1]["destination_domains"], ["actual.example"])
            self.assertEqual(packets[2]["source_domains"], ["actual.example"])
            self.assertEqual(packets[1]["destination_domain_source"], "tls_sni")
            self.assertNotIn("encrypted-private-payload", text)
            self.assertIn("actual.example:443", result.stdout)


if __name__ == "__main__":
    unittest.main()
