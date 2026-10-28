import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from unittest.mock import Mock, patch

from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, Dot1Q, Ether, Raw, wrpcap
from scapy.layers.inet6 import IPv6ExtHdrFragment, IPv6ExtHdrHopByHop

from wifi_watcher.capture import Capture, relay_frame
from wifi_watcher.cli import monitor, parser
from wifi_watcher.metadata import Statistics, packet_info
from wifi_watcher.network import Device, Network, discover, network_info


LOCAL = "02:00:00:00:00:10"
TARGET = Device("192.168.0.50", "02:00:00:00:00:50")
GATEWAY = Device("192.168.0.1", "02:00:00:00:00:01")
NETWORK = Network("en0", "192.168.0.10", LOCAL, IPv4Network("192.168.0.0/24"), GATEWAY.ip)


def outbound():
    return Ether(src=TARGET.mac, dst=LOCAL) / IP(src=TARGET.ip, dst="198.51.100.1") / TCP(sport=51000, dport=443) / Raw(b"private body")


def inbound():
    return Ether(src=GATEWAY.mac, dst=LOCAL) / IP(src="198.51.100.1", dst=TARGET.ip) / TCP(sport=443, dport=51000)


class MetadataTests(unittest.TestCase):
    def test_outbound_and_frame_length(self):
        packet = outbound()
        packet.time = 1000.25
        packet.wirelen = 1514
        info = packet_info(packet, TARGET)
        self.assertEqual((info.direction, info.protocol, info.destination_port), ("TX", "TCP", 443))
        self.assertEqual((info.bytes, info.captured_bytes), (1514, len(packet)))
        self.assertEqual(info.timestamp, "1970-01-01T00:16:40.250000+00:00")
        self.assertNotIn("private body", json.dumps(info.json()))

    def test_inbound_by_ip_during_relay(self):
        self.assertEqual(packet_info(inbound(), TARGET).direction, "RX")

    def test_unrelated_packet_ignored(self):
        self.assertIsNone(packet_info(Ether(src=LOCAL, dst=GATEWAY.mac) / IP(src=NETWORK.ip, dst="1.1.1.1"), TARGET))

    def test_passive_ipv6_identified_by_mac(self):
        packet = Ether(src=GATEWAY.mac, dst=TARGET.mac) / IPv6(src="2001:db8::1", dst="2001:db8::50") / UDP(sport=443, dport=50000)
        info = packet_info(packet, TARGET)
        self.assertEqual((info.direction, info.protocol, info.source_port), ("RX", "UDP", 443))

    def test_ipv6_extension_header(self):
        packet = Ether(src=TARGET.mac, dst=LOCAL) / IPv6(src="2001:db8::50", dst="2001:db8::1") / IPv6ExtHdrHopByHop() / TCP(sport=5, dport=443)
        self.assertEqual(packet_info(packet, TARGET).destination_port, 443)

    def test_ipv6_noninitial_fragment_has_no_ports(self):
        packet = Ether(src=TARGET.mac, dst=LOCAL) / IPv6(src="2001:db8::50", dst="2001:db8::1") / IPv6ExtHdrFragment(offset=4) / TCP(sport=5, dport=443)
        info = packet_info(packet, TARGET)
        self.assertEqual(info.protocol, "FRAGMENT")
        self.assertIsNone(info.destination_port)

    def test_ipv4_noninitial_fragment_has_no_ports(self):
        packet = Ether(src=TARGET.mac, dst=LOCAL) / IP(src=TARGET.ip, dst="198.51.100.1", frag=8) / TCP(sport=4, dport=123)
        info = packet_info(packet, TARGET)
        self.assertEqual(info.protocol, "FRAGMENT")
        self.assertIsNone(info.destination_port)

    def test_icmp_quoted_tcp_not_reported_as_tcp(self):
        packet = Ether(src=GATEWAY.mac, dst=LOCAL) / IP(src=GATEWAY.ip, dst=TARGET.ip) / ICMP(type=3) / IP(src=TARGET.ip, dst="198.51.100.1") / TCP(dport=443)
        info = packet_info(packet, TARGET)
        self.assertEqual(info.protocol, "ICMP")
        self.assertEqual(info.source, GATEWAY.ip)
        self.assertIsNone(info.destination_port)

    def test_vlan(self):
        packet = Ether(src=TARGET.mac, dst=LOCAL) / Dot1Q(vlan=20) / IP(src=TARGET.ip, dst="198.51.100.1") / UDP(dport=53)
        self.assertEqual(packet_info(packet, TARGET).protocol, "UDP")

    def test_arp(self):
        packet = Ether(src=TARGET.mac, dst=LOCAL) / ARP(psrc=TARGET.ip, pdst=GATEWAY.ip)
        self.assertEqual(packet_info(packet, TARGET).protocol, "ARP")

    def test_bidirectional_peer_aggregation_and_rate_expiry(self):
        stats = Statistics()
        stats.add(packet_info(outbound(), TARGET), 10)
        stats.add(packet_info(inbound(), TARGET), 10.2)
        self.assertEqual(len(stats.peers), 1)
        self.assertEqual(sum(stats.peer_packets.values()), 2)
        self.assertEqual(sum(stats.rate(10.3).values()), len(outbound()) + len(inbound()))
        self.assertEqual(sum(stats.rate(12).values()), 0)
        self.assertEqual(sum(stats.packets.values()), 2)


class RelayTests(unittest.TestCase):
    def test_forward_both_directions_preserving_ip_bytes(self):
        for packet, mac in ((outbound(), GATEWAY.mac), (inbound(), TARGET.mac)):
            with self.subTest(mac=mac):
                forwarded = relay_frame(packet, LOCAL, TARGET, GATEWAY)
                self.assertEqual(forwarded.src, LOCAL)
                self.assertEqual(forwarded.dst, mac)
                self.assertEqual(bytes(forwarded.payload), bytes(packet.payload))

    def test_reject_other_devices_and_forwarding_loops(self):
        packets = [
            Ether(src=LOCAL, dst=GATEWAY.mac) / outbound()[IP],
            Ether(src="02:00:00:00:00:66", dst=LOCAL) / outbound()[IP],
            Ether(src=TARGET.mac, dst=LOCAL) / IP(src="192.168.0.66", dst="1.1.1.1"),
            Ether(src=GATEWAY.mac, dst=LOCAL) / IP(src="1.1.1.1", dst="192.168.0.66"),
            Ether(src=TARGET.mac, dst=LOCAL) / IPv6(),
            Ether(src=TARGET.mac, dst=LOCAL) / ARP(),
        ]
        for packet in packets:
            self.assertIsNone(relay_frame(packet, LOCAL, TARGET, GATEWAY))

    def test_restore_after_partial_poison_failure(self):
        capture = Capture(NETWORK, TARGET, GATEWAY, True, Mock())
        socket = capture.socket = Mock()
        socket.send.side_effect = [OSError("send failed")] + [None] * 10
        capture.poison()
        self.assertTrue(capture.poisoned)
        self.assertIsInstance(capture.error, OSError)
        with patch("wifi_watcher.capture.time.sleep"):
            errors = capture.close()
        self.assertEqual(errors, [])
        self.assertEqual(socket.send.call_count, 11)
        socket.close.assert_called_once()
        self.assertIsNone(capture.socket)
        self.assertFalse(capture.poisoned)

    def test_restore_real_mac_mappings_before_sniffer_stops(self):
        capture = Capture(NETWORK, TARGET, GATEWAY, True, Mock())
        capture.socket = Mock()
        capture.sniffer = Mock(running=True)
        capture.poisoned = True
        actions = []
        capture.socket.send.side_effect = lambda packet: actions.append(packet)
        capture.sniffer.stop.side_effect = lambda: actions.append("stop")
        with patch("wifi_watcher.capture.time.sleep"):
            capture.close()
        self.assertEqual(actions[-1], "stop")
        self.assertEqual(len(actions), 11)
        for packet in actions[:-1:2]:
            self.assertEqual((packet[ARP].psrc, packet[ARP].hwsrc), (GATEWAY.ip, GATEWAY.mac))
        for packet in actions[1:-1:2]:
            self.assertEqual((packet[ARP].psrc, packet[ARP].hwsrc), (TARGET.ip, TARGET.mac))

    def test_forwarding_error_signals_failure(self):
        capture = Capture(NETWORK, TARGET, GATEWAY, True, Mock())
        capture.socket = Mock()
        capture.socket.send.side_effect = OSError("offline")
        capture.handle(outbound())
        with self.assertRaisesRegex(RuntimeError, "offline"):
            capture.check()
        self.assertEqual(capture.forwarded, 0)
        capture.on_packet.assert_not_called()


class DiscoveryTests(unittest.TestCase):
    def test_ignore_mac_host_route_and_vpn_gateway(self):
        address = lambda value: int(IPv4Address(value))
        routes = [
            (0, 0, "10.0.0.1", "ipsec0", "10.0.0.2", 1),
            (0, 0, GATEWAY.ip, "en0", NETWORK.ip, 1),
            (address("192.168.0.0"), address("255.255.255.0"), "0.0.0.0", "en0", NETWORK.ip, 1),
            (address(NETWORK.ip), 0xffffffff, "0.0.0.0", "en0", NETWORK.ip, 1),
        ]
        with patch("wifi_watcher.network.conf.route.routes", routes), patch("wifi_watcher.network.get_if_addr", return_value=NETWORK.ip), patch("wifi_watcher.network.get_if_hwaddr", return_value=LOCAL):
            network = network_info("en0")
        self.assertEqual(network.subnet, IPv4Network("192.168.0.0/24"))
        self.assertEqual(network.gateway, GATEWAY.ip)

    def test_discovery_only_returns_matched_active_arp_replies(self):
        responses = [
            (Ether()/ARP(pdst=TARGET.ip), Ether()/ARP(psrc=TARGET.ip, hwsrc=TARGET.mac)),
            (Ether()/ARP(pdst=GATEWAY.ip), Ether()/ARP(psrc=GATEWAY.ip, hwsrc=GATEWAY.mac)),
            (Ether()/ARP(pdst="192.168.0.99"), Ether()/ARP(psrc="192.168.0.88", hwsrc=TARGET.mac)),
        ]
        with patch("wifi_watcher.network.srp", return_value=(responses, [])):
            result = discover(NETWORK)
        self.assertEqual({d.ip for d in result}, {TARGET.ip, GATEWAY.ip, NETWORK.ip})


class IntegrationTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "wifi_watcher", *map(str, args)],
                              capture_output=True, text=True, timeout=15)

    def test_pcap_metadata_log_no_payload_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            capture, log = folder / "sample.pcap", folder / "metadata.jsonl"
            wrpcap(str(capture), [outbound(), inbound(), Ether(src=LOCAL, dst=GATEWAY.mac)/IP(src="10.0.0.1", dst="10.0.0.2")])
            result = self.run_cli("--read", capture, "--target", TARGET.ip, "--log", log, "--plain")
            self.assertEqual(result.returncode, 0, result.stderr)
            text = log.read_text()
            events = [json.loads(line) for line in text.splitlines()]
            self.assertEqual([e["direction"] for e in events if e["type"] == "packet"], ["TX", "RX"])
            self.assertNotIn("private body", text)
            self.assertEqual(events[-1]["packets"], {"TX": 1, "RX": 1})
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            self.assertIn("198.51.100.1:443", result.stdout)
            second = self.run_cli("--read", capture, "--target", TARGET.ip, "--log", log)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(log.read_text(), text)

    def test_existing_and_dangling_symlink_logs_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "must-not-create.jsonl"
            link = Path(temp) / "link.jsonl"
            link.symlink_to(target)
            result = self.run_cli("--demo", "--log", link, "--duration", ".01")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(target.exists())

    def test_offline_large_capture_has_no_queue_loss(self):
        with tempfile.TemporaryDirectory() as temp:
            capture = Path(temp) / "many.pcap"
            log = Path(temp) / "many.jsonl"
            wrpcap(str(capture), [outbound()] * 4500)
            result = self.run_cli("--read", capture, "--target", TARGET.ip, "--log", log, "--plain")
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(log.read_text().splitlines()[-1])
            self.assertEqual(summary["packets"]["TX"], 4500)
            self.assertEqual(summary["omitted_metadata"], 0)

    def test_invalid_offline_arguments(self):
        result = self.run_cli("--read", "missing.pcap")
        self.assertEqual(result.returncode, 2)
        result = self.run_cli("--demo", "--relay")
        self.assertEqual(result.returncode, 2)

    def test_interrupt_calls_capture_cleanup(self):
        args = parser().parse_args(["--no-log", "--plain"])
        fake = Mock()
        fake.check.side_effect = KeyboardInterrupt
        fake.close.return_value = []
        with patch("wifi_watcher.cli.Capture", return_value=fake), contextlib.redirect_stdout(io.StringIO()):
            monitor(args, TARGET, "RELAY", (NETWORK, TARGET, GATEWAY, True))
        fake.start.assert_called_once()
        fake.close.assert_called_once()

    def test_capture_failure_also_calls_cleanup(self):
        args = parser().parse_args(["--no-log", "--plain"])
        fake = Mock()
        fake.check.side_effect = RuntimeError("forwarding failed")
        fake.close.return_value = []
        with patch("wifi_watcher.cli.Capture", return_value=fake), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "forwarding failed"):
                monitor(args, TARGET, "RELAY", (NETWORK, TARGET, GATEWAY, True))
        fake.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
