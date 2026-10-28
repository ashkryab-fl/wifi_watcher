import io
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scapy.all import ARP, Ether
from wifi_watcher.capture import Capture
from wifi_watcher.network import Device, Network

from wifi_watcher.guardian import watch
from wifi_watcher.worker import Worker


class RecoveryTests(unittest.TestCase):
    def test_repeated_cleanup_does_not_hide_a_failed_restoration(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        capture = Capture(network, Device("192.168.0.100", "02:00:00:00:00:50"), Device("192.168.0.1", "02:00:00:00:00:01"), True, Mock())
        capture.socket = Mock()
        capture.socket.send.side_effect = OSError("interface disconnected")
        capture.poisoned = True
        with patch("wifi_watcher.capture.time.sleep"):
            first = capture.close()
        self.assertTrue(first)
        self.assertEqual(capture.close(), first)

    def test_disappearing_device_stops_after_three_missed_probes(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        capture = Capture(network, Device("192.168.0.100", "02:00:00:00:00:50"), Device("192.168.0.1", "02:00:00:00:00:01"), True, Mock())
        capture.stopped = Mock()
        capture.stopped.wait.side_effect = [False, False, False, True]
        with patch("wifi_watcher.capture.srp", return_value=([], [])):
            capture.probe()
        self.assertIn("не відповідає", str(capture.error))
        capture.stopped.set.assert_called_once()

    def test_changed_mac_stops_before_more_poisoning(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        capture = Capture(network, Device("192.168.0.100", "02:00:00:00:00:50"), Device("192.168.0.1", "02:00:00:00:00:01"), True, Mock())
        capture.stopped = Mock()
        capture.stopped.wait.return_value = False
        reply = Ether(src="02:00:00:00:00:66", dst=network.mac) / ARP(
            op=2, psrc=capture.device.ip, hwsrc="02:00:00:00:00:66", pdst=network.ip, hwdst=network.mac)
        with patch("wifi_watcher.capture.srp", return_value=([(None, reply)], [])):
            capture.probe()
        self.assertIn("змінився", str(capture.error))
        self.assertIn(capture.device.ip, str(capture.error))
        self.assertIn(capture.device.mac, str(capture.error))
        self.assertIn("02:00:00:00:00:66", str(capture.error))
        capture.stopped.set.assert_called_once()

    def test_live_traffic_prevents_false_arp_probe_disconnect(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        capture = Capture(network, Device("192.168.0.100", "02:00:00:00:00:50"), Device("192.168.0.1", "02:00:00:00:00:01"), True, Mock())
        capture.peer_activity = {capture.device.mac: 95, capture.gateway.mac: 95}
        capture.stopped = Mock()
        capture.stopped.wait.side_effect = [False, False, False, True]
        with patch("wifi_watcher.capture.srp", return_value=([], [])), \
                patch("wifi_watcher.capture.time.monotonic", return_value=100):
            capture.probe()
        self.assertIsNone(capture.error)
        capture.stopped.set.assert_not_called()

    def test_probe_ignores_own_interception_announcements(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        capture = Capture(network, Device("192.168.0.100", "02:00:00:00:00:50"), Device("192.168.0.1", "02:00:00:00:00:01"), True, Mock())
        capture.stopped = Mock()
        capture.stopped.wait.side_effect = [False, False, False, True]
        capture.peer_activity = {capture.device.mac: 99, capture.gateway.mac: 99}

        def respond(requests, **_):
            # Scapy matches these outgoing announcements to our requests by
            # ARP sender IP, despite their different Ethernet/ARP recipients.
            return ([(request, reply) for request in requests for reply in capture.arp_pair()
                     if reply.answers(request)], [])

        with patch("wifi_watcher.capture.srp", side_effect=respond) as send, \
                patch("wifi_watcher.capture.time.monotonic", return_value=100):
            capture.probe()
        self.assertIsNone(capture.error)
        capture.stopped.set.assert_not_called()
        for call in send.call_args_list:
            self.assertIn("not ether src " + network.mac, call.kwargs["filter"])
            self.assertIn("ether dst " + network.mac, call.kwargs["filter"])

    def test_broadcast_retry_ignores_own_interception_announcements(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        capture = Capture(network, Device("192.168.0.100", "02:00:00:00:00:50"), Device("192.168.0.1", "02:00:00:00:00:01"), True, Mock())
        capture.stopped = Mock()
        capture.stopped.wait.side_effect = [False, False, False, True]

        def respond(requests, **_):
            if requests[0].dst != "ff:ff:ff:ff:ff:ff":
                return [], []
            return ([(request, reply) for request in requests for reply in capture.arp_pair()
                     if reply.answers(request)], [])

        with patch("wifi_watcher.capture.srp", side_effect=respond):
            capture.probe()
        self.assertIn("не відповідає", str(capture.error))
        self.assertNotIn("змінився", str(capture.error))

    def test_probe_keeps_genuine_replies_among_announcements(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        capture = Capture(network, Device("192.168.0.100", "02:00:00:00:00:50"), Device("192.168.0.1", "02:00:00:00:00:01"), True, Mock())
        requests = [Ether(src=network.mac, dst=peer.mac) / ARP(
            psrc=network.ip, hwsrc=network.mac, pdst=peer.ip) for peer in (capture.device, capture.gateway)]
        replies = [(request, Ether(src=peer.mac, dst=network.mac) / ARP(
            op=2, psrc=peer.ip, hwsrc=peer.mac, pdst=network.ip, hwdst=network.mac))
            for request, peer in zip(requests, (capture.device, capture.gateway))]
        replies += [(None, reply) for reply in capture.arp_pair()]
        # A different recipient's reply is not evidence of our peer changing.
        replies.append((None, Ether(src="02:00:00:00:00:66", dst=network.mac) / ARP(
            op=2, psrc=capture.device.ip, hwsrc="02:00:00:00:00:66",
            pdst=capture.gateway.ip, hwdst=capture.gateway.mac)))
        with patch("wifi_watcher.capture.srp", return_value=(replies, [])):
            self.assertEqual(capture.probe_answers(requests), {
                capture.device.ip: capture.device.mac, capture.gateway.ip: capture.gateway.mac})

    def test_broadcast_retry_still_stops_on_genuine_mac_change(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        capture = Capture(network, Device("192.168.0.100", "02:00:00:00:00:50"), Device("192.168.0.1", "02:00:00:00:00:01"), True, Mock())
        capture.stopped = Mock()
        capture.stopped.wait.return_value = False
        reply = Ether(src="02:00:00:00:00:66", dst=network.mac) / ARP(
            op=2, psrc=capture.gateway.ip, hwsrc="02:00:00:00:00:66", pdst=network.ip, hwdst=network.mac)

        def respond(requests, **_):
            return ([(None, reply)], []) if requests[0].dst == "ff:ff:ff:ff:ff:ff" else ([], [])

        with patch("wifi_watcher.capture.srp", side_effect=respond):
            capture.probe()
        self.assertIn("змінився", str(capture.error))
        self.assertIn(capture.gateway.ip, str(capture.error))
        capture.stopped.set.assert_called_once()

    def test_traffic_from_only_one_peer_does_not_hide_missing_other_peer(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        capture = Capture(network, Device("192.168.0.100", "02:00:00:00:00:50"), Device("192.168.0.1", "02:00:00:00:00:01"), True, Mock())
        capture.peer_activity = {capture.device.mac: 99, capture.gateway.mac: 80}
        capture.stopped = Mock()
        capture.stopped.wait.side_effect = [False, False, False, True]
        with patch("wifi_watcher.capture.srp", return_value=([], [])), \
                patch("wifi_watcher.capture.time.monotonic", return_value=100):
            capture.probe()
        self.assertIn("не відповідає", str(capture.error))

    def test_broadcast_retry_recovers_peers_ignoring_unicast_arp(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        capture = Capture(network, Device("192.168.0.100", "02:00:00:00:00:50"), Device("192.168.0.1", "02:00:00:00:00:01"), True, Mock())
        capture.stopped = Mock()
        capture.stopped.wait.side_effect = [False, False, False, True]
        replies = [(None, Ether(src=d.mac, dst=network.mac) / ARP(
            op=2, psrc=d.ip, hwsrc=d.mac, pdst=network.ip, hwdst=network.mac))
            for d in (capture.device, capture.gateway)]
        def respond(packets, **_):
            return (replies, []) if packets[0].dst == "ff:ff:ff:ff:ff:ff" else ([], [])
        with patch("wifi_watcher.capture.srp", side_effect=respond) as send:
            capture.probe()
        self.assertTrue(any(call.args[0][0].dst == "ff:ff:ff:ff:ff:ff" for call in send.call_args_list))
        self.assertIsNone(capture.error)
        capture.stopped.set.assert_not_called()

    def test_capture_failure_restores_and_keeps_helper_available(self):
        server, client = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(client.close)
        client.settimeout(2)
        worker = Worker(server)
        worker.session = "failed-session"
        capture = worker.capture = Mock()
        capture.check.side_effect = RuntimeError("test peer unavailable")
        capture.close.return_value = []
        thread = threading.Thread(target=worker.run)
        thread.start()
        try:
            buffer = b""
            while b'"stopped"' not in buffer:
                buffer += client.recv(4096)
            stopped = next(json.loads(line) for line in buffer.splitlines() if json.loads(line)["event"] == "stopped")
            self.assertIn("peer unavailable", stopped["reason"])
            capture.close.assert_called_once()
            self.assertTrue(thread.is_alive())
            client.sendall(b'{"op":"shutdown"}\n')
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        finally:
            client.close()
            thread.join(timeout=2)

    def test_fresh_helper_reconnects_same_mac_after_dhcp_address_change(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        device = Device("192.168.0.105", "02:00:00:00:00:50")
        router = Device("192.168.0.1", "02:00:00:00:00:01")
        stranger = Device("192.168.0.100", "02:00:00:00:00:99")
        worker = Worker(Mock())
        with patch("wifi_watcher.worker.network_info", return_value=network), \
                patch("wifi_watcher.worker.discover", return_value=[device, router, stranger]), \
                patch("wifi_watcher.worker.Capture") as capture:
            worker.command({"op": "start", "ip": "192.168.0.100", "mac": device.mac,
                            "name": "Pixel", "interface": "en0", "gateway": router.ip, "relay": True})
        selected = capture.call_args.args[1]
        self.assertEqual(selected.mac, device.mac)
        self.assertEqual(selected.ip, "192.168.0.105")
        self.assertEqual(selected.name, "Pixel")
        capture.return_value.start.assert_called_once()

    def test_reconnect_never_substitutes_another_device_at_old_ip(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        worker = Worker(Mock())
        with patch("wifi_watcher.worker.network_info", return_value=network), \
                patch("wifi_watcher.worker.discover", return_value=[Device("192.168.0.100", "02:00:00:00:00:99")]), \
                patch("wifi_watcher.worker.Capture") as capture:
            with self.assertRaisesRegex(ValueError, "недоступний"):
                worker.command({"op": "start", "ip": "192.168.0.100", "mac": "02:00:00:00:00:50",
                                "interface": "en0", "relay": True})
        capture.assert_not_called()

    def test_automatic_mode_uses_passive_for_this_mac_and_relay_for_other_device(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", None, "192.168.0.1")
        local = Device(network.ip, network.mac)
        remote = Device("192.168.0.100", "02:00:00:00:00:50")
        router = Device(network.gateway, "02:00:00:00:00:01")
        for selected, relay in ((local, False), (remote, True)):
            with self.subTest(ip=selected.ip), \
                    patch("wifi_watcher.worker.network_info", return_value=network), \
                    patch("wifi_watcher.worker.discover", return_value=[local, remote, router]), \
                    patch("wifi_watcher.worker.Capture") as capture:
                Worker(Mock()).command({"op": "start", "ip": selected.ip, "mac": selected.mac,
                                        "interface": "en0", "relay": "auto"})
                self.assertIs(capture.call_args.args[3], relay)

    def pipe(self):
        reader, writer = os.pipe()
        source, sink = os.fdopen(reader, "rb", buffering=0), os.fdopen(writer, "wb", buffering=0)
        self.addCleanup(source.close)
        self.addCleanup(sink.close)
        return source, sink

    def test_guardian_eof_restores_mapping(self):
        source, sink = self.pipe()
        sink.close()
        restore = Mock(return_value=[])
        self.assertEqual(watch(source, restore), [])
        restore.assert_called_once()

    def test_clean_disarm_does_not_duplicate_recovery(self):
        source, sink = self.pipe()
        sink.write(b"alive\ndisarm\n")
        restore = Mock(return_value=[])
        watch(source, restore)
        restore.assert_not_called()

    def test_expired_lease_stops_poisoner_before_recovery(self):
        source, sink = self.pipe()
        actions = []
        watch(source, lambda: actions.append("restore") or [], timeout=.05,
              terminate=lambda: actions.append("terminate"))
        self.assertEqual(actions, ["terminate", "restore"])

    def test_gui_socket_loss_closes_capture(self):
        server, client = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(client.close)
        worker = Worker(server)
        capture = worker.capture = Mock()
        capture.close.return_value = []
        thread = threading.Thread(target=worker.run)
        thread.start()
        client.recv(4096)  # ready
        client.close()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        capture.close.assert_called_once()

    def test_stalled_gui_heartbeat_closes_capture(self):
        server, client = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(client.close)
        worker = Worker(server)
        capture = worker.capture = Mock()
        capture.close.return_value = []
        worker.last_heartbeat = time.monotonic() - 10
        worker.run()
        capture.close.assert_called_once()

    def test_disconnect_recovers_before_acknowledging(self):
        actions = []
        connection = Mock()
        connection.sendall.side_effect = lambda data: actions.append(json.loads(data))
        worker = Worker(connection)
        worker.session = "test"
        worker.capture = Mock()
        worker.capture.close.side_effect = lambda: actions.append("restore") or []
        worker.command({"op": "disconnect"})
        self.assertEqual(actions[0], "restore")
        self.assertEqual(actions[1]["event"], "stopped")
        self.assertIsNone(worker.capture)

    def test_sigkill_of_parent_still_triggers_independent_recovery(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "restored"
            guardian_code = "from wifi_watcher.guardian import watch; import sys; from pathlib import Path; watch(sys.stdin.buffer, lambda: Path(sys.argv[1]).write_text('restored') or [])"
            parent_code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True); p.stdin.write(b'alive\\n'); p.stdin.flush(); print('ready',flush=True); time.sleep(30)"
            parent = subprocess.Popen([sys.executable, "-c", parent_code, guardian_code, str(marker)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertEqual(parent.stdout.readline().strip(), b"ready")
                os.kill(parent.pid, signal.SIGKILL)
                parent.communicate(timeout=2)
                deadline = time.monotonic() + 3
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(marker.exists(), "independent guardian did not recover after SIGKILL")
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.communicate()


if __name__ == "__main__":
    unittest.main()
