import json
import queue
import socket
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from wifi_watcher.bridge import Bridge
from wifi_watcher.store import Store
from test_history import packet


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.folder.name) / "traffic.sqlite3")
        self.events = queue.Queue()
        self.bridge = Bridge(self.store, self.events)
        self.bridge.thread.start()
        self.client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.client.connect(str(self.bridge.directory / "control.sock"))

    def tearDown(self):
        self.client.close()
        self.bridge.close()
        self.bridge.thread.join(timeout=2)
        self.folder.cleanup()

    def send(self, value):
        self.client.sendall((json.dumps(value) + "\n").encode())

    def wait_for(self, kind):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            value = self.events.get(timeout=2)
            if value.get("event") == kind:
                return value
        self.fail("missing event: " + kind)

    def test_private_authenticated_stream_persists_packets_and_finishes_session(self):
        self.send({"token": self.bridge.token})
        self.send({"event": "session", "session": "s1", "device": {"name": "Pixel"}, "mode": "TEST"})
        self.send({"event": "packets", "session": "s1", "packets": [packet()], "dropped": 0})
        self.wait_for("dirty")
        self.assertEqual(self.store.packets()[0], 1)
        self.send({"event": "stopped", "session": "s1", "errors": []})
        self.wait_for("stopped")
        self.assertIsNotNone(self.store.sessions()[0]["ended"])
        self.assertTrue(self.bridge.authenticated)

    def test_bad_token_cannot_create_session_or_packet_history(self):
        self.send({"token": "wrong"})
        self.wait_for("offline")
        self.assertEqual(self.store.sessions(), [])
        self.assertEqual(self.store.packets()[0], 0)

    def test_http_content_is_persisted_but_gui_events_remain_small(self):
        from test_https import fixture
        self.send({"token": self.bridge.token})
        self.send({"event": "session", "session": "https", "device": {}, "mode": "HTTPS IPv4"})
        self.send({"event": "http_flow", "session": "https", "flow": fixture(200), "dropped": 3})
        event = self.wait_for("https_dirty")
        self.assertEqual(event, {"event": "https_dirty", "dropped": 3})
        self.assertEqual(self.store.http_detail("https", "request-1")["status"], 200)

    def test_broken_http_storage_disconnects_helper_for_network_cleanup(self):
        from test_https import fixture
        self.send({"token": self.bridge.token})
        self.send({"event": "session", "session": "https", "device": {}, "mode": "HTTPS IPv4"})
        self.wait_for("session")
        with patch.object(self.store, "record_http", side_effect=OSError("disk full")):
            self.send({"event": "http_flow", "session": "https", "flow": fixture()})
            self.wait_for("offline")
        self.assertTrue(self.bridge.stopped.is_set())

    def test_disconnect_reason_is_preserved_in_history(self):
        self.send({"token": self.bridge.token})
        self.send({"event": "session", "session": "s1", "device": {}, "mode": "TEST"})
        self.send({"event": "stopped", "session": "s1", "reason": "ARP unavailable", "errors": []})
        self.wait_for("stopped")
        self.assertEqual(self.store.sessions()[0]["error"], "ARP unavailable")

    def test_broken_log_storage_still_disconnects_helper(self):
        self.send({"token": self.bridge.token})
        self.send({"event": "session", "session": "s1", "device": {}, "mode": "TEST"})
        self.wait_for("session")
        with patch.object(self.store, "record", side_effect=OSError("disk full")), \
                patch.object(self.store, "finish", side_effect=OSError("disk full")):
            self.send({"event": "packets", "session": "s1", "packets": [packet()]})
            self.wait_for("offline")
        self.assertTrue(self.bridge.stopped.is_set())
        self.assertIsNone(self.bridge.connection)


if __name__ == "__main__":
    unittest.main()
