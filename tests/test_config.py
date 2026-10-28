import json
import tempfile
import unittest
from ipaddress import IPv4Network
from pathlib import Path
from unittest.mock import Mock, patch

from wifi_watcher.config import router_credentials
from wifi_watcher.network import Device, Network
from wifi_watcher.router import DhcpClient
from wifi_watcher.worker import Worker


class ConfigTests(unittest.TestCase):
    def test_loads_credentials_and_rejects_invalid_config_without_secret_in_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text(json.dumps({"router": {"username": " admin ", "password": "secret"}}))
            self.assertEqual(router_credentials(path), {"username": "admin", "password": "secret"})
            for value in ('{"router":{"password":"secret"}}', '{"router":[]}', 'secret', 'null'):
                path.write_text(value)
                with self.assertRaises(ValueError) as error:
                    router_credentials(path)
                self.assertNotIn("secret", str(error.exception))

    def test_scan_automatically_reads_dhcp_names(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", IPv4Network("192.168.0.0/24"), "192.168.0.1")
        device = Device("192.168.0.100", "02:00:00:00:00:50")
        worker = Worker(Mock())
        with patch("wifi_watcher.worker.network_info", return_value=network), \
                patch("wifi_watcher.worker.discover", return_value=[device]), \
                patch("wifi_watcher.worker.read_clients", return_value=[DhcpClient(device.mac, "Pixel", device.ip)]) as read:
            worker.command({"op": "scan", "interface": "en0", "router": {"username": "admin", "password": "admin"}})
        read.assert_called_once_with(network.gateway, "admin", "admin")
        message = json.loads(worker.connection.sendall.call_args.args[0])
        self.assertEqual(message["devices"][0]["name"], "Pixel")

    def test_router_failure_keeps_discovered_devices_and_does_not_expose_secret(self):
        network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", IPv4Network("192.168.0.0/24"), "192.168.0.1")
        device = Device("192.168.0.100", "02:00:00:00:00:50")
        worker = Worker(Mock())
        with patch("wifi_watcher.worker.network_info", return_value=network), \
                patch("wifi_watcher.worker.discover", return_value=[device]), \
                patch("wifi_watcher.worker.read_clients", side_effect=OSError("secret")):
            worker.command({"op": "scan", "interface": "en0", "router": {"username": "admin", "password": "secret"}})
        message = json.loads(worker.connection.sendall.call_args.args[0])
        self.assertEqual(message["devices"][0]["mac"], device.mac)
        self.assertTrue(message["warning"])
        self.assertNotIn("secret", json.dumps(message))
