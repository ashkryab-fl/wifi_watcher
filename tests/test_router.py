import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch
from urllib.error import HTTPError, URLError

from wifi_watcher.cli import device_label, monitor, parser, router_names
from wifi_watcher.display import Display
from wifi_watcher.metadata import Statistics
from wifi_watcher.network import Device, Network
from wifi_watcher.router import NoRedirect, RouterError, attach_names, parse_clients, read_clients


CLIENTS = """[1,1,0,0,0,0]0
hostName=Mac
MACAddress=12:56:60:6A:58:44
IPAddress=192.168.0.108
leaseTimeRemaining=5680
[1,2,0,0,0,0]0
hostName=Pixel-6-Pro
MACAddress=F2-4C-5B-62-C8-A0
IPAddress=192.168.0.100
leaseTimeRemaining=5790
[error]0
"""

MAC = Device("192.168.0.108", "12:56:60:6a:58:44", "цей комп’ютер")
PIXEL = Device("192.168.0.100", "f2:4c:5b:62:c8:a0")
NETWORK = Network("en0", MAC.ip, MAC.mac, None, "192.168.0.1")


class RouterTests(unittest.TestCase):
    def test_parse_names_from_dhcp_table(self):
        clients = parse_clients(CLIENTS.replace("\n", "\r\n"))
        self.assertEqual([(c.name, c.mac, c.ip) for c in clients], [
            ("Mac", MAC.mac, MAC.ip), ("Pixel-6-Pro", PIXEL.mac, PIXEL.ip),
        ])

    def test_match_by_mac_even_after_ip_change(self):
        pixel = Device("192.168.0.150", PIXEL.mac)
        named = attach_names([MAC, pixel], parse_clients(CLIENTS))
        self.assertEqual([d.name for d in named], ["Mac", "Pixel-6-Pro"])
        self.assertEqual(named[1].ip, "192.168.0.150")
        self.assertEqual(named[0].label, "цей комп’ютер")

    def test_no_match_by_ip_if_mac_differs(self):
        different = Device(PIXEL.ip, "02:00:00:00:00:66")
        self.assertEqual(attach_names([different], parse_clients(CLIENTS)), [different])

    def test_empty_table_is_success(self):
        self.assertEqual(parse_clients("[error]0\r\n"), [])

    def test_login_html_and_error_code_rejected(self):
        for text in ('<html><input type="password"></html>', '[error]71015', CLIENTS.replace('[error]0', '')):
            with self.subTest(text=text[:20]):
                with self.assertRaises(RouterError):
                    parse_clients(text)

    def test_terminal_controls_sanitized_in_host_name(self):
        clients = parse_clients(CLIENTS.replace("Pixel-6-Pro", "Pixel\x1b[2J\t\u202ePro"))
        self.assertNotIn("\x1b", clients[1].name)
        self.assertNotIn("\t", clients[1].name)
        self.assertNotIn("\u202e", clients[1].name)

    def test_read_only_request_matches_router_javascript_protocol(self):
        opener = Mock()
        response = MagicMock()
        response.__enter__.return_value.read.return_value = CLIENTS.encode()
        opener.open.return_value = response
        with patch("wifi_watcher.router.build_opener", return_value=opener):
            clients = read_clients(NETWORK.gateway, "admin", "local-secret")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://192.168.0.1/cgi?5")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.data, b"[LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n")
        auth = base64.b64encode(b"admin:local-secret").decode()
        self.assertEqual(request.get_header("Cookie"), "Authorization=Basic " + auth)
        self.assertEqual(request.get_header("Referer"), "http://192.168.0.1/")
        self.assertEqual(len(clients), 2)
        self.assertEqual(opener.open.call_count, 1)

    def test_auth_errors_not_retried_or_exposed(self):
        opener = Mock()
        opener.open.side_effect = HTTPError("http://192.168.0.1/cgi?5", 403, "Forbidden", {}, None)
        with patch("wifi_watcher.router.build_opener", return_value=opener):
            with self.assertRaises(RouterError) as error:
                read_clients(NETWORK.gateway, "admin", "local-secret")
        self.assertNotIn("local-secret", str(error.exception))
        self.assertEqual(opener.open.call_count, 1)

    def test_network_failure_has_fallback_error(self):
        opener = Mock()
        opener.open.side_effect = URLError("connection refused")
        with patch("wifi_watcher.router.build_opener", return_value=opener):
            with self.assertRaises(RouterError):
                read_clients(NETWORK.gateway, "admin", "local-secret")

    def test_redirects_are_not_followed(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://elsewhere.invalid"))

    def test_blank_login_skips_password_and_network_request(self):
        with patch("wifi_watcher.cli.sys.stdin", Mock(isatty=lambda: True)), \
                patch("builtins.input", return_value=""), \
                patch("wifi_watcher.cli.getpass") as password, \
                patch("wifi_watcher.cli.read_clients") as request, \
                contextlib.redirect_stdout(io.StringIO()):
            devices = router_names([MAC, PIXEL], NETWORK)
        self.assertEqual(devices, [MAC, PIXEL])
        password.assert_not_called()
        request.assert_not_called()

    def test_interactive_login_fetches_names_without_printing_password(self):
        output = io.StringIO()
        with patch("wifi_watcher.cli.sys.stdin", Mock(isatty=lambda: True)), \
                patch("builtins.input", return_value="admin"), \
                patch("wifi_watcher.cli.getpass", return_value="local-secret"), \
                patch("wifi_watcher.cli.read_clients", return_value=parse_clients(CLIENTS)), \
                contextlib.redirect_stdout(output):
            devices = router_names([MAC, PIXEL], NETWORK)
        self.assertEqual(devices[1].name, "Pixel-6-Pro")
        self.assertNotIn("local-secret", output.getvalue())
        self.assertIn("Pixel-6-Pro", device_label(devices[1]))

    def test_named_device_in_dashboard_and_session_log(self):
        named = attach_names([PIXEL], parse_clients(CLIENTS))[0]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            Display(named, "TEST", None, plain=True).render(Statistics(), 0, 0, final=True)
        self.assertIn("Pixel-6-Pro", output.getvalue())
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "test.jsonl"
            args = parser().parse_args(["--demo", "--duration", ".01", "--log", str(log), "--plain"])
            with contextlib.redirect_stdout(io.StringIO()):
                monitor(args, named, "TEST")
            session = json.loads(log.read_text().splitlines()[0])
            self.assertEqual(session["target_name"], "Pixel-6-Pro")
            self.assertEqual(session["target_name_source"], "router_dhcp")


if __name__ == "__main__":
    unittest.main()
