import base64
import gzip
import io
import json
import queue
import subprocess
import tempfile
import unittest
from ipaddress import IPv4Network
from pathlib import Path
from unittest.mock import Mock, patch

try:
    from compression import zstd
except ImportError:
    from backports import zstd

from scapy.all import Ether, IP, TCP

from wifi_watcher.capture import Capture
from wifi_watcher.https import CertificateServer, Proxy, command, executable, prepare_certificate
from wifi_watcher.https_view import body_preview, flow_text
from wifi_watcher.network import Device, Network
from wifi_watcher.store import Store
from wifi_watcher.transparent import TransparentNetwork, redirect_rules
from wifi_watcher.worker import Worker


def fixture(status=None):
    return {"id": "request-1", "ts": 1792062000.0, "host": "api.example", "method": "POST",
            "url": "https://api.example/test?literal=%_", "status": status, "error": None,
            "request": {"headers": [["Content-Type", "application/json"]], "http_version": "HTTP/2",
                        "body": base64.b64encode(b'{"test":true}').decode(), "body_omitted": False},
            "response": None}


class HttpsTests(unittest.TestCase):
    def setUp(self):
        self.network = Network("en0", "192.168.0.108", "02:00:00:00:00:10", IPv4Network("192.168.0.0/24"), "192.168.0.1")
        self.device = Device("192.168.0.50", "02:00:00:00:00:50")
        self.gateway = Device(self.network.gateway, "02:00:00:00:00:01")

    def test_redirect_and_quic_rejection_are_scoped_to_one_device(self):
        rule = redirect_rules(self.network, self.device, 18080)
        self.assertEqual(rule,
            "rdr pass on en0 inet proto tcp from 192.168.0.50 to ! 192.168.0.0/24 port { 80, 443 } -> 127.0.0.1 port 18080\n"
            "block return in quick on en0 inet proto udp from 192.168.0.50 to ! 192.168.0.0/24 port 443\n")
        with self.assertRaises(ValueError):
            redirect_rules(self.network, Device("203.0.113.1", self.device.mac), 18080)
        with self.assertRaises(ValueError):
            redirect_rules(self.network, self.device, 80)

    def test_missing_anchor_fails_before_host_mutation(self):
        with tempfile.TemporaryDirectory() as folder, patch("wifi_watcher.transparent.sys.platform", "darwin"):
            network = TransparentNetwork(self.network, self.device, 18080, Path(folder))
            network.run = Mock(return_value="")
            with self.assertRaisesRegex(RuntimeError, "rdr-anchor"):
                network.start()
            self.assertEqual(network.close(), [])
            network.run.assert_called_once_with("/sbin/pfctl", "-sn")

    def test_missing_filter_anchor_fails_before_host_mutation(self):
        with tempfile.TemporaryDirectory() as folder, patch("wifi_watcher.transparent.sys.platform", "darwin"):
            network = TransparentNetwork(self.network, self.device, 18080, Path(folder))
            network.run = Mock(side_effect=['rdr-anchor "com.apple/*" all\n', ''])
            with self.assertRaisesRegex(RuntimeError, "filter anchor"):
                network.start()
            self.assertEqual(network.close(), [])
            self.assertEqual([call.args for call in network.run.call_args_list], [
                ("/sbin/pfctl", "-sn"), ("/sbin/pfctl", "-sr")])

    def fake_system(self, fail_load=False):
        calls, values = [], {"net.inet.ip.forwarding": "0", "net.inet.ip.redirect": "1",
                             "net.link.generic.system.hwcksum_rx": "1"}

        def run(*args, input=None):
            calls.append((args, input))
            if args == ("/sbin/pfctl", "-sn"):
                return 'rdr-anchor "com.apple/*" all\n'
            if args == ("/sbin/pfctl", "-sr"):
                return 'anchor "com.apple/*" all\n'
            if args[:2] == ("/usr/sbin/sysctl", "-n"):
                return values[args[2]]
            if args[:2] == ("/usr/sbin/sysctl", "-w"):
                key, value = args[2].split("=")
                values[key] = value
            if args == ("/sbin/pfctl", "-E"):
                return "pf enabled\nToken : 12345"
            if fail_load and args[:2] == ("/sbin/pfctl", "-a") and input:
                raise RuntimeError("load failed")
            return ""

        return calls, values, run

    def test_cleanup_removes_only_owned_anchor_and_restores_sysctls(self):
        with tempfile.TemporaryDirectory() as folder, patch("wifi_watcher.transparent.sys.platform", "darwin"):
            network = TransparentNetwork(self.network, self.device, 18080, Path(folder))
            calls, values, network.run = self.fake_system()
            network.start()
            self.assertEqual(values, {"net.inet.ip.forwarding": "1", "net.inet.ip.redirect": "0",
                                      "net.link.generic.system.hwcksum_rx": "0"})
            self.assertEqual(network.close(), [])
            self.assertEqual(values, {"net.inet.ip.forwarding": "0", "net.inet.ip.redirect": "1",
                                      "net.link.generic.system.hwcksum_rx": "1"})
            self.assertIn((("/sbin/pfctl", "-a", network.anchor, "-f", "-"), ""), calls)
            self.assertIn((("/sbin/pfctl", "-X", "12345"), None), calls)
            self.assertFalse(any("-F" in args or "-d" in args for args, _ in calls))

    def test_existing_software_checksum_setting_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder, patch("wifi_watcher.transparent.sys.platform", "darwin"):
            network = TransparentNetwork(self.network, self.device, 18080, Path(folder))
            calls, values, network.run = self.fake_system()
            values["net.link.generic.system.hwcksum_rx"] = "0"
            network.start()
            self.assertEqual(network.original["net.link.generic.system.hwcksum_rx"], ("0", "0"))
            self.assertEqual(network.close(), [])
            self.assertEqual(values["net.link.generic.system.hwcksum_rx"], "0")
            self.assertFalse(any(args[:2] == ("/usr/sbin/sysctl", "-w")
                                 and args[2].startswith("net.link.generic.system.hwcksum_rx=")
                                 for args, _ in calls))

    def test_checksum_setting_changed_externally_is_not_overwritten_on_cleanup(self):
        with tempfile.TemporaryDirectory() as folder, patch("wifi_watcher.transparent.sys.platform", "darwin"):
            network = TransparentNetwork(self.network, self.device, 18080, Path(folder))
            _, values, network.run = self.fake_system()
            network.start()
            values["net.link.generic.system.hwcksum_rx"] = "1"
            errors = network.close()
            self.assertTrue(any("hwcksum_rx" in error for error in errors))
            self.assertEqual(values["net.link.generic.system.hwcksum_rx"], "1")

    def test_partial_setup_rolls_back_and_does_not_overwrite_external_changes(self):
        with tempfile.TemporaryDirectory() as folder, patch("wifi_watcher.transparent.sys.platform", "darwin"):
            network = TransparentNetwork(self.network, self.device, 18080, Path(folder))
            calls, values, network.run = self.fake_system(fail_load=True)
            with self.assertRaisesRegex(RuntimeError, "load failed"):
                network.start()
            values["net.inet.ip.redirect"] = "1"  # Changed by another process.
            errors = network.close()
            self.assertEqual(values["net.inet.ip.forwarding"], "0")
            self.assertEqual(values["net.link.generic.system.hwcksum_rx"], "1")
            self.assertTrue(any("інший процес" in error for error in errors))
            self.assertFalse(any(args == ("/sbin/pfctl", "-X", "12345") for args, _ in calls))

    def test_transparent_capture_does_not_double_forward_or_double_count_rx(self):
        callback = Mock()
        capture = Capture(self.network, self.device, self.gateway, True, callback)
        capture.intercept_port = 18080
        capture.socket = Mock()
        outgoing = Ether(src=self.device.mac, dst=self.network.mac) / IP(src=self.device.ip, dst="203.0.113.10") / TCP(dport=443)
        original_reply = Ether(src=self.gateway.mac, dst=self.network.mac) / IP(src="203.0.113.10", dst=self.device.ip) / TCP(sport=443)
        kernel_reply = Ether(src=self.network.mac, dst=self.device.mac) / original_reply[IP]
        for frame in (outgoing, original_reply, kernel_reply):
            capture.handle(frame)
        capture.socket.send.assert_not_called()
        self.assertEqual(callback.call_count, 2)
        self.assertEqual(callback.call_args_list[0].args[0], outgoing)
        self.assertEqual(callback.call_args_list[1].args[0], kernel_reply)
        self.assertIn(self.gateway.mac, capture.peer_activity)
        self.assertIsNone(capture.error)

    def test_worker_starts_proxy_before_arp_and_stops_it_after_restore(self):
        events, actions = [], []
        connection = Mock()
        connection.sendall.side_effect = lambda data: events.append(json.loads(data))
        worker = Worker(connection)
        with patch("wifi_watcher.worker.network_info", return_value=self.network), \
                patch("wifi_watcher.worker.discover", return_value=[self.device, self.gateway]), \
                patch("wifi_watcher.worker.Capture") as capture, patch("wifi_watcher.worker.Proxy") as proxy:
            proxy.return_value.start.side_effect = lambda: actions.append("proxy-start")
            proxy.return_value.port = 18080
            proxy.return_value.events = queue.Queue()
            proxy.return_value.close.side_effect = lambda: actions.append("proxy-stop")
            capture.return_value.start.side_effect = lambda: actions.append("arp-start")
            capture.return_value.close.side_effect = lambda: actions.append("arp-restore") or []
            worker.command({"op": "start", "interface": "en0", "mac": self.device.mac, "relay": "auto",
                            "https": {"binary": "/mitmdump", "directory": "/ca"}})
            self.assertEqual(capture.return_value.intercept_port, 18080)
            self.assertEqual(events[0]["mode"], "HTTPS IPv4")
            worker.command({"op": "disconnect"})
        self.assertEqual(actions, ["proxy-start", "arp-start", "arp-restore", "proxy-stop"])
        self.assertEqual(events[-1]["event"], "stopped")

    def test_failed_proxy_start_restores_capture_and_never_starts_arp(self):
        worker = Worker(Mock())
        with patch("wifi_watcher.worker.network_info", return_value=self.network), \
                patch("wifi_watcher.worker.discover", return_value=[self.device, self.gateway]), \
                patch("wifi_watcher.worker.Capture") as capture, patch("wifi_watcher.worker.Proxy") as proxy:
            proxy.return_value.start.side_effect = RuntimeError("proxy failed")
            proxy.return_value.events = queue.Queue()
            capture.return_value.close.return_value = []
            with self.assertRaisesRegex(RuntimeError, "proxy failed"):
                worker.command({"op": "start", "interface": "en0", "mac": self.device.mac, "relay": "auto",
                                "https": {"binary": "/mitmdump", "directory": "/ca"}})
            capture.return_value.start.assert_not_called()
            capture.return_value.close.assert_called_once()
            proxy.return_value.close.assert_called_once()
            self.assertIsNone(worker.capture)
            self.assertIsNone(worker.proxy)

    def test_local_proxy_waits_without_blocking_heartbeats_and_never_redirects_arp(self):
        events = []
        connection = Mock()
        connection.sendall.side_effect = lambda data: events.append(json.loads(data))
        worker = Worker(connection)
        device = Device(self.network.ip, self.network.mac)
        with patch("wifi_watcher.worker.network_info", return_value=self.network), \
                patch("wifi_watcher.worker.discover", return_value=[device]), \
                patch("wifi_watcher.worker.Capture") as capture, patch("wifi_watcher.worker.Proxy") as proxy:
            capture.return_value.device = device
            capture.return_value.close.return_value = []
            proxy.return_value.events = queue.Queue()
            proxy.return_value.startup_ready.return_value = False
            worker.command({"op": "start", "interface": "en0", "mac": device.mac, "relay": "auto",
                            "https": {"binary": "/mitmdump", "directory": "/ca"}})
            proxy.assert_called_once_with("/mitmdump", "/ca", mode="local")
            proxy.return_value.start.assert_called_once_with(wait=False)
            self.assertFalse(capture.call_args.args[3])
            self.assertEqual(events[0]["mode"], "HTTPS LOCAL")
            worker.poll_local_start()
            worker.command({"op": "heartbeat"})
            capture.return_value.start.assert_not_called()
            self.assertNotIn("intercept_port", vars(capture.return_value))
            self.assertFalse(any(event["event"] == "started" for event in events))
            proxy.return_value.startup_ready.return_value = True
            worker.poll_local_start()
            capture.return_value.start.assert_called_once()
            self.assertFalse(worker.starting_local)
            self.assertEqual(events[-1]["event"], "started")
            worker.stop()
            proxy.return_value.close.assert_called_once()

    def test_disconnect_cancels_local_permission_wait(self):
        worker = Worker(Mock())
        device = Device(self.network.ip, self.network.mac)
        with patch("wifi_watcher.worker.network_info", return_value=self.network), \
                patch("wifi_watcher.worker.discover", return_value=[device]), \
                patch("wifi_watcher.worker.Capture") as capture, patch("wifi_watcher.worker.Proxy") as proxy:
            capture.return_value.close.return_value = []
            proxy.return_value.events = queue.Queue()
            worker.command({"op": "start", "interface": "en0", "mac": device.mac, "relay": "auto",
                            "https": {"binary": "/mitmdump", "directory": "/ca"}})
            worker.command({"op": "disconnect"})
            worker.poll_local_start()
            self.assertFalse(worker.starting_local)
            capture.return_value.start.assert_not_called()
            proxy.return_value.close.assert_called_once()

    def test_local_mode_has_no_transparent_tcp_listener(self):
        args = command("/mitmdump", "/ca", mode="local")
        self.assertEqual(args[args.index("--mode") + 1], "local")
        self.assertNotIn("--listen-host", args)
        self.assertNotIn("--listen-port", args)

    def test_proxy_eof_cannot_report_successful_startup(self):
        proxy = Proxy("/mitmdump", "/ca", mode="local")
        proxy.process = Mock(stdout=io.BytesIO(b"extension failed\n"))
        proxy.read()
        self.assertFalse(proxy.ready.is_set())
        with self.assertRaisesRegex(RuntimeError, "extension failed"):
            proxy.startup_ready()

    def test_local_startup_timeout_and_actual_ready_acknowledgement(self):
        proxy = Proxy("/mitmdump", "/ca", mode="local")
        proxy.deadline = 50
        with patch("wifi_watcher.https.time.monotonic", return_value=10):
            self.assertFalse(proxy.startup_ready())
        with patch("wifi_watcher.https.time.monotonic", return_value=51):
            with self.assertRaisesRegex(RuntimeError, "Mitmproxy Redirector"):
                proxy.startup_ready()
        proxy.ready.set()
        self.assertTrue(proxy.startup_ready())

    def test_request_response_update_session_isolation_search_and_clear(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "history.sqlite3")
            store.session("one", {}, "HTTPS IPv4")
            store.session("two", {}, "HTTPS IPv4")
            store.record_http("one", fixture())
            store.record_http("one", fixture(200))
            store.record_http("two", fixture(201))
            self.assertEqual(len(store.http_flows()), 2)
            self.assertEqual(store.http_flows("one")[0]["status"], 200)
            self.assertEqual(len(store.http_flows(search="%_")), 2)
            self.assertEqual(store.http_flows(search="not-found"), [])
            self.assertEqual(store.http_detail("two", "request-1")["status"], 201)
            ca = Path(folder) / "https-ca"
            ca.mkdir()
            (ca / "ca.pem").write_text("keep")
            store.clear_logs()
            self.assertEqual(store.http_flows(), [])
            self.assertTrue((ca / "ca.pem").exists())

    def test_body_preview_handles_json_compression_binary_and_limits(self):
        message = fixture()["request"]
        self.assertIn('"test": true', body_preview(message))
        message["headers"] = [["Content-Encoding", "gzip"]]
        message["body"] = base64.b64encode(gzip.compress(b'{"answer":42}')).decode()
        self.assertIn('"answer": 42', body_preview(message))
        message["body"] = base64.b64encode(gzip.compress(b"x" * 1000000)).decode()
        self.assertIn("перевищує", body_preview(message))
        message["body_omitted"] = True
        self.assertIn("не збережено", body_preview(message))
        self.assertIn("POST https://api.example", flow_text(fixture(200)))

    def test_zstd_preview_decodes_json_and_multiple_frames(self):
        for raw in (zstd.compress(b'{"answer":42}'),
                    zstd.compress(b'{"answer":') + zstd.compress(b'42}')):
            message = {"headers": [["Content-Encoding", "zstd"]],
                       "body": base64.b64encode(raw).decode()}
            self.assertIn('"answer": 42', body_preview(message))

    def test_zstd_preview_bounds_expansion_and_reports_invalid_data(self):
        for content in (b"x" * 65536, b"x" * 65537, b"x" * 1000000):
            message = {"headers": [["Content-Encoding", "zstd"]],
                       "body": base64.b64encode(zstd.compress(content)).decode()}
            result = body_preview(message)
            if len(content) == 65536:
                self.assertEqual(result, content.decode())
            else:
                self.assertIn("перевищує", result)
        for raw in (b"invalid", zstd.compress(b'{"answer":42}')[:-2]):
            message["body"] = base64.b64encode(raw).decode()
            self.assertIn("Не вдалося", body_preview(message))

    def test_incomplete_ca_is_never_silently_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "mitmproxy-ca.pem").write_text("existing private key")
            with self.assertRaisesRegex(ValueError, "Неповний CA"), patch("wifi_watcher.https.subprocess.run") as run:
                prepare_certificate(folder)
            run.assert_not_called()

    def test_certificate_handler_never_serves_private_key_or_arbitrary_paths(self):
        # Invoke the real HTTP handler with in-memory sockets; no server/listener.
        import io
        from unittest.mock import MagicMock
        captured = []
        with patch("wifi_watcher.https.ssl.PEM_cert_to_DER_cert", return_value=b"test-der"), \
                patch("wifi_watcher.https.ThreadingHTTPServer") as server, \
                patch("wifi_watcher.https.threading.Thread"), \
                tempfile.TemporaryDirectory() as folder:
            cert = Path(folder) / "ca.pem"
            cert.write_bytes(b"public-cert")
            download = CertificateServer("192.168.0.108", cert)
            handler = server.call_args.args[1]
            for path in ("/ca.cer", "/ca.mobileconfig", "/mitmproxy-ca.pem", "/../config.json"):
                connection = MagicMock()
                connection.makefile.return_value = io.BytesIO(f"GET {path} HTTP/1.0\r\n\r\n".encode())
                connection.sendall.side_effect = captured.append
                handler(connection, ("192.168.0.50", 1234), Mock())
                response = b"".join(captured)
                captured.clear()
                self.assertIn(b"200 OK" if path.startswith("/ca.") else b"404", response)
                self.assertNotIn(b"PRIVATE KEY", response)
            download.close()


class MitmproxyIntegrationTests(unittest.TestCase):
    """Real mitmdump addon/cert checks, with networking disabled throughout."""
    def test_ca_generation_reuse_and_offline_http_hooks(self):
        try:
            binary = executable()
        except RuntimeError:
            self.skipTest("mitmdump not installed")
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / "ca"
            cert = prepare_certificate(directory)
            original = cert.read_bytes()
            self.assertEqual(prepare_certificate(directory).read_bytes(), original)
            self.assertEqual((directory / "mitmproxy-ca.pem").stat().st_mode & 0o777, 0o600)
            script = Path(folder) / "fixture.py"
            script.write_text('''
from mitmproxy import ctx, http, connection
from mitmproxy.proxy.layers.http import HttpRequestHook, HttpResponseHook
from mitmproxy.proxy.layers.tls import TlsFailedClientHook, TlsFailedServerHook
from types import SimpleNamespace
async def running():
    client = connection.Client(peername=("192.168.0.50", 1234), sockname=("127.0.0.1", 8080))
    flow = http.HTTPFlow(client, connection.Server(address=("203.0.113.10", 443)))
    flow.request = http.Request.make("POST", "https://203.0.113.10/test", b'{"test":true}', {"Content-Type":"application/json"})
    flow.request.headers["Host"] = "api.example"
    await ctx.master.addons.trigger_event(HttpRequestHook(flow))
    flow.response = http.Response.make(200, b'{"ok":true}', {"Content-Type":"application/json"})
    await ctx.master.addons.trigger_event(HttpResponseHook(flow))
    flow.response.raw_content = b'x' * 70000
    for i in range(120):
        flow.response.headers.add('X-Test-' + str(i), 'x' * 1000)
    await ctx.master.addons.trigger_event(HttpResponseHook(flow))
    client.sni = "pinned.example"
    client.error = "certificate verify failed"
    await ctx.master.addons.trigger_event(TlsFailedClientHook(SimpleNamespace(context=SimpleNamespace(client=client), conn=client)))
    server = connection.Server(address=("203.0.113.10", 443))
    server.error = "upstream certificate verify failed"
    await ctx.master.addons.trigger_event(TlsFailedServerHook(SimpleNamespace(context=SimpleNamespace(client=client, server=server), conn=server)))
    h2 = http.HTTPFlow(client, server)
    h2.request = http.Request.make("GET", "https://203.0.113.10/h2")
    h2.request.http_version = "HTTP/2.0"
    h2.request.headers.pop("Host", None)
    h2.request.authority = "h2.example"
    await ctx.master.addons.trigger_event(HttpRequestHook(h2))
''')
            result = subprocess.run(command(binary, directory, prepare=True) + ["-s", str(script)],
                                    input=b"", capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors="replace"))
            records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith(b"{")]
            flows = [record["flow"] for record in records if record.get("type") == "flow"]
            self.assertEqual(len(flows), 6, [(f["method"], f["host"], f["error"]) for f in flows])
            self.assertEqual(flows[0]["host"], "api.example")
            self.assertEqual(flows[0]["url"], "https://api.example/test")
            self.assertEqual(flows[5]["host"], "h2.example")
            self.assertEqual(flows[5]["url"], "https://h2.example/h2")
            captured = Store()
            try:
                captured.session("test", {}, "active")
                for flow in (flows[1], flows[5]):
                    captured.record_http("test", flow)
                self.assertEqual({row["title"] for row in captured.groups(domains_only=True)},
                                 {"api.example", "h2.example"})
                self.assertEqual({row["host"] for row in captured.requests(domains_only=True)},
                                 {"api.example", "h2.example"})
            finally:
                captured.close()
            self.assertIsNone(flows[0]["status"])
            self.assertEqual(flows[1]["status"], 200)
            self.assertEqual(flows[0]["id"], flows[1]["id"])
            self.assertIn('"ok": true', flow_text(flows[1]))
            self.assertTrue(flows[2]["response"]["body_omitted"])
            self.assertTrue(flows[2]["response"]["headers_omitted"])
            self.assertEqual(len(base64.b64decode(flows[2]["response"]["body"])), 65536)
            self.assertEqual(flows[3]["method"], "TLS")
            self.assertIn("certificate", flows[3]["error"])
            self.assertIn("телефоном", flows[3]["error"])
            self.assertEqual(flows[4]["method"], "TLS")
            self.assertIn("сайтом", flows[4]["error"])
            self.assertIn("upstream certificate verify failed", flows[4]["error"])
            self.assertNotEqual(flows[3]["id"], flows[4]["id"])
            self.assertEqual(flows[4]["server"], ["203.0.113.10", 443])
            # Exercise the parent-EOF watchdog with all network listeners off.
            args = command(binary, directory, prepare=True)
            args[args.index("ww_prepare=true")] = "ww_prepare=false"
            stopped = subprocess.run(args, input=b"", capture_output=True, timeout=10)
            self.assertEqual(stopped.returncode, 0, (stopped.stdout + stopped.stderr).decode(errors="replace"))
            self.assertIn(b'"type": "ready"', stopped.stdout)
            # Model an OS approval prompt before running(), without starting any
            # listener or network extension. Parent EOF must cancel setup too.
            blocked = Path(folder) / "blocked_setup.py"
            blocked.write_text('''
import asyncio
from mitmproxy import ctx
def configure(updated):
    async def wait_for_approval():
        await asyncio.Event().wait()
    ctx.master.addons.get("proxyserver").setup_servers = wait_for_approval
''')
            stopped = subprocess.run(args + ["--set", "ww_watch_parent=true", "-s", str(blocked)],
                                     input=b"", capture_output=True, timeout=10)
            self.assertEqual(stopped.returncode, 0, (stopped.stdout + stopped.stderr).decode(errors="replace"))
            self.assertNotIn(b'"type": "ready"', stopped.stdout)


if __name__ == "__main__":
    unittest.main()
