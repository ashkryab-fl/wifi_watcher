"""mitmdump lifecycle, public certificate delivery, and bounded flow IPC."""

import json
import os
import plistlib
import pwd
import queue
import shutil
import socket
import ssl
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ADDON = Path(__file__).with_name("https_addon.py")
CA_DIR = Path(__file__).resolve().parent.parent / "logs" / "https-ca"
PUBLIC_CERT = "mitmproxy-ca-cert.pem"


def executable():
    for candidate in (shutil.which("mitmdump"), "/opt/homebrew/bin/mitmdump", "/usr/local/bin/mitmdump"):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return str(Path(candidate).resolve())
    raise RuntimeError("Встанови mitmproxy: brew install --cask mitmproxy, потім перезапусти програму.")


def command(binary, directory, *, prepare=False, port=0, mode="transparent"):
    if mode not in ("transparent", "local"):
        raise ValueError("Невідомий режим HTTPS-проксі.")
    args = [binary, "-q", "--set", f"confdir={directory}",
            "--set", "flow_detail=0", "--set", "stream_large_bodies=64k", "-s", str(ADDON)]
    if prepare:
        args += ["--set", "server=false", "--set", "ww_prepare=true"]
    elif mode == "local":
        args += ["--mode", "local", "--set", "ww_watch_parent=true"]
    else:
        args += ["--mode", "transparent", "--listen-host", "127.0.0.1", "--listen-port", str(port),
                 "--set", "ww_watch_parent=true"]
    return args


def prepare_certificate(directory=CA_DIR):
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("Каталог сертифіката не може бути посиланням.")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    if any(file.is_symlink() for file in directory.iterdir()):
        raise ValueError("Файли CA не можуть бути посиланнями.")
    cert = directory / PUBLIC_CERT
    key = directory / "mitmproxy-ca.pem"
    if cert.exists() != key.exists():
        raise ValueError("Неповний CA: віднови сертифікат і ключ із резервної копії. Автоматична заміна CA вимкнена.")
    if not cert.exists() or not key.exists():
        result = subprocess.run(command(executable(), directory, prepare=True), input=b"",
                                capture_output=True, timeout=20)
        if result.returncode or not cert.is_file() or not key.is_file():
            raise RuntimeError("Не вдалося створити CA mitmproxy: " + result.stderr.decode(errors="replace")[-1000:])
    for file in directory.iterdir():
        if file.is_symlink():
            raise ValueError("Файли CA не можуть бути посиланнями.")
        if file.is_file():
            os.chmod(file, 0o600)
    # Validate that this is a certificate before offering it to the device.
    ssl.PEM_cert_to_DER_cert(cert.read_text())
    return cert


class Proxy:
    def __init__(self, binary, directory, *, mode="transparent"):
        self.binary, self.directory = binary, Path(directory)
        self.mode = mode
        self.process = None
        self.events = queue.Queue(maxsize=128)
        self.ready = threading.Event()
        self.dropped = 0
        self.diagnostic = ""
        self.failure = None
        self.thread = None
        self.port = None
        self.deadline = None

    def read(self):
        try:
            stream = self.process.stdout
            for line in iter(lambda: stream.readline(1048577), b""):
                if len(line) > 1048576:
                    raise ValueError("Завелике повідомлення HTTPS-проксі.")
                try:
                    value = json.loads(line)
                except ValueError:
                    self.diagnostic = line.decode(errors="replace")[-1000:]
                    continue
                if value.get("type") == "ready":
                    self.ready.set()
                elif value.get("type") == "flow":
                    try:
                        self.events.put_nowait(value["flow"])
                    except queue.Full:
                        self.dropped += 1
        except Exception as error:
            self.failure = self.diagnostic = str(error)
        finally:
            # EOF is a failure, never a successful startup acknowledgement.
            if self.process is not None:
                self.failure = self.failure or "HTTPS-проксі закрив канал повідомлень. " + self.diagnostic

    def start(self, *, wait=True):
        if self.mode == "local" and wait:
            raise ValueError("Локальний HTTPS запускається асинхронно, щоб очікувати дозвіл macOS.")
        if not (self.directory / PUBLIC_CERT).is_file() or not (self.directory / "mitmproxy-ca.pem").is_file():
            raise ValueError("Спочатку натисни «Сертифікат HTTPS…» для створення CA.")
        if self.mode != "local":
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                self.port = reservation.getsockname()[1]
        options = {}
        if self.mode == "local" and os.geteuid() == 0:
            # The network extension's approval UI belongs to the GUI user's
            # login session. The CA is prepared by that unprivileged user.
            owner = pwd.getpwuid(self.directory.stat().st_uid)
            options = {"user": owner.pw_uid, "group": owner.pw_gid,
                       "extra_groups": os.getgrouplist(owner.pw_name, owner.pw_gid),
                       "env": {**os.environ, "HOME": owner.pw_dir,
                               "USER": owner.pw_name, "LOGNAME": owner.pw_name}}
        # Root is required for mitmproxy's macOS original-destination lookup.
        # No sudoers edits, shell interpolation, or global CA installation.
        self.process = subprocess.Popen(command(self.binary, self.directory, port=self.port, mode=self.mode),
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, start_new_session=True, **options)
        self.deadline = time.monotonic() + (120 if self.mode == "local" else 8)
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()
        if not wait:
            return
        if not self.ready.wait(8) or self.process.poll() is not None:
            self.close()
            raise RuntimeError("HTTPS-проксі не запустився. " + self.diagnostic)
        # The addon ready event precedes opening the listening sockets in some
        # mitmproxy versions, so also verify the listener before changing ARP.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            self.check()
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=.15):
                    return
            except OSError:
                time.sleep(.05)
        self.close()
        raise RuntimeError("HTTPS-проксі не відкрив локальний порт.")

    def startup_ready(self):
        """Polled by the worker so heartbeats/disconnect work during OS prompts."""
        self.check()
        if self.ready.is_set():
            return True
        if time.monotonic() >= self.deadline:
            raise RuntimeError("Не вдалося запустити HTTPS на цьому Mac. Дозволь Mitmproxy Redirector "
                               "у системних параметрах macOS та підключись повторно. " + self.diagnostic)
        return False

    def check(self):
        if self.failure:
            raise RuntimeError("Помилка журналу HTTPS: " + self.failure)
        if self.process and self.process.poll() is not None:
            raise RuntimeError("HTTPS-проксі завершився. " + self.diagnostic)

    def close(self):
        if not self.process:
            return
        process, self.process = self.process, None
        if process.stdin:
            process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        if self.thread:
            self.thread.join(timeout=1)
        if process.stdout:
            process.stdout.close()


class CertificateServer:
    """Serve only the public CA/profile, never the CA directory or private key."""
    def __init__(self, address, certificate):
        pem = Path(certificate).read_bytes()
        der = ssl.PEM_cert_to_DER_cert(pem.decode())
        profile = plistlib.dumps({
            "PayloadType": "Configuration", "PayloadVersion": 1,
            "PayloadIdentifier": "local.wifi-watcher.ca", "PayloadUUID": str(uuid.uuid4()),
            "PayloadDisplayName": "WiFi Watcher HTTPS CA",
            "PayloadContent": [{"PayloadType": "com.apple.security.root", "PayloadVersion": 1,
                                "PayloadIdentifier": "local.wifi-watcher.ca.root", "PayloadUUID": str(uuid.uuid4()),
                                "PayloadDisplayName": "WiFi Watcher CA", "PayloadContent": der}],
        })

        class Handler(BaseHTTPRequestHandler):
            timeout = 5

            def do_GET(self):
                resources = {
                    "/ca.cer": (der, "application/x-x509-ca-cert"),
                    "/ca.pem": (pem, "application/x-pem-file"),
                    "/ca.mobileconfig": (profile, "application/x-apple-aspen-config"),
                    "/": (b'<a href="/ca.cer">Android / CA certificate</a><br>'
                           b'<a href="/ca.mobileconfig">iPhone / iPad profile</a>', "text/html; charset=utf-8"),
                }
                if self.path not in resources:
                    self.send_error(404)
                    return
                data, content_type = resources[self.path]
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer((address, 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://{address}:{self.server.server_port}/"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)
