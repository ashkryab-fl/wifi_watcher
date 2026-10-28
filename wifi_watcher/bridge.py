"""Private local IPC and system authorization for the graphical application."""

import hmac
import json
import os
import queue
import secrets
import select
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


class Bridge:
    def __init__(self, store, events):
        self.store, self.events = store, events
        self.directory = Path(tempfile.mkdtemp(prefix="ww-"))
        self.token = secrets.token_hex(32)
        token_file = self.directory / "token"
        descriptor = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as output:
            output.write(self.token)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.directory / "control.sock"))
        self.server.listen(1)
        self.server.settimeout(0.25)
        self.connection = None
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.process = None
        self.current_session = None
        self.authenticated = False
        self.thread = threading.Thread(target=self.reader, daemon=True)

    def launch(self):
        root = Path(__file__).resolve().parent.parent
        arguments = [sys.executable, "-m", "wifi_watcher.worker", "--socket",
                     str(self.directory / "control.sock"), "--token-file", str(self.directory / "token")]
        if os.geteuid() == 0:
            command = arguments
        elif sys.platform == "darwin":
            shell = "cd " + shlex.quote(str(root)) + " && exec " + shlex.join(arguments)
            command = ["/usr/bin/osascript", "-e", "do shell script " + json.dumps(shell, ensure_ascii=False) + " with administrator privileges"]
        else:
            command = ["pkexec", *arguments]
        self.process = subprocess.Popen(command, cwd=root, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.PIPE, start_new_session=True)
        self.thread.start()

    def send(self, message):
        with self.lock:
            if not self.connection:
                raise ConnectionError("Помічник захоплення ще не підключений.")
            self.connection.sendall((json.dumps(message, ensure_ascii=False) + "\n").encode())

    def event(self, event):
        kind = event.get("event")
        if kind == "session":
            self.current_session = event["session"]
            self.store.session(event["session"], event["device"], event["mode"])
        elif kind == "packets":
            self.store.record(event["session"], event["packets"])
            self.events.put({"event": "dirty", "dropped": event.get("dropped", 0)})
            return
        elif kind == "http_flow":
            self.store.record_http(event["session"], event["flow"])
            self.events.put({"event": "https_dirty", "dropped": event.get("dropped", 0)})
            return
        elif kind == "stopped":
            detail = [event.get("reason"), *event.get("errors", [])]
            self.store.finish(event["session"], "; ".join(value for value in detail if value) or None)
            self.current_session = None
        self.events.put(event)

    def reader(self):
        authenticated = False
        buffer = b""
        try:
            while not self.stopped.is_set() and self.connection is None:
                try:
                    candidate, _ = self.server.accept()
                    candidate.settimeout(0.5)
                    self.connection = candidate
                except socket.timeout:
                    if self.process and self.process.poll() is not None:
                        detail = self.process.stderr.read(4096).decode(errors="replace").strip()
                        raise RuntimeError(detail or "Дозвіл на захоплення не надано.")
            while not self.stopped.is_set() and self.connection:
                if not select.select([self.connection], [], [], 0.25)[0]:
                    continue
                data = self.connection.recv(262144)
                if not data:
                    break
                buffer += data
                if len(buffer) > 2097152:
                    raise ValueError("Завелика відповідь помічника.")
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    message = json.loads(line)
                    if not authenticated:
                        if not hmac.compare_digest(str(message.get("token", "")), self.token):
                            raise ValueError("Не підтверджено локального помічника.")
                        authenticated = True
                        self.authenticated = True
                    else:
                        self.event(message)
        except Exception as error:
            self.events.put({"event": "error", "message": str(error)})
        finally:
            try:
                if self.current_session:
                    self.store.finish(self.current_session, "З’єднання з інтерфейсом перервано.")
            except Exception as error:
                self.events.put({"event": "error", "message": f"Не вдалося завершити журнал: {error}"})
            finally:
                # Even a full/broken database must close IPC and trigger recovery.
                self.close()
                self.events.put({"event": "offline"})

    def close(self):
        self.stopped.set()
        connected = self.connection is not None
        if self.connection:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            self.connection = None
        self.server.close()
        if not connected and not self.authenticated and self.process and self.process.poll() is None:
            # Cancel an authorization dialog if the window closed before a helper connected.
            try:
                self.process.terminate()
            except OSError:
                pass
        # The root helper sees EOF and restores ARP. It is never killed here.
        shutil.rmtree(self.directory, ignore_errors=True)
