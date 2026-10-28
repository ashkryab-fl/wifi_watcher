"""Privileged capture helper. The GUI stays unprivileged and owns the log database."""

import argparse
import json
import os
import queue
import select
import signal
import socket
import time
import uuid
from dataclasses import asdict, replace
from pathlib import Path

from .capture import Capture
from .domains import DomainTracker
from .https import Proxy
from .metadata import packet_info
from .network import discover, network_info
from .router import attach_names, read_clients


class Worker:
    def __init__(self, connection):
        self.connection = connection
        self.network = None
        self.devices = []
        self.capture = None
        self.session = None
        self.packets = queue.Queue(maxsize=8192)
        self.domains = DomainTracker()
        self.dropped = 0
        self.last_heartbeat = time.monotonic()
        self.running = True
        self.cleanup_errors = []
        self.proxy = None
        self.starting_local = False

    def send(self, value):
        self.connection.sendall((json.dumps(value, ensure_ascii=False) + "\n").encode())

    def receive_packet(self, packet):
        info = packet_info(packet, self.capture.device) if self.capture else None
        if info:
            info = self.domains.enrich(packet, info)
            try:
                self.packets.put_nowait(info.json())
            except queue.Full:
                self.dropped += 1

    def flush(self):
        self.flush_https()
        batch = []
        while len(batch) < 200:
            try:
                batch.append(self.packets.get_nowait())
            except queue.Empty:
                break
        if batch:
            self.send({"event": "packets", "session": self.session, "packets": batch, "dropped": self.dropped})

    def flush_https(self, limit=16):
        if self.proxy and self.session:
            for _ in range(limit):
                try:
                    flow = self.proxy.events.get_nowait()
                except queue.Empty:
                    break
                self.send({"event": "http_flow", "session": self.session, "flow": flow,
                           "dropped": self.proxy.dropped})

    def stop(self, reason=None):
        self.starting_local = False
        errors = []
        if self.capture:
            try:
                errors = self.capture.close()
            except Exception as error:
                errors.append(str(error))
            finally:
                self.capture = None
        if self.proxy:
            try:
                self.proxy.close()
                self.flush_https(limit=128)
            except Exception as error:
                errors.append(str(error))
            finally:
                self.proxy = None
        self.cleanup_errors = errors
        while not self.packets.empty():
            self.flush()
        if self.session:
            self.send({"event": "stopped", "session": self.session, "errors": errors,
                       "reason": reason, "dropped": self.dropped})
        self.session = None
        return errors

    def command(self, message):
        operation = message.get("op")
        if operation == "heartbeat":
            self.last_heartbeat = time.monotonic()
        elif operation == "scan":
            if self.capture:
                raise ValueError("Спочатку від’єднай поточний девайс.")
            self.network = network_info(message["interface"], message.get("gateway") or None)
            self.devices = discover(self.network)
            warning = None
            if message.get("router"):
                try:
                    credentials = message["router"]
                    self.devices = attach_names(self.devices, read_clients(
                        self.network.gateway, credentials["username"], credentials["password"]))
                except Exception:
                    # Device discovery stays usable if the router refuses its
                    # optional DHCP table. Never include credentials in errors.
                    warning = "Імена недоступні. Перевір доступ до роутера в config.json."
            self.send({"event": "devices", "network": {**asdict(self.network), "subnet": str(self.network.subnet)},
                       "devices": [asdict(device) for device in self.devices], "warning": warning})
        elif operation == "names":
            if not self.network or self.capture:
                raise ValueError("Спочатку знайди девайси та від’єднай захоплення.")
            self.devices = attach_names(self.devices, read_clients(self.network.gateway, message["username"], message["password"]))
            self.send({"event": "devices", "network": {**asdict(self.network), "subnet": str(self.network.subnet)},
                       "devices": [asdict(device) for device in self.devices]})
        elif operation == "start":
            if self.capture:
                raise ValueError("Заверши попереднє підключення.")
            if message.get("interface"):
                self.network = network_info(message["interface"], message.get("gateway") or None)
            if not self.network:
                raise ValueError("Спочатку знайди девайси.")
            # Reconnect by MAC, never by a possibly reassigned DHCP address.
            fresh = discover(self.network)
            mac = message.get("mac")
            if not mac:
                previous = next((d for d in self.devices if d.ip == message["ip"]), None)
                mac = previous.mac if previous else None
            device = next((d for d in fresh if d.mac == mac), None)
            if device:
                previous = next((d for d in self.devices if d.mac == mac), None)
                device = replace(device, name=(previous.name if previous else message.get("name", "")))
            gateway = next((d for d in fresh if d.ip == self.network.gateway), None)
            if device is None or device.ip == self.network.gateway:
                raise ValueError("Обраний девайс зараз недоступний. Перевір Wi-Fi девайса та натисни «Підключити» ще раз.")
            relay = device.ip != self.network.ip if message.get("relay") == "auto" else bool(message.get("relay"))
            https = message.get("https")
            local_https = bool(https) and device.ip == self.network.ip
            if https and not relay and not local_https:
                raise ValueError("HTTPS для іншого LAN-девайса потребує relay.")
            if relay and (device.ip == self.network.ip or gateway is None or
                          device.mac in (self.network.mac, gateway.mac) or gateway.mac == self.network.mac):
                raise ValueError("Для relay потрібні окремі MAC девайса, роутера та цього Mac. Для самого Mac обери пасивний режим.")
            self.devices = [device if d.mac == device.mac else d for d in fresh]
            self.domains, self.dropped = DomainTracker(), 0
            self.cleanup_errors = []
            self.session = str(uuid.uuid4())
            self.capture = Capture(self.network, device, gateway, relay, self.receive_packet)
            # Persist the session before the first packet batch can reach the GUI.
            self.send({"event": "session", "session": self.session, "device": asdict(device),
                       "mode": "HTTPS LOCAL" if local_https else "HTTPS IPv4" if https else "RELAY IPv4" if relay else "PASSIVE"})
            try:
                if local_https:
                    self.proxy = Proxy(https["binary"], https["directory"], mode="local")
                    self.starting_local = True
                    self.send({"event": "starting_local", "message":
                               "При першому запуску дозволь мережеве розширення Mitmproxy Redirector "
                               "у системних параметрах macOS. Після підключення відкрий сайт заново."})
                    self.proxy.start(wait=False)
                    return
                elif https:
                    self.proxy = Proxy(https["binary"], https["directory"])
                    self.proxy.start()
                    self.capture.intercept_port = self.proxy.port
                self.capture.start()
            except BaseException as error:
                self.stop(str(error))
                raise
            self.send({"event": "started", "session": self.session, "device": asdict(device)})
        elif operation == "disconnect":
            self.stop()
        elif operation == "shutdown":
            self.stop()
            self.running = False
        else:
            raise ValueError("Невідома команда.")

    def poll_local_start(self):
        if self.starting_local and self.proxy.startup_ready():
            self.capture.start()  # Passive packet metadata; no ARP/pf redirection.
            self.starting_local = False
            self.send({"event": "started", "session": self.session,
                       "device": asdict(self.capture.device)})

    def run(self):
        buffer = b""
        self.send({"event": "ready"})
        try:
            while self.running:
                readable, _, _ = select.select([self.connection], [], [], 0.1)
                if readable:
                    data = self.connection.recv(65536)
                    if not data:
                        break
                    buffer += data
                    if len(buffer) > 131072:
                        raise ValueError("Завелика команда.")
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        try:
                            self.command(json.loads(line))
                        except Exception as error:
                            if self.capture:
                                self.stop(str(error))
                            message = str(error)
                            if self.cleanup_errors:
                                message += " Відновлення не підтверджено: " + "; ".join(self.cleanup_errors)
                            self.send({"event": "error", "message": message})
                # Heartbeats come from the GUI event loop, so a frozen UI also stops capture.
                if time.monotonic() - self.last_heartbeat > 5 and not select.select([self.connection], [], [], 0)[0]:
                    raise RuntimeError("Інтерфейс не відповідав понад 5 секунд. Захоплення безпечно зупинено.")
                if self.capture:
                    try:
                        if self.proxy:
                            self.proxy.check()
                        if self.starting_local:
                            self.poll_local_start()
                        else:
                            self.capture.check()
                    except Exception as error:
                        # Restore first, but keep the helper and discovered devices
                        # available for reconnecting without another authorization.
                        self.stop(str(error))
                self.flush()
        except Exception as error:
            if self.capture:
                self.stop(str(error))
            try:
                message = str(error)
                if self.cleanup_errors:
                    message += " Відновлення не підтверджено: " + "; ".join(self.cleanup_errors)
                self.send({"event": "error", "message": message})
            except OSError:
                pass
        finally:
            # Recovery precedes all socket/log notifications, which may fail on a dead GUI.
            if self.capture:
                try:
                    self.stop()
                except OSError:
                    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--token-file", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        return 1

    def terminate(*_):
        raise KeyboardInterrupt

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, terminate)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(0.5)
    try:
        connection.connect(args.socket)
        token = Path(args.token_file).read_text().strip()
        connection.sendall((json.dumps({"token": token}) + "\n").encode())
        Worker(connection).run()
    except (KeyboardInterrupt, ConnectionError, OSError):
        pass
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
