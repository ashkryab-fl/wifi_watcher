"""Independent ARP recovery after capture-process death or a stalled event loop."""

import fcntl
import json
import os
import select
import signal
import subprocess
import sys
import time
from dataclasses import asdict
from ipaddress import IPv4Network
from pathlib import Path


def watch(stream, restore, *, timeout=10, terminate=None):
    """EOF/crash/lease expiry restores; only explicit 'disarm' skips recovery."""
    last = time.monotonic()
    buffer = b""
    while True:
        readable, _, _ = select.select([stream], [], [], min(0.25, timeout))
        if readable:
            data = os.read(stream.fileno(), 4096)
            if not data:
                return restore()
            buffer += data
            if len(buffer) > 8192:
                return restore()
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if line == b"disarm":
                    return []
                if line == b"alive":
                    last = time.monotonic()
        if time.monotonic() - last > timeout:
            # Stop the poisoner first, otherwise it could undo our ARP recovery.
            if terminate:
                terminate()
            return restore()


class Guardian:
    def __init__(self, network, device, gateway):
        self.network, self.device, self.gateway = network, device, gateway
        self.process = None
        self.last_pulse = 0
        self.intercept_port = None

    def start(self):
        config = {"network": {**asdict(self.network), "subnet": str(self.network.subnet)},
                  "device": asdict(self.device), "gateway": asdict(self.gateway),
                  "intercept_port": self.intercept_port}
        self.process = subprocess.Popen([sys.executable, "-m", "wifi_watcher.guardian"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, bufsize=0, start_new_session=True)
        self.process.stdin.write((json.dumps(config) + "\n").encode())
        if not select.select([self.process.stdout], [], [], 12 if self.intercept_port else 4)[0]:
            self.process.stdin.close()
            raise RuntimeError("Не запустився процес аварійного відновлення ARP.")
        answer = json.loads(self.process.stdout.readline())
        if not answer.get("ready"):
            raise RuntimeError(answer.get("error", "Не вдалося підготувати відновлення ARP."))
        self.pulse()

    def pulse(self):
        if self.process and time.monotonic() - self.last_pulse >= 0.5:
            if self.process.poll() is not None:
                raise RuntimeError("Процес захисту ARP завершився; захоплення зупинено.")
            self.process.stdin.write(b"alive\n")
            self.last_pulse = time.monotonic()

    def close(self, disarm=False):
        if not self.process:
            return []
        process, self.process = self.process, None
        try:
            # Closing stdin alone requests recovery. Never kill the recovery process.
            if process.stdin.closed:
                process.stdin = None
            output, _ = process.communicate(b"disarm\n" if disarm and process.stdin else None,
                                            timeout=12 if self.intercept_port else 4)
            lines = output.splitlines()
            result = json.loads(lines[-1]) if lines else {}
            if process.returncode or not result.get("done"):
                return ["Не підтверджено завершення процесу відновлення ARP."]
            return result.get("errors", [])
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return ["Процес відновлення ARP не підтвердив результат; перепідключи девайс до Wi-Fi, якщо немає мережі."]


def main():
    from scapy.all import conf
    from .capture import Capture
    from .network import Device, Network

    parent = os.getppid()
    sender = None
    lock = None
    transparent = None
    try:
        config = json.loads(sys.stdin.buffer.readline(65536))
        network = config["network"]
        network["subnet"] = IPv4Network(network["subnet"])
        network = Network(**network)
        device, gateway = Device(**config["device"]), Device(**config["gateway"])
        directory = Path("/var/run/wifi-watcher")
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or directory.stat().st_uid != 0:
            raise ValueError("Недоступний каталог блокування ARP.")
        filename = "".join(c for c in network.interface + "-" + device.mac if c.isalnum() or c in "-_")
        descriptor = os.open(directory / filename, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        lock = os.fdopen(descriptor, "w")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Цей девайс уже перехоплюється іншою копією програми.") from None
        sender = conf.L2socket(iface=network.interface)
        frames = Capture(network, device, gateway, True, None).arp_pair(restore=True)
        if config.get("intercept_port") is not None:
            from .transparent import TransparentNetwork
            transparent = TransparentNetwork(network, device, config["intercept_port"], directory)
            transparent.start()

        def restore():
            errors = []
            for _ in range(5):
                for frame in frames:
                    try:
                        sender.send(frame)
                    except Exception as error:
                        errors.append(str(error))
                time.sleep(0.1)
            return sorted(set(errors))

        def terminate():
            if os.getppid() == parent:
                try:
                    os.kill(parent, signal.SIGTERM)
                    time.sleep(0.3)
                    if os.getppid() == parent:
                        os.kill(parent, signal.SIGKILL)
                except ProcessLookupError:
                    pass

        print(json.dumps({"ready": True}), flush=True)
        # Ignore terminal/group termination so the worker can die and we recover.
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        errors = watch(sys.stdin.buffer, restore, terminate=terminate)
        if transparent:
            errors.extend(transparent.close())
            transparent = None
        print(json.dumps({"done": True, "errors": errors}), flush=True)
    except Exception as error:
        errors = transparent.close() if transparent else []
        transparent = None
        print(json.dumps({"ready": False, "error": str(error) + ("; " + "; ".join(errors) if errors else "")}), flush=True)
        return 1
    finally:
        if transparent:
            transparent.close()
        if sender:
            sender.close()
        if lock:
            lock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
