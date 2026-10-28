import argparse
import json
import os
import queue
import signal
import sys
import threading
import time
from getpass import getpass
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, PcapReader

from .capture import Capture
from .display import Display
from .domains import DomainTracker
from .metadata import Statistics, packet_info
from .network import Device, discover, interfaces, network_info
from .router import RouterError, attach_names, read_clients


def parser():
    result = argparse.ArgumentParser(
        description="Список девайсів та моніторинг метаданих пакетів у тестовій LAN.",
        epilog="Звичайний Wi-Fi не показує весь чужий трафік. --relay пересилає IPv4 через цей Mac.",
    )
    result.add_argument("-i", "--interface", help="LAN-інтерфейс, наприклад en0")
    result.add_argument("--gateway", help="IPv4 роутера, наприклад 192.168.0.1")
    result.add_argument("--subnet", help="Підмережа пошуку, наприклад 192.168.0.0/24")
    result.add_argument("--target", help="IP девайса; без цього параметра буде список для вибору")
    result.add_argument("--list", action="store_true", help="Лише знайти та показати девайси")
    result.add_argument("--no-router-names", action="store_true", help="Не запитувати вхід до роутера для DHCP-імен")
    modes = result.add_mutually_exclusive_group()
    modes.add_argument("--relay", action="store_true", help="Активне ARP-пересилання IPv4 вибраного девайса")
    modes.add_argument("--passive", action="store_true", help="Лише пакети, які вже видно інтерфейсу")
    offline = result.add_mutually_exclusive_group()
    offline.add_argument("--demo", action="store_true", help="Синтетичний трафік, без доступу до мережі/sudo")
    offline.add_argument("--read", type=Path, help="Прочитати PCAP/PCAPNG без доступу до мережі/sudo; потрібен --target")
    result.add_argument("--duration", type=float, help="Зупинитися через N секунд")
    result.add_argument("--log", type=Path, help="Явно записати метадані у вказаний JSONL-файл")
    result.add_argument("--no-log", action="store_true", help="Не записувати журнал")
    result.add_argument("--plain", action="store_true", help="Рядок на пакет замість оновлення екрана")
    result.add_argument("--gui", action="store_true", help="Відкрити графічний інтерфейс")
    return result


def choose(items, title, label):
    if not items:
        raise ValueError(f"{title}: немає доступних варіантів.")
    print(title)
    for index, item in enumerate(items, 1):
        print(f"  {index:2}. {label(item)}")
    while True:
        choice = input("Номер (q — вийти): ").strip()
        if choice.lower() == "q":
            raise KeyboardInterrupt
        if choice.isdigit() and 1 <= int(choice) <= len(items):
            return items[int(choice) - 1]
        print("Введи номер зі списку.")


def router_names(devices, network, disabled=False):
    if disabled or not sys.stdin.isatty():
        return devices
    print(f"Імена девайсів із DHCP роутера {network.gateway} (вхід лише для читання списку).")
    username = input("Логін вебінтерфейсу роутера (Enter — пропустити): ").strip()
    if not username:
        return devices
    password = getpass("Пароль вебінтерфейсу роутера: ")
    try:
        clients = read_clients(network.gateway, username, password)
        named = attach_names(devices, clients)
        print(f"Імена DHCP отримано для {sum(bool(device.name) for device in named)} девайсів.")
        return named
    except RouterError as error:
        print(f"{error} Продовжую з IP/MAC без DHCP-імен.")
        return devices
    finally:
        password = None


def device_label(device):
    return f"{device.name or 'Без імені':24} {device.ip:16} {device.mac}  {device.label}"


def live_setup(args):
    if sys.platform not in ("darwin", "linux"):
        raise ValueError("Підтримуються macOS та Linux.")
    if os.geteuid() != 0:
        print("Для ARP-пошуку й захоплення потрібен sudo; пароль вводиться лише локально в sudo.", flush=True)
        os.execvp("sudo", ["sudo", sys.executable, "-m", "wifi_watcher", *sys.argv[1:]])
    available = interfaces()
    interface = args.interface
    if not interface:
        interface = available[0] if len(available) == 1 else choose(available, "LAN-інтерфейси:", str)
    network = network_info(interface, args.gateway, args.subnet)
    print(f"Мережа: {network.subnet} · {interface} · цей комп’ютер {network.ip} · роутер {network.gateway}")
    print("ARP-пошук активних IPv4-девайсів…")
    devices = discover(network)
    devices = router_names(devices, network, args.no_router_names)
    print("Знайдені ARP-відповіді; сплячі/ізольовані девайси можуть бути відсутні.")
    if args.list:
        for device in devices:
            print(device_label(device))
        return None
    if args.target:
        device = next((d for d in devices if d.ip == args.target), None)
        if device is None:
            raise ValueError("Обраний IP не відповів на ARP. Перевір IP, інтерфейс та client isolation.")
    else:
        device = choose(devices, "Обери девайс:", device_label)
    if device.ip == network.gateway:
        raise ValueError("Обери клієнтський девайс: роутер пересилає трафік багатьох клієнтів.")
    relay = args.relay
    if not args.relay and not args.passive and device.ip != network.ip:
        print("p — пасивно (звичайний Wi-Fi може не показати трафік девайса).")
        print("r — тимчасово пересилати IPv4 через цей Mac; можливий вплив на з’єднання.")
        while True:
            mode = input("Режим [p/r], q — вийти: ").strip().lower()
            if mode == "q":
                raise KeyboardInterrupt
            if mode in ("p", "r"):
                relay = mode == "r"
                break
    gateway = next((d for d in devices if d.ip == network.gateway), None)
    if relay:
        if device.ip == network.ip or device.mac == network.mac:
            raise ValueError("Для цього комп’ютера використовуй --passive.")
        if gateway is None or gateway.mac in (device.mac, network.mac):
            raise ValueError("Не вдалося незалежно визначити MAC девайса та роутера; relay скасовано.")
        print("Relay: лише IPv4 між вибраним девайсом і роутером; IPv6 та прямий LAN-трафік не охоплено.")
        print("Зупиняй через Ctrl+C: програма надішле справжні ARP-відповідності обом сторонам.")
    else:
        print("Пасивний режим: видно лише пакети, які мережа передає на цей інтерфейс.")
    return network, device, gateway, relay


def demo_packets(device):
    yield Ether(src="02:00:00:00:00:01", dst=device.mac) / IP(src="192.0.2.53", dst=device.ip) / UDP(sport=53, dport=53000) / DNS(
        qr=1, qd=DNSQR(qname="demo.example"),
        an=DNSRR(rrname="demo.example", ttl=60, rdata="198.51.100.10"),
    )
    for index in range(24):
        incoming = index % 3 != 0
        peer = "198.51.100.10" if index % 4 else "192.0.2.53"
        peer_port = 443 if index % 4 else 53
        src, dst = (peer, device.ip) if incoming else (device.ip, peer)
        sport, dport = (peer_port, 51000) if incoming else (51000, peer_port)
        packet = Ether(
            src="02:00:00:00:00:01" if incoming else device.mac,
            dst=device.mac if incoming else "02:00:00:00:00:01",
        ) / IP(src=src, dst=dst) / (
            TCP(sport=sport, dport=dport, flags="A") if peer_port == 443 else UDP(sport=sport, dport=dport)
        ) / bytes(1200 if incoming else 100)
        packet.time = time.time()
        yield packet


def monitor(args, device, mode, setup=None):
    events = queue.Queue(maxsize=4096)
    stats = Statistics()
    domains = DomainTracker()
    stop = threading.Event()
    done = threading.Event()
    source_error = []
    omitted = 0
    capture = None
    source = None
    log = None
    path = None
    started = time.monotonic()
    display = None
    final_error = None

    def receive(packet):
        nonlocal omitted
        info = packet_info(packet, device)
        if info:
            info = domains.enrich(packet, info)
            if not setup:
                # Offline reading can pause; a live relay must never wait for UI.
                while not stop.is_set():
                    try:
                        events.put(info, timeout=0.1)
                        return
                    except queue.Full:
                        continue
                return
            try:
                events.put_nowait(info)
            except queue.Full:
                omitted += 1

    def read_source():
        try:
            if args.demo:
                for packet in demo_packets(device):
                    if stop.is_set():
                        break
                    receive(packet)
                    stop.wait(0.08)
            else:
                with PcapReader(str(args.read)) as reader:
                    for packet in reader:
                        if stop.is_set():
                            break
                        receive(packet)
        except Exception as error:
            source_error.append(error)
        finally:
            done.set()

    def record(value):
        if log:
            log.write(json.dumps(value, ensure_ascii=False) + "\n")

    def consume(info):
        stats.add(info, time.monotonic())
        record({"type": "packet", **info.json()})
        display.packet(info)

    try:
        if args.log and not args.no_log:
            path = args.log.absolute()
            new_parent = not path.parent.exists()
            path.parent.mkdir(parents=True, exist_ok=True)
            if new_parent and os.geteuid() == 0 and os.environ.get("SUDO_UID"):
                os.chown(path.parent, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
            # Refuse overwrites and symlinks. This matters when invoked via sudo.
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            if os.geteuid() == 0 and os.environ.get("SUDO_UID"):
                os.fchown(descriptor, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
            log = os.fdopen(descriptor, "w", encoding="utf-8")
            record({"type": "session", "started_at": datetime.now(timezone.utc).isoformat(),
                    "target_ip": device.ip, "target_mac": device.mac, "mode": mode,
                    "target_name": device.name or None,
                    "target_name_source": "router_dhcp" if device.name else None,
                    "domain_sources": ["dns", "tls_sni", "tls_sni_outer", "http_host"],
                    "byte_basis": "captured link-layer frame length, excluding uncaptured wire overhead"})
        display = Display(device, mode, path, args.plain)
        if setup:
            network, _, gateway, relay = setup
            capture = Capture(network, device, gateway, relay, receive)
            capture.start()
        else:
            source = threading.Thread(target=read_source, daemon=True)
            source.start()
        last_render = 0
        while True:
            if capture:
                capture.check()
            now = time.monotonic()
            if args.duration and now - started >= args.duration:
                break
            try:
                consume(events.get(timeout=0.1))
            except queue.Empty:
                pass
            if now - last_render >= 0.5:
                display.render(stats, now, now - started, omitted)
                if log:
                    log.flush()
                last_render = now
            if not setup and done.is_set() and events.empty():
                if source_error:
                    raise source_error[0]
                break
    except KeyboardInterrupt:
        pass
    except Exception as error:
        final_error = error
    finally:
        # Complete ARP restoration even if Ctrl+C is pressed a second time.
        old_handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            stop.set()
            if capture:
                errors = capture.close()
                if errors:
                    print("Не всі ARP-відповідності відновлено: " + "; ".join(sorted(set(errors))), file=sys.stderr)
                    print("Перепідключи девайс до Wi-Fi для відновлення з’єднання.", file=sys.stderr)
                    final_error = final_error or RuntimeError("Помилка відновлення ARP.")
            if source:
                source.join(timeout=2)
            if display:
                while not events.empty():
                    try:
                        consume(events.get_nowait())
                    except Exception as error:
                        final_error = final_error or error
                        break
                now = time.monotonic()
                display.render(stats, now, now - started, omitted, final=True)
                if log:
                    try:
                        record({"type": "summary", "packets": dict(stats.packets),
                                "bytes": dict(stats.bytes), "protocols": dict(stats.protocols),
                                "omitted_metadata": omitted, "elapsed_seconds": now - started,
                                "forwarded_packets": capture.forwarded if capture and capture.relay else None,
                                "error": str(final_error) if final_error else None})
                    except Exception as error:
                        final_error = final_error or error
        finally:
            if log:
                try:
                    log.close()
                except OSError as error:
                    final_error = final_error or error
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
    if final_error:
        raise final_error


def main(argv=None):
    arguments = parser()
    args = arguments.parse_args(argv)
    if args.duration is not None and (not 0 < args.duration < float("inf")):
        arguments.error("--duration має бути скінченним додатним числом")
    if args.target:
        try:
            args.target = str(ip_address(args.target))
        except ValueError:
            arguments.error("--target має бути IP-адресою")
    if args.read and not args.target:
        arguments.error("Для --read потрібен --target IP")
    if (args.demo or args.read) and (args.relay or args.list):
        arguments.error("--demo/--read несумісні з --relay/--list")
    if args.log and args.no_log:
        arguments.error("Обери --log або --no-log")
    if args.gui:
        from .gui import main as gui_main
        return gui_main(args.interface, args.gateway, args.demo)
    def terminate(*_):
        raise KeyboardInterrupt

    previous_term = signal.signal(signal.SIGTERM, terminate)
    try:
        if args.demo or args.read:
            device = Device("192.168.0.50", "02:00:00:00:00:50", "demo") if args.demo else Device(args.target, "")
            monitor(args, device, "DEMO · синтетичні дані" if args.demo else "PCAP")
        else:
            setup = live_setup(args)
            if setup:
                monitor(args, setup[1], "RELAY IPv4" if setup[3] else "PASSIVE", setup)
        return 0
    except (KeyboardInterrupt, EOFError):
        print("\nЗавершено.")
        return 0
    except Exception as error:
        print(f"Помилка: {error}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_term)
