import shutil
import sys
from datetime import datetime

from .metadata import endpoint, human_bytes


def packet_line(info):
    local_time = datetime.fromisoformat(info.timestamp).astimezone().strftime("%H:%M:%S.%f")[:-3]
    return (
        f"{local_time} {info.direction} {info.protocol:8} "
        f"{endpoint(info.source, info.source_port, info.source_domains, info.source_domain_source)} → "
        f"{endpoint(info.destination, info.destination_port, info.destination_domains, info.destination_domain_source)}  {info.bytes} B"
    )


class Display:
    def __init__(self, device, mode, path, plain=False):
        self.device, self.mode, self.path = device, mode, path
        self.interactive = sys.stdout.isatty() and not plain

    def packet(self, info):
        if not self.interactive:
            print(packet_line(info), flush=True)

    def render(self, stats, now, elapsed, dropped=0, final=False):
        rates = stats.rate(now)
        title = f"WiFi Watcher · {self.mode} · {self.device.ip} · {self.device.mac or 'MAC невідомий'}"
        if self.device.name:
            title = f"WiFi Watcher · {self.device.name} · {self.mode} · {self.device.ip} · {self.device.mac}"
        last = f"{now - stats.last_time:.0f} с тому" if stats.last_time is not None else "ще немає"
        lines = [
            title,
            f"Час: {elapsed:.1f} с | Пакети: {sum(stats.packets.values())} | Останній: {last}",
            f"TX: {human_bytes(stats.bytes['TX'])} / {stats.packets['TX']} pkt / {human_bytes(rates['TX'])}/s",
            f"RX: {human_bytes(stats.bytes['RX'])} / {stats.packets['RX']} pkt / {human_bytes(rates['RX'])}/s",
            "Протоколи: " + (", ".join(f"{p} {n}" for p, n in stats.protocols.most_common()) or "—"),
            f"Журнал метаданих: {self.path or 'вимкнено'}",
            f"Пропущено метаданих у черзі: {dropped} (не є лічильником втрат мережі)",
            "", "Віддалені домени / адреси / порти (TX + RX, за обсягом):",
        ]
        for key, size in stats.peers.most_common(8):
            proto, address, port, domains, evidence = key
            lines.append(f"  {proto:8} {endpoint(address, port, domains, evidence):42} {human_bytes(size):>12}  {stats.peer_packets[key]} pkt")
        if stats.other_peers:
            lines.append(f"  Інші адреси понад ліміт 10 000: {human_bytes(stats.other_peers)}")
        lines.extend(["", "Останні пакети (час комп’ютера):"])
        lines.extend(packet_line(info) for info in stats.recent)
        if not stats.recent:
            lines.append("  Очікування. Нуль пакетів не доводить, що девайс не має трафіку.")
        lines.extend(["", "Готово." if final else "Ctrl+C — завершити та відновити ARP (якщо ввімкнено relay)."])
        if self.interactive:
            width = max(20, shutil.get_terminal_size((120, 40)).columns - 1)
            height = max(5, shutil.get_terminal_size((120, 40)).lines - 1)
            # Domain labels are validated as ASCII DNS names before display.
            print("\033[H\033[2J" + "\n".join(line[:width] for line in lines[:height]), flush=True)
        elif final:
            summary_end = lines.index("Останні пакети (час комп’ютера):")
            print("\n" + "\n".join(lines[:summary_end]), flush=True)
