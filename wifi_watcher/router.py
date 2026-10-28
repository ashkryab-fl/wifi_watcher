"""Read the TP-Link TL-WR841N DHCP host table without changing settings.

Uses the cookie authentication and ACT_GL request format served by this router's
/js/lib.js and /js/oid_str.js. Credentials stay in memory for one request.
"""

import base64
import re
from dataclasses import dataclass, replace
from http.client import HTTPException
from ipaddress import IPv4Address
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class RouterError(ValueError):
    pass


@dataclass(frozen=True)
class DhcpClient:
    mac: str
    name: str
    ip: str


def normalize_mac(value):
    value = value.strip().replace("-", ":").lower()
    if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", value):
        return None
    if int(value[:2], 16) & 1 or value == "00:00:00:00:00:00":
        return None
    return value


def device_name(value):
    # DHCP host names are controlled by other clients, not by this program.
    return " ".join("".join(char if char.isprintable() else " " for char in value).split())[:80]


def parse_clients(text):
    """Parse CGI records as data, never execute router-provided JavaScript."""
    records = []
    current = None
    status = None
    for line in text.lstrip("\ufeff").splitlines():
        line = line.strip()
        if not line:
            continue
        header = re.fullmatch(r"\[([^\]]+)\](\d+)", line)
        if header:
            if header[1] == "error":
                status = int(header[2])
                if status:
                    raise RouterError("Роутер відхилив читання DHCP: перевір логін/пароль та активний сеанс адміністратора.")
                current = None
            elif re.fullmatch(r"\d+(?:,\d+){5}", header[1]) and header[2] == "0":
                current = {}
                records.append(current)
            else:
                current = None
        elif current is not None and "=" in line:
            key, value = line.split("=", 1)
            current[key.lower()] = value
    # A successful empty list still ends in [error]0. Login HTML does not.
    if status != 0:
        raise RouterError("Не отримано список DHCP: перевір логін/пароль або сумісність прошивки.")
    clients = []
    for record in records[:1024]:
        mac = normalize_mac(record.get("macaddress", ""))
        name = device_name(record.get("hostname", ""))
        try:
            ip = str(IPv4Address(record.get("ipaddress", "")))
        except ValueError:
            continue
        if mac and name:
            clients.append(DhcpClient(mac, name, ip))
    return clients


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        # Do not send the authorization cookie to any redirected destination.
        return None


def read_clients(gateway, username, password):
    gateway = str(IPv4Address(gateway))
    base = f"http://{gateway}"
    auth = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    # ACT_GL=5 is read-only. Empty attributes request the host object's fields.
    body = b"[LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
    request = Request(base + "/cgi?5", data=body, headers={
        "Cookie": "Authorization=Basic " + auth,
        "Referer": base + "/",
        "User-Agent": "Mozilla/5.0 WiFiWatcher",
        "Content-Type": "text/plain",
    }, method="POST")
    # Local router traffic must not go through environment-configured proxies.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=5) as response:
            raw = response.read(1048577)
            if len(raw) > 1048576:
                raise RouterError("Список DHCP перевищує допустимий розмір.")
            text = raw.decode("utf-8-sig", errors="replace")
    except HTTPError as error:
        error.close()
        raise RouterError("Роутер не дозволив читання DHCP: перевір логін/пароль та активний сеанс адміністратора.") from None
    except (URLError, OSError, HTTPException):
        raise RouterError("Не вдалося з’єднатися з вебінтерфейсом роутера.") from None
    return parse_clients(text)


def attach_names(devices, clients):
    names = {}
    for client in clients:
        names.setdefault(client.mac, set()).add(client.name)
    return [replace(device, name=next(iter(names[device.mac])))
            if len(names.get(device.mac, ())) == 1 else device for device in devices]
