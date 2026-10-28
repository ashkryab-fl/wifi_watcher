"""Loaded by mitmdump, not by the application's Python interpreter."""

import asyncio
import base64
import json
import sys

from mitmproxy import ctx

LIMIT = 65536


def emit(value):
    print(json.dumps(value, ensure_ascii=True), flush=True)


def message_data(message):
    if message is None:
        return None
    raw = message.raw_content
    headers, size = [], 0
    for key, value in message.headers.items(multi=True):
        key, value = key[:2048], value[:4096]
        size += len(key.encode()) + len(value.encode())
        if size > 32768 or len(headers) >= 100:
            break
        headers.append([key, value])
    return {
        "headers": headers,
        "headers_omitted": len(headers) < len(message.headers.fields),
        "http_version": message.http_version,
        "body": base64.b64encode((raw or b"")[:LIMIT]).decode("ascii"),
        "body_bytes": len(raw) if raw is not None else None,
        "body_omitted": raw is None or len(raw) > LIMIT,
    }


class Watcher:
    task = None

    def load(self, loader):
        loader.add_option("ww_prepare", bool, False, "Generate CA without listening")
        loader.add_option("ww_watch_parent", bool, False, "Exit on parent EOF, including during OS approval")

    def configure(self, updated):
        if ctx.options.ww_watch_parent and self.task is None:
            # Local capture can wait for OS approval before running() is called.
            self.task = asyncio.create_task(self.watch_parent())

    async def running(self):
        emit({"type": "ready"})
        if ctx.options.ww_prepare:
            ctx.master.shutdown()
        elif self.task is None:
            # Parent death closes this pipe. Never leave an orphaned root proxy.
            self.task = asyncio.create_task(self.watch_parent())

    async def watch_parent(self):
        await asyncio.to_thread(sys.stdin.buffer.read, 1)
        ctx.master.shutdown()

    def record(self, flow):
        request = flow.request
        if request is None:
            client = flow.client_conn
            host = client.sni or "невідомий домен"
            emit({"type": "flow", "flow": {
                "id": flow.id, "ts": client.timestamp_start, "host": host[:1024], "method": "HTTP",
                "url": "https://" + host[:1024] + "/", "status": None,
                "error": str(flow.error or "Не вдалося прочитати HTTP-запит.")[:2048],
                "request": None, "response": None,
                "client": client.peername, "server": flow.server_conn.peername or flow.server_conn.address,
            }})
            return
        emit({"type": "flow", "flow": {
            "id": flow.id, "ts": request.timestamp_start,
            "host": request.pretty_host[:1024], "method": request.method[:32],
            "url": request.pretty_url[:16384],
            "status": flow.response.status_code if flow.response else None,
            "error": str(flow.error)[:2048] if flow.error else None,
            "client": flow.client_conn.peername,
            "server": flow.server_conn.peername or flow.server_conn.address,
            "request": message_data(request), "response": message_data(flow.response),
        }})

    def request(self, flow):
        self.record(flow)

    def response(self, flow):
        self.record(flow)

    def error(self, flow):
        self.record(flow)

    def tls_failed_client(self, data):
        client = data.context.client
        server = getattr(data.context, "server", None)
        host = client.sni or "невідомий домен"
        emit({"type": "flow", "flow": {
            "id": "tls:" + client.id, "ts": client.timestamp_start,
            "host": host[:1024], "method": "TLS", "url": "https://" + host[:1024] + "/",
            "status": None, "error": "TLS між проксі та телефоном не встановлено. " + str(data.conn.error or "")[:1024],
            "request": None, "response": None,
            "client": client.peername,
            "server": (server.peername or server.address) if server else None,
        }})

    def tls_failed_server(self, data):
        client, server = data.context.client, data.context.server
        host = client.sni or server.sni or (server.address[0] if server.address else "невідомий домен")
        emit({"type": "flow", "flow": {
            "id": "tls-server:" + client.id, "ts": client.timestamp_start,
            "host": host[:1024], "method": "TLS", "url": "https://" + host[:1024] + "/",
            "status": None, "error": "TLS між проксі та сайтом не встановлено. " + str(data.conn.error or "")[:1024],
            "request": None, "response": None,
            "client": client.peername, "server": server.peername or server.address,
        }})


addons = [Watcher()]
