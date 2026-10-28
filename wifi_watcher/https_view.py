"""Single-column request tree and an embedded request/response inspector."""

import base64
import json
import queue
import threading
from urllib.parse import urlsplit
import zlib

try:
    from compression import zstd
except ImportError:
    from backports import zstd

from .store import local_time


def body_preview(message):
    if message.get("body_omitted"):
        return "[Тіло передавалося потоком або перевищує 64 KiB; повне тіло не збережено.]"
    raw = base64.b64decode(message.get("body", ""))
    encoding = next((v.lower() for k, v in message.get("headers", []) if k.lower() == "content-encoding"), "")
    if encoding in ("gzip", "deflate"):
        try:
            decoder = zlib.decompressobj(31 if encoding == "gzip" else 15)
            raw = decoder.decompress(raw, 65537)
            if len(raw) > 65536 or decoder.unconsumed_tail:
                return "[Розпаковане тіло перевищує 64 KiB.]"
        except zlib.error:
            return "[Не вдалося розпакувати тіло.]"
    elif encoding == "zstd":
        try:
            output = bytearray()
            while True:
                decoder = zstd.ZstdDecompressor(options={zstd.DecompressionParameter.window_log_max: 23})
                output.extend(decoder.decompress(raw, 65537 - len(output)))
                while not decoder.eof and not decoder.needs_input and len(output) <= 65536:
                    output.extend(decoder.decompress(b"", 65537 - len(output)))
                if len(output) > 65536:
                    return "[Розпаковане тіло перевищує 64 KiB.]"
                if not decoder.eof:
                    return "[Не вдалося розпакувати тіло.]"
                raw = decoder.unused_data
                if not raw:
                    raw = bytes(output)
                    break
        except zstd.ZstdError:
            return "[Не вдалося розпакувати тіло.]"
    elif encoding and encoding != "identity":
        return f"[Стиснене тіло {encoding}; байти у Base64]\n" + message.get("body", "")
    try:
        text = raw.decode("utf-8")
        if any(ord(char) < 32 and char not in "\n\r\t" for char in text):
            raise UnicodeError
        try:
            return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except (ValueError, RecursionError):
            return text
    except UnicodeError:
        return "[Бінарне тіло; HEX]\n" + raw.hex(" ")


def flow_text(flow):
    if not flow:
        return "Обери запит."
    parts = [f"{flow['method']} {flow['url']}", f"Статус: {flow_status(flow)}"]
    if flow.get("error"):
        parts.append("Помилка: " + flow["error"])
    for name, message in (("ЗАПИТ", flow.get("request")), ("ВІДПОВІДЬ", flow.get("response"))):
        parts += ["", name]
        if message is None:
            parts.append("[Ще немає]")
            continue
        parts.append(message.get("http_version", ""))
        parts.extend(f"{key}: {value}" for key, value in message.get("headers", []))
        if message.get("headers_omitted"):
            parts.append("[Частину заголовків пропущено через обмеження розміру.]")
        parts += ["", body_preview(message)]
    return "\n".join(parts)


def flow_status(flow):
    if flow.get("error"):
        return "помилка" + (f" (HTTP {flow['status']})" if flow.get("status") else "")
    return flow.get("status") or "очікування"


def request_groups(rows):
    """Group exact URL paths (query strings stay on leaves), newest activity first."""
    groups = {}
    for row in sorted(rows, key=lambda item: (item["ts"], item["key"]), reverse=True):
        url = row.get("url")
        if url:
            parsed = urlsplit(url)
            path = parsed.path or "/"
            key = "path:" + json.dumps([parsed.scheme, parsed.netloc, path])
            group = groups.setdefault(key, {"key": key, "text": path, "rows": [], "ts": row["ts"]})
            group["rows"].append(row)
        else:
            groups[row["key"]] = {"key": row["key"], "text": row["host"], "rows": [], "ts": row["ts"]}
    return sorted(groups.values(), key=lambda item: (item["ts"], item["key"]), reverse=True)


def message_text(message):
    if message is None:
        return "[Дані недоступні або ще не отримані.]"
    parts = [message.get("http_version", "")]
    parts.extend(f"{key}: {value}" for key, value in message.get("headers", []))
    if message.get("headers_omitted"):
        parts.append("[Частину заголовків пропущено через обмеження розміру.]")
    parts.extend(("", body_preview(message)))
    return "\n".join(parts)


def detail_sections(row):
    if not row:
        return ("Обери запит у списку ліворуч.", "", "")
    if "packet" in row:
        from .metadata import endpoint
        packet = row["packet"]
        overview = (f"{row['host']}\nЧас: {local_time(row['ts'], True)}\n"
                    f"Протокол: {packet['protocol']}\n"
                    f"Звідки: {endpoint(packet['source'], packet.get('source_port'))}\n"
                    f"Куди: {endpoint(packet['destination'], packet.get('destination_port'))}\n"
                    f"Пакетів: {row['count']} · Байтів: {row['bytes']}\n\n"
                    "Доступні лише метадані з’єднання. URL, заголовки та тіла HTTP не отримано.")
        return overview, "[HTTP-запит недоступний.]", "[HTTP-відповідь недоступна.]"
    flow = row["flow"]
    overview = (f"{flow['method']} {row.get('url') or row['host']}\n"
                f"Час: {local_time(row['ts'], True)}\n"
                f"Статус: {flow_status(flow)}")
    if flow.get("error"):
        overview += "\nПомилка: " + flow["error"]
    return overview, message_text(flow.get("request")), message_text(flow.get("response"))


class RequestBrowser:
    def __init__(self, parent, store):
        import tkinter as tk
        from tkinter import ttk
        from tkinter.font import Font
        self.parent, self.store = parent, store
        self.font = Font(parent, family="Helvetica", size=11)
        panes = ttk.Panedwindow(parent, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left, right = ttk.Frame(panes, width=340), ttk.Frame(panes, width=720)
        left.grid_propagate(False)
        panes.add(left, weight=1)
        panes.add(right, weight=3)
        self.tree = ttk.Treeview(left, columns=(), show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="URL / домен / IP · нові зверху")
        self.tree.column("#0", width=340, minwidth=220, stretch=True)
        y = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        x = ttk.Scrollbar(left, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.tabs = ttk.Notebook(right)
        self.tabs.pack(fill="both", expand=True, padx=(12, 0))
        self.texts = []
        for label in ("Огляд", "Запит", "Відповідь"):
            frame = ttk.Frame(self.tabs)
            self.tabs.add(frame, text=label)
            text = tk.Text(frame, wrap="word" if label == "Огляд" else "none", font=("Menlo", 11), state="disabled",
                           background="#181d24", foreground="#ffffff", insertbackground="#ffffff",
                           selectbackground="#315f91", selectforeground="#ffffff",
                           inactiveselectbackground="#315f91", highlightbackground="#414b59",
                           highlightcolor="#315f91", borderwidth=0)
            y = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
            x = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
            text.configure(yscrollcommand=y.set, xscrollcommand=x.set)
            text.grid(row=0, column=0, sticky="nsew")
            y.grid(row=0, column=1, sticky="ns")
            x.grid(row=1, column=0, sticky="ew")
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)
            self.texts.append(text)
        self.rows = {}
        self.results = queue.Queue()
        self.selected_row = None
        self.revision = 0
        self.alive = True
        self.tree.bind("<<TreeviewSelect>>", self.show_selection)
        self.set_detail(detail_sections(None))
        self.job = parent.after(100, self.poll)

    def display(self, rows):
        self.rows = {row["key"]: row for row in rows}
        width = max((self.font.measure(row.get("url") or row["host"]) + 70 for row in rows), default=340)
        self.tree.column("#0", width=max(340, width))
        wanted = set()
        for index, group in enumerate(request_groups(rows)):
            key = group["key"]
            wanted.add(key)
            if not self.tree.exists(key):
                self.tree.insert("", "end", iid=key, text=group["text"], open=True)
            self.tree.move(key, "", index)
            for position, row in enumerate(group["rows"]):
                child = row["key"]
                wanted.add(child)
                if not self.tree.exists(child):
                    self.tree.insert(key, "end", iid=child, text=row["url"])
                else:
                    self.tree.item(child, text=row["url"])
                self.tree.move(child, key, position)
        for key in self.tree.get_children():
            for child in self.tree.get_children(key):
                if child not in wanted:
                    self.tree.delete(child)
            if key not in wanted:
                self.tree.delete(key)
        self.show_selection()

    def show_selection(self, *_):
        selected = self.tree.selection()
        row = self.rows.get(selected[0]) if selected else None
        if row == self.selected_row:
            return
        self.selected_row = row
        self.revision += 1
        revision = self.revision
        self.set_detail(detail_sections(None))
        if row is None:
            return

        def decode():
            try:
                result = detail_sections(self.store.request_detail(row))
            except Exception as error:
                result = ("Не вдалося відкрити деталі: " + str(error), "", "")
            self.results.put((revision, result))

        threading.Thread(target=decode, daemon=True).start()

    def set_detail(self, sections):
        for text, value in zip(self.texts, sections):
            if text.get("1.0", "end-1c") == value:
                continue
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.insert("1.0", value)
            text.configure(state="disabled")

    def poll(self):
        try:
            while True:
                revision, sections = self.results.get_nowait()
                if revision == self.revision:
                    self.set_detail(sections)
        except queue.Empty:
            pass
        if self.alive:
            self.job = self.parent.after(100, self.poll)

    def close(self):
        self.alive = False
        self.parent.after_cancel(self.job)
