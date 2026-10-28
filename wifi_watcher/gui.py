"""Native live domain list, request inspector, and separate connection settings."""

import fcntl
import queue
import signal
import threading
import time
import tkinter as tk
import uuid
from pathlib import Path
from tkinter import filedialog, ttk

from .bridge import Bridge
from .cli import demo_packets
from .config import router_credentials
from .domains import DomainTracker
from .https import CA_DIR, CertificateServer, executable, prepare_certificate
from .https_view import RequestBrowser
from .metadata import human_bytes, packet_info
from .network import Device, interfaces
from .store import Store, local_time, remove_saved_history, time_range


class FilterBar:
    def __init__(self, parent, changed):
        self.frame = ttk.Frame(parent, padding=(0, 8))
        self.frame.pack(fill="x")
        self.search = tk.StringVar()
        self.start = tk.StringVar()
        self.end = tk.StringVar()
        self.only_domains = tk.BooleanVar(value=False)
        for index, (text, variable, width) in enumerate((
            ("Пошук URL / домену / IP", self.search, 28),
            ("Від дати / часу", self.start, 22),
            ("До дати / часу включно", self.end, 22),
        )):
            box = ttk.Frame(self.frame)
            box.grid(row=0, column=index, padx=(0, 12), sticky="ew")
            ttk.Label(box, text=text, style="Muted.TLabel").pack(anchor="w")
            ttk.Entry(box, textvariable=variable, width=width).pack(fill="x", pady=(5, 0))
            variable.trace_add("write", lambda *_: changed())
        self.frame.columnconfigure(0, weight=1)
        ttk.Button(self.frame, text="Скинути", command=self.clear).grid(row=0, column=3, sticky="s", pady=(0, 1))
        self.domain_checkbox = ttk.Checkbutton(self.frame, text="Лише з доменом", variable=self.only_domains)
        self.domain_checkbox.grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.only_domains.trace_add("write", lambda *_: changed())
        ttk.Label(self.frame, text="Формат: РРРР-ММ-ДД ГГ:ХХ:СС · час Києва · порожні межі — поточне підключення",
                  style="Muted.TLabel").grid(row=1, column=1, columnspan=3, sticky="w", pady=(6, 0))

    def clear(self):
        for value in (self.search, self.start, self.end):
            value.set("")
        self.only_domains.set(False)

    def values(self):
        start, end = time_range(self.start.get(), self.end.get())
        return {"search": self.search.get(), "start": start, "end": end, "domains_only": self.only_domains.get()}


def table(parent, columns):
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True)
    tree = ttk.Treeview(frame, columns=[item[0] for item in columns], show="headings", selectmode="browse")
    for identifier, title, width in columns:
        tree.heading(identifier, text=title)
        tree.column(identifier, width=width, minwidth=65, stretch=identifier in ("domain", "source", "destination"))
    vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(0, weight=1)
    return tree


def update_rows(tree, rows):
    present = set(tree.get_children())
    for position, (identifier, values) in enumerate(rows):
        identifier = str(identifier)
        if identifier in present:
            if tuple(map(str, tree.item(identifier, "values"))) != tuple(map(str, values)):
                tree.item(identifier, values=values)
            present.remove(identifier)
        else:
            tree.insert("", "end", iid=identifier, values=values)
        tree.move(identifier, "", position)
    for identifier in present:
        tree.delete(identifier)


class Application:
    def __init__(self, root, store, interface=None, gateway=None):
        self.root, self.store = root, store
        self.events = queue.Queue()
        self.bridge = None
        self.pending = None
        self.devices = []
        self.active = False
        self.busy = False
        self.closing = False
        self.alive = True
        self.demo_id = None
        self.demo_job = None
        self.session_id = None
        self.group = None
        self.dropped = 0
        self.dirty = True
        self.filter_job = None
        self.last_refresh = 0
        self.query_busy = False
        self.domain_sort = "name_asc"
        self.notice = ""
        self.preparing_https = False
        self.certificate_server = None
        self.lan_ip = None
        self.https_dropped = 0
        self.status = tk.StringVar(value="Готово")
        self.footer = tk.StringVar()
        self.settings_notice = tk.StringVar()
        root.title("WiFi Watcher")
        root.geometry("1220x850")
        root.minsize(1000, 720)
        background = "#20252d"
        surface, control = "#181d24", "#2b323d"
        foreground, muted, disabled = "#ffffff", "#b8c1cf", "#838b98"
        border, hover, selection = "#414b59", "#364151", "#315f91"
        root.configure(background=background)
        root.option_add("*Background", background)
        root.option_add("*Foreground", foreground)
        root.option_add("*Listbox.background", surface)
        root.option_add("*Listbox.foreground", foreground)
        root.option_add("*Listbox.selectBackground", selection)
        root.option_add("*Listbox.selectForeground", foreground)
        style = ttk.Style(root)
        # Native themes can ignore field/background colors, especially on macOS.
        style.theme_use("clam")
        style.configure(".", background=background, foreground=foreground,
                        bordercolor=border, lightcolor=border, darkcolor=border,
                        troughcolor=surface, selectbackground=selection,
                        selectforeground=foreground)
        style.map(".", foreground=[("disabled", disabled)])
        style.configure("TFrame", background=background)
        style.configure("TLabelframe", background=background)
        style.configure("TLabelframe.Label", background=background, foreground=foreground)
        style.configure("TLabel", background=background, foreground=foreground, font=("Helvetica", 12))
        style.configure("Muted.TLabel", foreground=muted, font=("Helvetica", 10))
        style.configure("TCheckbutton", background=background, foreground=foreground,
                        indicatorbackground=surface, indicatorforeground=foreground)
        style.map("TCheckbutton", background=[("active", background)],
                  indicatorbackground=[("disabled", control), ("selected", selection), ("active", hover)])
        style.configure("TButton", background=control, padding=(10, 6))
        style.map("TButton", background=[("disabled", background), ("pressed", selection), ("active", hover)])
        for widget_style in ("TEntry", "TCombobox"):
            style.configure(widget_style, fieldbackground=surface, background=control,
                            foreground=foreground, insertcolor=foreground, arrowcolor=foreground)
            style.map(widget_style, fieldbackground=[("disabled", background), ("readonly", surface)],
                      background=[("disabled", background), ("pressed", selection), ("active", hover),
                                  ("readonly", control)],
                      foreground=[("disabled", disabled), ("readonly", foreground)],
                      arrowcolor=[("disabled", disabled), ("!disabled", foreground)],
                      selectbackground=[("!disabled", selection)],
                      selectforeground=[("!disabled", foreground)])
        style.configure("Status.TLabel", font=("Helvetica", 18, "bold"))
        style.configure("Heading.TLabel", font=("Helvetica", 16, "bold"))
        style.configure("Treeview", background=surface, fieldbackground=surface,
                        foreground=foreground, rowheight=30, font=("Helvetica", 11))
        style.map("Treeview", background=[("selected", selection)], foreground=[("selected", foreground)])
        style.configure("Treeview.Heading", background=control, foreground=foreground,
                        font=("Helvetica", 11, "bold"))
        style.map("Treeview.Heading", background=[("active", hover)])
        style.configure("TNotebook", background=background)
        style.configure("TNotebook.Tab", background=control, foreground=muted, padding=(12, 7))
        style.map("TNotebook.Tab", background=[("selected", surface), ("active", hover)],
                  foreground=[("selected", foreground), ("active", foreground)])
        style.configure("TScrollbar", background=control, arrowcolor=foreground)
        style.map("TScrollbar", background=[("pressed", selection), ("active", hover)])
        main = ttk.Frame(root, padding=22)
        main.pack(fill="both", expand=True)
        header = ttk.Frame(main)
        header.pack(fill="x", pady=(0, 8))
        self.status_label = ttk.Label(header, textvariable=self.status, style="Muted.TLabel")
        self.status_label.pack(side="left")
        ttk.Button(header, text="Налаштування…", command=self.open_settings).pack(side="right")
        self.settings_window = tk.Toplevel(root)
        self.settings_window.withdraw()
        self.settings_window.title("Налаштування WiFi Watcher")
        self.settings_window.geometry("780x430")
        self.settings_window.protocol("WM_DELETE_WINDOW", self.settings_window.withdraw)
        self.settings = ttk.Frame(self.settings_window, padding=22)
        self.settings.pack(fill="both", expand=True)
        self.interface = tk.StringVar(value=interface or "")
        self.gateway = tk.StringVar(value=gateway or "")
        self.device = tk.StringVar()
        ttk.Label(self.settings, text="Мережевий інтерфейс").grid(row=0, column=0, sticky="w")
        ttk.Label(self.settings, text="IP роутера (порожньо — автоматично)").grid(row=0, column=1, columnspan=2, sticky="w")
        interface_entry = ttk.Entry(self.settings, textvariable=self.interface)
        interface_entry.grid(row=1, column=0, sticky="ew", padx=(0, 12), pady=(5, 16))
        gateway_entry = ttk.Entry(self.settings, textvariable=self.gateway)
        gateway_entry.grid(row=1, column=1, columnspan=2, sticky="ew", pady=(5, 16))
        self.device_box = ttk.Combobox(self.settings, textvariable=self.device, state="readonly")
        self.device_box.grid(row=2, column=0, sticky="ew", padx=(0, 12))
        self.scan_button = ttk.Button(self.settings, text="Знайти девайси", command=self.scan)
        self.scan_button.grid(row=2, column=1, sticky="ew", padx=(0, 12))
        self.connect_button = ttk.Button(self.settings, text="Підключити", command=self.connect)
        self.connect_button.grid(row=2, column=2, sticky="ew")
        self.controls = [self.device_box, interface_entry, gateway_entry]
        self.settings.columnconfigure(0, weight=1)
        self.certificate_button = ttk.Button(self.settings, text="Сертифікат HTTPS…", command=self.prepare_https)
        self.certificate_button.grid(row=3, column=0, sticky="w", pady=(16, 0))
        self.demo_button = ttk.Button(self.settings, text="Демонстрація", command=self.demo)
        self.demo_button.grid(row=3, column=1, sticky="ew", padx=(0, 12), pady=(16, 0))
        self.disconnect_button = ttk.Button(self.settings, text="Від’єднати", command=self.disconnect, state="disabled")
        self.disconnect_button.grid(row=3, column=2, sticky="ew", pady=(16, 0))
        ttk.Label(self.settings, text="HTTP / HTTPS увімкнено завжди для окремого девайса.\n"
                  "Імена DHCP запитуються автоматично після пошуку.\n"
                  "Трафік зберігається лише в пам’яті поточного підключення.",
                  style="Muted.TLabel").grid(row=4, column=0, columnspan=3, sticky="w", pady=(18, 0))
        ttk.Label(self.settings, textvariable=self.status, wraplength=720).grid(row=5, column=0, columnspan=3, sticky="w", pady=(12, 0))
        ttk.Label(self.settings, textvariable=self.settings_notice, wraplength=720, style="Muted.TLabel").grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.pages = ttk.Frame(main)
        self.pages.pack(fill="both", expand=True)
        self.domain_page = ttk.Frame(self.pages)
        self.packet_page = ttk.Frame(self.pages)
        self.domain_page.pack(fill="both", expand=True)
        self.domain_filters = FilterBar(self.domain_page, self.filter_changed)
        self.domain_table = table(self.domain_page, [("domain", "Домен / IP", 320), ("count", "Події", 85),
                                 ("tx", "Надіслано", 100), ("rx", "Отримано", 100),
                                 ("last", "Остання активність", 170)])
        self.domain_sort_columns = {"domain": ("Домен / IP", "name"), "tx": ("Надіслано", "tx"),
                                    "rx": ("Отримано", "rx"), "last": ("Остання активність", "last")}
        for column in self.domain_sort_columns:
            self.domain_table.heading(column, command=lambda column=column: self.sort_domains(column))
        self.update_sort_headings(self.domain_table, self.domain_sort_columns, self.domain_sort)
        self.domain_table.bind("<ButtonRelease-1>", self.open_domain)
        self.domain_table.bind("<Return>", self.open_domain)
        detail_header = ttk.Frame(self.packet_page)
        detail_header.pack(fill="x")
        ttk.Button(detail_header, text="← Усі домени", command=self.back).pack(side="left", padx=(0, 12))
        self.domain_title = ttk.Label(detail_header, style="Heading.TLabel")
        self.domain_title.pack(side="left")
        self.packet_filters = FilterBar(self.packet_page, self.filter_changed)
        self.request_browser = RequestBrowser(self.packet_page, self.store)
        ttk.Label(main, textvariable=self.footer, style="Muted.TLabel", wraplength=1120).pack(fill="x", pady=(10, 0))
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.report_callback_exception = self.callback_error
        self.set_controls()
        threading.Thread(target=self.initialize, daemon=True).start()
        root.after(100, self.poll)
        root.after(500, self.heartbeat)

    def initialize(self):
        try:
            self.events.put({"event": "interfaces", "interfaces": interfaces()})
        except Exception as error:
            self.events.put({"event": "error", "message": str(error)})

    def open_settings(self):
        self.settings_window.deiconify()
        self.settings_window.lift()

    def set_controls(self):
        locked = self.active or self.busy or self.closing or self.preparing_https
        for widget in self.controls:
            widget.configure(state="disabled" if locked else "readonly" if isinstance(widget, ttk.Combobox) else "normal")
        self.scan_button.configure(state="disabled" if locked else "normal")
        self.connect_button.configure(state="normal" if not locked and self.devices else "disabled")
        self.disconnect_button.configure(state="normal" if self.active and not self.busy and not self.closing else "disabled")
        self.demo_button.configure(state="disabled" if locked else "normal")
        self.certificate_button.configure(state="disabled" if self.closing or self.preparing_https else "normal")

    def request(self, message):
        try:
            if not self.bridge or self.bridge.stopped.is_set():
                self.bridge = Bridge(self.store, self.events)
                self.pending = message
                self.set_status("Очікування дозволу…")
                self.bridge.launch()
            else:
                self.bridge.send(message)
            self.busy = True
            self.set_controls()
        except Exception as error:
            self.busy = False
            if self.bridge and not self.bridge.connection:
                self.bridge.close()
            self.set_status("Помилка", str(error))
            self.set_controls()

    def scan(self):
        if not self.interface.get():
            self.set_status("Мережу не знайдено", "Підключи Mac до локальної мережі та перезапусти програму.")
            return
        try:
            credentials = router_credentials()
        except ValueError as error:
            self.set_status("Помилка конфігу", str(error))
            return
        self.set_status("Пошук девайсів…")
        self.request({"op": "scan", "interface": self.interface.get(), "gateway": self.gateway.get().strip(),
                      "router": credentials})

    def connect(self):
        index = self.device_box.current()
        if index < 0:
            self.set_status("Оберіть девайс")
            return
        self.set_status("Підключення…")
        device = self.devices[index]
        try:
            binary = executable()
            if not (CA_DIR / "mitmproxy-ca.pem").is_file():
                raise ValueError("У налаштуваннях натисни «Сертифікат HTTPS…» та встанови CA на девайсі.")
            https = {"binary": binary, "directory": str(CA_DIR)}
        except (ValueError, RuntimeError) as error:
            self.set_status("HTTPS не підготовлено", str(error))
            return
        self.request({"op": "start", "ip": device["ip"], "mac": device["mac"],
                      "name": device.get("name", ""), "interface": self.interface.get(),
                      "gateway": self.gateway.get().strip(), "relay": "auto", "https": https})

    def prepare_https(self):
        if self.preparing_https or self.closing:
            return
        self.preparing_https = True
        self.set_status("Підготовка сертифіката…")
        self.set_controls()

        def prepare():
            try:
                cert = prepare_certificate()
                self.events.put({"event": "certificate", "path": str(cert)})
            except Exception as error:
                self.events.put({"event": "certificate_error", "message": str(error)})

        threading.Thread(target=prepare, daemon=True).start()

    def certificate_dialog(self, certificate):
        window = tk.Toplevel(self.root)
        window.title("Сертифікат HTTPS")
        frame = ttk.Frame(window, padding=20)
        frame.pack(fill="both", expand=True)
        text = ("Встанови цей CA лише на тестовому девайсі.\n"
                "Цей Mac: імпортуй CA у В’язку ключів та встанови «Завжди довіряти».\n"
                "При першому підключенні дозволь мережеве розширення Mitmproxy Redirector.\n"
                "iPhone / iPad: встанови профіль, потім увімкни повну довіру в\n"
                "Параметри → Загальні → Про пристрій → Довіра сертифікатам.\n"
                "Android: встанови як сертифікат центру сертифікації (CA).\n"
                "Застосунок має довіряти цьому CA; pinning потребує окремого налаштування.\n\n"
                "Для окремих LAN-девайсів IPv6 та HTTP/3 (QUIC) не розшифровуються.\n"
                "Запити, заголовки й невеликі тіла доступні лише в пам’яті поточного підключення.")
        ttk.Label(frame, text=text, justify="left").pack(anchor="w")
        ttk.Label(frame, text="Публічний сертифікат:").pack(anchor="w", pady=(12, 3))
        path = ttk.Entry(frame, width=88)
        path.insert(0, str(certificate))
        path.configure(state="readonly")
        path.pack(fill="x")
        if self.certificate_server:
            self.certificate_server.close()
            self.certificate_server = None
        if self.lan_ip:
            try:
                self.certificate_server = CertificateServer(self.lan_ip, certificate)
                ttk.Label(frame, text="На девайсі в тій самій Wi-Fi мережі відкрий у браузері:").pack(anchor="w", pady=(12, 3))
                url = ttk.Entry(frame)
                url.insert(0, self.certificate_server.url)
                url.configure(state="readonly")
                url.pack(fill="x")
            except OSError as error:
                ttk.Label(frame, text="Завантаження мережею недоступне: " + str(error)).pack(anchor="w")
        else:
            ttk.Label(frame, text="Для завантаження через Wi-Fi спочатку знайди девайси, потім відкрий це вікно ще раз.").pack(anchor="w", pady=(12, 0))

        def export():
            filename = filedialog.asksaveasfilename(parent=window, defaultextension=".cer", initialfile="wifi-watcher-ca.cer")
            if filename:
                import ssl
                Path(filename).write_bytes(ssl.PEM_cert_to_DER_cert(Path(certificate).read_text()))

        ttk.Button(frame, text="Зберегти сертифікат…", command=export).pack(anchor="e", pady=(14, 0))

    def disconnect(self):
        if self.demo_id:
            if self.demo_job:
                self.root.after_cancel(self.demo_job)
                self.demo_job = None
            self.store.finish(self.demo_id)
            self.demo_id = None
            self.active = self.busy = False
            self.set_status("Демонстрацію завершено")
            self.dirty = True
            self.set_controls()
            return
        self.set_status("Від’єднання…")
        self.request({"op": "disconnect"})

    def filter_changed(self):
        if self.filter_job:
            self.root.after_cancel(self.filter_job)
        self.filter_job = self.root.after(250, self.apply_filters)

    def apply_filters(self):
        self.filter_job = None
        self.dirty = True

    def open_domain(self, event=None):
        if event and getattr(event, "keysym", "") != "Return":
            row = self.domain_table.identify_row(event.y)
            if not row:
                return
            self.domain_table.selection_set(row)
        selected = self.domain_table.selection()
        if not selected:
            return
        self.group = selected[0]
        self.request_browser.display([])
        self.domain_title.configure(text=self.domain_table.item(self.group, "values")[0])
        self.domain_page.pack_forget()
        self.packet_page.pack(fill="both", expand=True)
        self.dirty = True

    def back(self):
        self.packet_page.pack_forget()
        self.domain_page.pack(fill="both", expand=True)
        self.group = None
        self.dirty = True

    def set_status(self, text, detail=""):
        self.status.set(text)
        self.notice = detail
        self.settings_notice.set(detail)
        self.dirty = True

    @staticmethod
    def update_sort_headings(tree, columns, sort):
        for column, (title, key) in columns.items():
            arrow = " ↑" if sort == key + "_asc" else " ↓" if sort == key + "_desc" else ""
            tree.heading(column, text=title + arrow)

    def sort_domains(self, column):
        key = self.domain_sort_columns[column][1]
        self.domain_sort = key + ("_desc" if self.domain_sort == key + "_asc" else "_asc")
        self.update_sort_headings(self.domain_table, self.domain_sort_columns, self.domain_sort)
        self.dirty = True

    def query_filters(self):
        filters = (self.packet_filters if self.group else self.domain_filters).values()
        filters["session"] = self.session_id
        if not self.group:
            filters["sort"] = self.domain_sort
        return filters

    def refresh(self):
        if self.query_busy:
            return
        try:
            filters = self.query_filters()
        except ValueError as error:
            self.footer.set(str(error))
            return
        signature = (self.group, filters)
        self.query_busy = True

        def query():
            try:
                group, values = signature
                result = self.store.requests(group=group, **values) if group else self.store.groups(**values)
                self.events.put({"event": "query", "signature": signature, "result": result})
            except Exception as error:
                self.events.put({"event": "query", "signature": signature, "error": str(error)})

        threading.Thread(target=query, daemon=True).start()

    def display_query(self, event):
        self.query_busy = False
        try:
            filters = self.query_filters()
            if event["signature"] != (self.group, filters):
                self.dirty = True
                return
            if event.get("error"):
                self.footer.set(event["error"])
                return
            if self.group:
                rows = event["result"]
                self.request_browser.display(rows)
                count = f"Запитів / з’єднань: {len(rows)} · нові зверху · групування URL за path"
            else:
                groups = event["result"]
                update_rows(self.domain_table, [(row["group_key"], (row["title"], row["count"], human_bytes(row["tx"]),
                    human_bytes(row["rx"]), local_time(row["last"]))) for row in groups])
                count = f"Доменів / IP: {len(groups)} (до 1000 за вибраним сортуванням) · Подій у вибірці: {sum(row['count'] for row in groups)}"
            detail = self.notice + "\n" if self.notice else ""
            self.footer.set(f"{detail}{count} · Пропущено метаданих: {self.dropped} · Пропущено HTTP: {self.https_dropped}")
        except ValueError as error:
            self.footer.set(str(error))

    def on_event(self, event):
        kind = event.get("event")
        if kind == "query":
            self.display_query(event)
            return
        elif kind == "interfaces":
            if not self.interface.get() and event["interfaces"]:
                self.interface.set(event["interfaces"][0])
        elif kind == "ready":
            if self.pending:
                message, self.pending = self.pending, None
                self.bridge.send(message)
        elif kind == "devices":
            index = self.device_box.current()
            previous = self.devices[index]["mac"] if 0 <= index < len(self.devices) else None
            self.devices = event["devices"]
            self.device_box["values"] = [f"{d.get('name') or 'Без імені'} · {d['ip']} · {d['mac']} {d.get('label', '')}" for d in self.devices]
            network = event["network"]
            self.lan_ip = network["ip"]
            selected = next((i for i, device in enumerate(self.devices) if device["mac"] == previous), None)
            if selected is None:
                selected = next((i for i, device in enumerate(self.devices) if device["ip"] not in (network["ip"], network["gateway"])), 0)
            if self.devices:
                self.device_box.current(selected)
            self.busy = False
            self.set_status(f"Знайдено: {len(self.devices)}", event.get("warning") or "")
        elif kind == "session":
            self.session_id = event["session"]
            self.dropped = self.https_dropped = 0
            self.back()
            update_rows(self.domain_table, [])
            self.request_browser.display([])
        elif kind == "starting_local":
            self.active, self.busy = True, False
            self.set_status("Запуск HTTPS на цьому Mac…", event["message"])
        elif kind == "started":
            self.active, self.busy = True, False
            device = event["device"]
            for index, previous in enumerate(self.devices):
                if previous["mac"] == device["mac"]:
                    self.devices[index] = device
                    self.device_box["values"] = [f"{d.get('name') or 'Без імені'} · {d['ip']} · {d['mac']} {d.get('label', '')}" for d in self.devices]
                    self.device_box.current(index)
                    break
            self.set_status(f"HTTPS · {device.get('name') or device['ip']}")
            self.settings_window.withdraw()
        elif kind == "certificate":
            self.preparing_https = False
            self.set_status("Сертифікат готовий")
            self.certificate_dialog(event["path"])
        elif kind == "certificate_error":
            self.preparing_https = False
            self.set_status("Помилка сертифіката", event["message"])
        elif kind == "https_dirty":
            self.https_dropped = event.get("dropped", 0)
            if self.https_dropped:
                self.set_status("HTTPS: пропущено записи", f"Черга переповнена: {self.https_dropped}. Мережеві втрати цим числом не вимірюються.")
        elif kind == "stopped":
            self.active = self.busy = False
            errors = event.get("errors", [])
            details = [event.get("reason")]
            if errors:
                details.append("Відновлення не підтверджено: " + "; ".join(errors))
            self.set_status("Помилка відновлення" if errors else "Від’єднано", " ".join(d for d in details if d))
        elif kind == "error":
            self.busy = False
            self.set_status("Помилка", event["message"])
        elif kind == "offline":
            was_active = self.active
            self.active = self.busy = False
            self.pending = None
            if was_active:
                self.set_status("З’єднання втрачено", "Аварійний процес відновлює ARP; результат не підтверджено.")
            if self.closing:
                self.destroy()
                return
        if kind == "dirty":
            self.dropped = event.get("dropped", 0)
        self.dirty = True
        self.set_controls()

    def poll(self):
        try:
            for _ in range(300):
                try:
                    self.on_event(self.events.get_nowait())
                except queue.Empty:
                    break
                if not self.alive:
                    return
            if self.dirty and not self.query_busy and time.monotonic() - self.last_refresh > 0.6:
                self.refresh()
                self.dirty = False
                self.last_refresh = time.monotonic()
        finally:
            if self.alive:
                self.root.after(100, self.poll)

    def heartbeat(self):
        if self.bridge and self.bridge.connection:
            try:
                self.bridge.send({"op": "heartbeat"})
            except OSError:
                self.bridge.close()
        if not self.closing:
            self.root.after(750, self.heartbeat)

    def demo(self):
        if self.active or self.busy or self.closing:
            return
        self.demo_id = "demo:" + str(uuid.uuid4())
        self.session_id = self.demo_id
        self.dropped = self.https_dropped = 0
        self.back()
        self.request_browser.display([])
        update_rows(self.domain_table, [])
        self.demo_device = Device("192.168.0.50", "02:00:00:00:00:50", name="Demo Pixel")
        self.store.session(self.demo_id, {"name": self.demo_device.name, "ip": self.demo_device.ip, "mac": self.demo_device.mac}, "DEMO")
        self.demo_tracker = DomainTracker()
        self.demo_stream = iter(demo_packets(self.demo_device))
        self.active = True
        self.set_status("Демонстрація")
        self.settings_window.withdraw()
        self.set_controls()
        self.demo_tick()

    def demo_tick(self):
        if not self.demo_id:
            return
        try:
            packet = next(self.demo_stream)
        except StopIteration:
            self.demo_stream = iter(demo_packets(self.demo_device))
            packet = next(self.demo_stream)
        info = self.demo_tracker.enrich(packet, packet_info(packet, self.demo_device))
        self.store.record(self.demo_id, [info.json()])
        self.dirty = True
        self.demo_job = self.root.after(100, self.demo_tick)

    def callback_error(self, kind, error, traceback):
        self.set_status("Помилка інтерфейсу", str(error))
        if self.active:
            self.disconnect()

    def close(self):
        if self.closing:
            return
        if self.demo_id:
            self.disconnect()
        self.closing = True
        self.set_controls()
        if self.bridge and self.bridge.connection:
            self.set_status("Завершення…")
            try:
                self.bridge.send({"op": "shutdown"})
                self.root.after(15000, self.force_transport_close)
            except OSError:
                self.force_transport_close()
        else:
            if self.bridge:
                self.bridge.close()
            self.destroy()

    def force_transport_close(self):
        if self.bridge:
            self.bridge.close()
        self.destroy()

    def destroy(self):
        if self.alive:
            self.alive = False
            self.request_browser.close()
            if self.certificate_server:
                self.certificate_server.close()
                self.certificate_server = None
            for job in self.root.tk.call("after", "info"):
                self.root.after_cancel(job)
            self.root.destroy()


def main(interface=None, gateway=None, demo=False):
    folder = Path(__file__).resolve().parent.parent / "logs"
    folder.mkdir(exist_ok=True)
    lock = (folder / "gui.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("WiFi Watcher уже запущений.")
        lock.close()
        return 1
    root = tk.Tk()
    app = None
    try:
        remove_saved_history(folder)
        store = Store()
        app = Application(root, store, interface, gateway)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, lambda *_: root.after(0, app.close))
        if demo:
            root.after(500, app.demo)
        root.mainloop()
    finally:
        if app and app.bridge:
            app.bridge.close()
        if app and app.bridge and app.bridge.thread.is_alive():
            app.bridge.thread.join(timeout=2)
        if app:
            app.store.close()
        lock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
