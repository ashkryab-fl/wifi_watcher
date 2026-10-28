"""Thread-safe capture data. The GUI uses an in-memory database only."""

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from zoneinfo import ZoneInfo

LOCAL_ZONE = ZoneInfo("Europe/Kyiv")


def host_group(host):
    try:
        ip_address(host)
        return "ip:" + host
    except ValueError:
        return "domain:" + host


def remove_saved_history(folder):
    """Remove old traffic files while keeping the reusable CA and helper lock."""
    folder = Path(folder)
    paths = [folder / ("traffic.sqlite3" + suffix) for suffix in ("", "-wal", "-shm", "-journal")]
    paths.extend(folder.glob("*.jsonl"))
    for path in paths:
        if path.is_file() and not path.is_symlink():
            path.unlink()


def time_range(start="", end=""):
    def parse(value, upper=False):
        value = value.strip()
        if not value:
            return None
        try:
            pattern = "%Y-%m-%d" if len(value) == 10 else "%Y-%m-%d %H:%M:%S"
            date = datetime.strptime(value, pattern).replace(tzinfo=LOCAL_ZONE)
            if upper:
                date += timedelta(days=1) if len(value) == 10 else timedelta(seconds=1)
            return date.timestamp()
        except ValueError:
            raise ValueError("Дата: РРРР-ММ-ДД або РРРР-ММ-ДД ГГ:ХХ:СС.") from None
    lower, upper = parse(start), parse(end, True)
    if lower is not None and upper is not None and lower >= upper:
        raise ValueError("Кінець діапазону має бути не раніше початку.")
    return lower, upper


def local_time(timestamp, milliseconds=False):
    date = datetime.fromtimestamp(timestamp, LOCAL_ZONE)
    return date.strftime("%Y-%m-%d %H:%M:%S") + (f".{date.microsecond // 1000:03}" if milliseconds else "")


def group_for(packet):
    outgoing = packet["direction"] == "TX"
    prefix = "destination" if outgoing else "source"
    address, port = packet[prefix], packet.get(prefix + "_port")
    names = tuple(packet.get(prefix + "_domains") or ())
    evidence = packet.get(prefix + "_domain_source")
    # Ambiguous DNS/ECH outer names stay in the IP group, searchable as hints.
    exact = len(names) == 1 and evidence in ("dns", "tls_sni", "http_host")
    title = names[0] if exact else address
    key = ("domain:" if exact else "ip:") + title
    return key, title, address, port, evidence or "ip", " ".join((title, address, *names)).casefold()


class Store:
    def __init__(self, path=None):
        self.history_lock = threading.RLock()
        self.path = Path(path).absolute() if path is not None else None
        self.memory = None
        if self.path is None:
            self.memory = sqlite3.connect(":memory:", check_same_thread=False)
            self.memory.execute("PRAGMA temp_store=MEMORY")
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.is_symlink():
                raise ValueError("База журналів не може бути символічним посиланням.")
            descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, started REAL NOT NULL, ended REAL,
                    name TEXT, ip TEXT, mac TEXT, mode TEXT, error TEXT
                );
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY, session TEXT NOT NULL, ts REAL NOT NULL,
                    group_key TEXT NOT NULL, title TEXT NOT NULL, search TEXT NOT NULL,
                    address TEXT NOT NULL, port INTEGER, evidence TEXT NOT NULL,
                    direction TEXT NOT NULL, size INTEGER NOT NULL, protocol TEXT NOT NULL,
                    data TEXT NOT NULL, origin TEXT UNIQUE
                );
                CREATE INDEX IF NOT EXISTS packets_time ON packets(ts);
                CREATE INDEX IF NOT EXISTS packets_group_time ON packets(group_key, ts);
                CREATE INDEX IF NOT EXISTS packets_session_time ON packets(session, ts);
                CREATE TABLE IF NOT EXISTS imports (path TEXT PRIMARY KEY, size INTEGER);
                CREATE TABLE IF NOT EXISTS http_flows (
                    session TEXT NOT NULL, id TEXT NOT NULL, ts REAL NOT NULL,
                    host TEXT NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL,
                    status INTEGER, error TEXT, data TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(session,id)
                );
                CREATE INDEX IF NOT EXISTS http_session_time ON http_flows(session,ts);
                CREATE INDEX IF NOT EXISTS http_time ON http_flows(ts);
            """)
            if "revision" not in {row["name"] for row in db.execute("PRAGMA table_info(http_flows)")}:
                db.execute("ALTER TABLE http_flows ADD COLUMN revision INTEGER NOT NULL DEFAULT 0")

    @contextmanager
    def connection(self):
        with self.history_lock:
            db = self.memory if self.memory is not None else sqlite3.connect(self.path, timeout=5)
            db.row_factory = sqlite3.Row
            db.create_function("host_group", 1, host_group, deterministic=True)
            try:
                with db:
                    yield db
            finally:
                if self.memory is None:
                    db.close()

    def close(self):
        with self.history_lock:
            if self.memory is not None:
                self.memory.close()

    def session(self, identifier, device, mode, started=None):
        with self.connection() as db:
            if self.memory is not None and not db.execute("SELECT 1 FROM sessions WHERE id=?", (identifier,)).fetchone():
                for table in ("packets", "http_flows", "sessions"):
                    db.execute("DELETE FROM " + table)
            db.execute("INSERT OR IGNORE INTO sessions(id,started,name,ip,mac,mode) VALUES(?,?,?,?,?,?)",
                       (identifier, started if started is not None else datetime.now(timezone.utc).timestamp(),
                        device.get("name", ""), device.get("ip", ""), device.get("mac", ""), mode))

    def finish(self, identifier, error=None):
        with self.connection() as db:
            db.execute("UPDATE sessions SET ended=?,error=? WHERE id=?",
                       (datetime.now(timezone.utc).timestamp(), error, identifier))

    def record(self, identifier, packets, origins=None):
        rows = []
        for index, packet in enumerate(packets):
            key, title, address, port, evidence, search = group_for(packet)
            stamp = datetime.fromisoformat(packet["timestamp"]).timestamp()
            rows.append((identifier, stamp, key, title, search, address, port, evidence,
                         packet["direction"], packet["bytes"], packet["protocol"],
                         json.dumps(packet, ensure_ascii=False), origins[index] if origins else None))
        with self.connection() as db:
            db.executemany("""INSERT OR IGNORE INTO packets
                (session,ts,group_key,title,search,address,port,evidence,direction,size,protocol,data,origin)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)

    def record_http(self, session, flow):
        data = json.dumps(flow, ensure_ascii=False)
        if len(data.encode()) > 1048576:
            raise ValueError("Завеликий запис HTTPS.")
        with self.connection() as db:
            db.execute("""INSERT INTO http_flows
                (session,id,ts,host,method,url,status,error,data) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session,id) DO UPDATE SET ts=excluded.ts,host=excluded.host,
                    method=excluded.method,url=excluded.url,status=excluded.status,error=excluded.error,
                    data=excluded.data,revision=http_flows.revision+1""",
                       (session, flow["id"], float(flow["ts"]), flow["host"], flow["method"], flow["url"],
                        flow.get("status"), flow.get("error"), data))

    def http_flows(self, session=None, search=""):
        terms, args = [], []
        if session is not None:
            terms.append("session=?")
            args.append(session)
        if search.strip():
            terms.append("instr(lower(url),?)>0")
            args.append(search.strip().lower())
        where = " WHERE " + " AND ".join(terms) if terms else ""
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT session,id,ts,host,method,url,status,error "
                    "FROM http_flows" + where + " ORDER BY ts DESC,id LIMIT 300", args)]

    def http_detail(self, session, identifier):
        with self.connection() as db:
            row = db.execute("SELECT data FROM http_flows WHERE session=? AND id=?", (session, identifier)).fetchone()
            return json.loads(row[0]) if row else None

    @staticmethod
    def where(session=None, search="", start=None, end=None, group=None, domains_only=False):
        terms, values = [], []
        for expression, value in (("session=?", session), ("ts>=?", start),
                                  ("ts<?", end), ("group_key=?", group)):
            if value is not None:
                terms.append(expression)
                values.append(value)
        if search.strip():
            # instr is literal, so wildcard characters are not interpreted.
            terms.append("instr(search,?) > 0")
            values.append(search.strip().casefold())
        if domains_only:
            terms.append("group_key LIKE 'domain:%'")
        return (" WHERE " + " AND ".join(terms) if terms else ""), values

    def groups(self, *, sort="activity", **filters):
        order = {
            "activity": "last DESC, group_key ASC",
            "name_asc": "title COLLATE NOCASE ASC, group_key ASC",
            "name_desc": "title COLLATE NOCASE DESC, group_key ASC",
            "last_asc": "last ASC, group_key ASC",
            "last_desc": "last DESC, group_key ASC",
            "tx_asc": "tx ASC, group_key ASC",
            "tx_desc": "tx DESC, group_key ASC",
            "rx_asc": "rx ASC, group_key ASC",
            "rx_desc": "rx DESC, group_key ASC",
        }.get(sort)
        if order is None:
            raise ValueError("Невідоме сортування доменів.")
        where, values = self.where(**filters)
        with self.connection() as db:
            return [dict(row) for row in db.execute("""SELECT group_key,title,COUNT(*) count,
                SUM(CASE WHEN direction='TX' THEN size ELSE 0 END) tx,
                SUM(CASE WHEN direction='RX' THEN size ELSE 0 END) rx,
                MIN(ts) first,MAX(ts) last,GROUP_CONCAT(DISTINCT evidence) evidence,
                GROUP_CONCAT(DISTINCT address) addresses FROM (
                    SELECT session,ts,group_key,title,search,address,evidence,direction,size FROM packets
                    UNION ALL
                    SELECT session,ts,host_group(host),host,lower(host || ' ' || url),host,'http','TX',0 FROM http_flows
                )""" + where +
                " GROUP BY group_key ORDER BY " + order + " LIMIT 1000", values)]

    def requests(self, **filters):
        """Decoded HTTP requests plus metadata-only transport connections, newest first."""
        where, values = self.where(**filters)
        with self.connection() as db:
            flows = [dict(row) for row in db.execute("""SELECT * FROM (
                SELECT session,id,ts,host,method,url,status,error,revision,
                    json_type(data,'$.request') has_request,
                    host_group(host) group_key,lower(host || ' ' || url) search FROM http_flows
                )""" + where, values)]
            # Match decoded flows before applying search/date filters so their packets
            # cannot reappear as apparent requests when the URL is filtered out.
            decoded = set()
            scope = filters.get("session")
            for row in db.execute("""SELECT session,json_extract(data,'$.client') client,
                    json_extract(data,'$.server') server FROM http_flows""" + (" WHERE session=?" if scope else ""),
                                  (scope,) if scope else ()):
                client = json.loads(row["client"]) if row["client"] else None
                server = json.loads(row["server"]) if row["server"] else None
                if client and server:
                    decoded.add((row["session"], client[0], client[1], server[0], server[1], "TCP"))
            # Aggregate before transferring to Python. A busy connection can contain
            # thousands of packets but needs just one metadata row in the browser.
            connections = db.execute("""WITH connections AS (
                SELECT session,ts,title,group_key,search,size,protocol,
                    CASE direction WHEN 'TX' THEN json_extract(data,'$.source')
                        ELSE json_extract(data,'$.destination') END local_ip,
                    CASE direction WHEN 'TX' THEN json_extract(data,'$.source_port')
                        ELSE json_extract(data,'$.destination_port') END local_port,
                    CASE direction WHEN 'TX' THEN json_extract(data,'$.destination')
                        ELSE json_extract(data,'$.source') END remote_ip,
                    CASE direction WHEN 'TX' THEN json_extract(data,'$.destination_port')
                        ELSE json_extract(data,'$.source_port') END remote_port FROM packets
                ) SELECT session,title,group_key,protocol,local_ip,local_port,remote_ip,remote_port,
                    MAX(ts) ts,COUNT(*) count,SUM(size) bytes FROM connections""" + where + """
                GROUP BY session,group_key,protocol,local_ip,local_port,remote_ip,remote_port""", values)
            result = []
            for row in connections:
                key = (row["session"], row["local_ip"], row["local_port"],
                       row["remote_ip"], row["remote_port"], row["protocol"])
                if key in decoded:
                    continue
                result.append({"key": "connection:" + json.dumps((*key, row["group_key"])),
                    "ts": row["ts"], "host": row["title"], "url": "",
                    "count": row["count"], "bytes": row["bytes"],
                    "packet": {"source": row["local_ip"], "source_port": row["local_port"],
                               "destination": row["remote_ip"], "destination_port": row["remote_port"],
                               "protocol": row["protocol"]}})
            for flow in flows:
                flow["key"] = "http:" + json.dumps([flow["session"], flow["id"]])
                # A TLS failure has a host but no observed HTTP URL.
                if flow["has_request"] in (None, "null"):
                    flow["url"] = ""
                result.append(flow)
            return sorted(result, key=lambda item: (item["ts"], item["key"]), reverse=True)

    def request_detail(self, row):
        if "packet" in row:
            return row
        flow = self.http_detail(row["session"], row["id"])
        return {**row, "flow": flow} if flow else None

    def packets(self, *, offset=0, limit=300, sort="time_desc", **filters):
        order = {
            "time_asc": "ts ASC,id ASC", "time_desc": "ts DESC,id DESC",
            "size_asc": "size ASC,ts DESC,id DESC", "size_desc": "size DESC,ts DESC,id DESC",
        }.get(sort)
        if order is None:
            raise ValueError("Невідоме сортування пакетів.")
        where, values = self.where(**filters)
        with self.connection() as db:
            total = db.execute("SELECT COUNT(*) FROM packets" + where, values).fetchone()[0]
            rows = db.execute("SELECT id,ts,data FROM packets" + where +
                              " ORDER BY " + order + " LIMIT ? OFFSET ?", [*values, limit, offset])
            return total, [(row["id"], row["ts"], json.loads(row["data"])) for row in rows]

    def sessions(self):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM sessions ORDER BY started DESC LIMIT 100")]

    def import_logs(self, folder):
        with self.history_lock:
            return self._import_logs(folder)

    def clear_logs(self):
        """Clear all history and its JSONL sources so it stays cleared on restart."""
        with self.history_lock:
            files = 0
            for path in sorted(self.path.parent.glob("*.jsonl")):
                if path.is_file() and not path.is_symlink():
                    path.unlink()
                    files += 1
            with self.connection() as db:
                count = db.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
                db.execute("DELETE FROM packets")
                db.execute("DELETE FROM http_flows")
                db.execute("DELETE FROM sessions")
                db.execute("DELETE FROM imports")
            with self.connection() as db:
                db.execute("VACUUM")
                db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return {"packets": count, "files": files}

    def _import_logs(self, folder):
        imported = 0
        for path in sorted(Path(folder).glob("*.jsonl")):
            if path.is_symlink():
                continue
            size = path.stat().st_size
            with self.connection() as db:
                previous = db.execute("SELECT size FROM imports WHERE path=?", (str(path.absolute()),)).fetchone()
            if previous and previous[0] == size:
                continue
            identifier = "jsonl:" + str(uuid.uuid5(uuid.NAMESPACE_URL, str(path.absolute())))
            self.session(identifier, {}, "JSONL", path.stat().st_mtime)
            packets, origins = [], []
            with path.open(encoding="utf-8") as stream:
                for index, line in enumerate(stream):
                    try:
                        value = json.loads(line)
                        if value.get("type") == "session":
                            with self.connection() as db:
                                db.execute("UPDATE sessions SET started=?,name=?,ip=?,mac=?,mode=? WHERE id=?",
                                           (datetime.fromisoformat(value["started_at"]).timestamp(), value.get("target_name"),
                                            value.get("target_ip"), value.get("target_mac"), value.get("mode"), identifier))
                        elif value.get("type") == "packet":
                            group_for(value)
                            datetime.fromisoformat(value["timestamp"])
                            packets.append(value)
                            origins.append(f"{identifier}:{index}")
                        elif value.get("type") == "summary":
                            self.finish(identifier, value.get("error"))
                    except (ValueError, KeyError, TypeError):
                        continue
                    if len(packets) >= 500:
                        self.record(identifier, packets, origins)
                        imported += len(packets)
                        packets, origins = [], []
            if packets:
                self.record(identifier, packets, origins)
                imported += len(packets)
            with self.connection() as db:
                db.execute("INSERT OR REPLACE INTO imports VALUES(?,?)", (str(path.absolute()), size))
        return imported
