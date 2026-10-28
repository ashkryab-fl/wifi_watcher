import json
import tempfile
import unittest
from pathlib import Path

from wifi_watcher.store import Store, group_for, time_range


def packet(domain="one.example", *, stamp="2026-10-15T10:00:00+00:00", direction="TX", size=100, address="198.51.100.10", evidence="tls_sni"):
    return {"timestamp": stamp, "direction": direction, "protocol": "TCP",
            "source": "192.168.0.50" if direction == "TX" else address,
            "destination": address if direction == "TX" else "192.168.0.50",
            "source_port": 51000 if direction == "TX" else 443,
            "destination_port": 443 if direction == "TX" else 51000,
            "source_domains": [] if direction == "TX" or domain is None else [domain],
            "destination_domains": [domain] if direction == "TX" and domain else [],
            "source_domain_source": evidence if direction == "RX" and domain else None,
            "destination_domain_source": evidence if direction == "TX" and domain else None,
            "bytes": size, "captured_bytes": size}


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.folder.name) / "traffic.sqlite3")
        self.store.session("s1", {"name": "Pixel", "ip": "192.168.0.50"}, "RELAY")

    def tearDown(self):
        self.folder.cleanup()

    def test_shared_cdn_ip_has_separate_domain_groups(self):
        self.store.record("s1", [packet("one.example"), packet("two.example"), packet("one.example", direction="RX", size=500)])
        groups = {row["title"]: row for row in self.store.groups()}
        self.assertEqual(set(groups), {"one.example", "two.example"})
        self.assertEqual((groups["one.example"]["count"], groups["one.example"]["tx"], groups["one.example"]["rx"]), (2, 100, 500))

    def test_domain_detail_contains_only_its_packets(self):
        self.store.record("s1", [packet("one.example"), packet("two.example")])
        total, rows = self.store.packets(group="domain:one.example")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0][2]["destination_domains"], ["one.example"])

    def test_domain_name_sort_both_directions_and_case_insensitive(self):
        self.store.record("s1", [packet("Zebra.example"), packet("alpha.example"), packet("Beta.example")])
        ascending = [row["title"] for row in self.store.groups(sort="name_asc")]
        self.assertEqual(ascending, ["alpha.example", "Beta.example", "Zebra.example"])
        self.assertEqual([row["title"] for row in self.store.groups(sort="name_desc")], ascending[::-1])

    def test_group_time_and_byte_totals_sort_numerically(self):
        self.store.record("s1", [packet("a.example", size=900, stamp="2026-10-15T10:00:00+00:00"),
                                 packet("a.example", size=800, direction="RX"),
                                 packet("b.example", size=80, stamp="2026-10-15T11:00:00+00:00"),
                                 packet("b.example", size=90, direction="RX"),
                                 packet("b.example", size=20)])
        for key, ascending in (("tx", ["b.example", "a.example"]), ("rx", ["b.example", "a.example"]),
                               ("last", ["a.example", "b.example"])):
            with self.subTest(key=key):
                self.assertEqual([g["title"] for g in self.store.groups(sort=key + "_asc")], ascending)
                self.assertEqual([g["title"] for g in self.store.groups(sort=key + "_desc")], ascending[::-1])

    def test_packet_size_sort_precedes_pagination_and_has_stable_ties(self):
        self.store.record("s1", [packet(size=1000-i) for i in range(305)] + [packet(size=1)])
        total, page = self.store.packets(sort="size_asc", limit=300)
        self.assertEqual(total, 306)
        self.assertEqual(page[0][2]["bytes"], 1)
        self.assertEqual([p[2]["bytes"] for p in page], sorted(p[2]["bytes"] for p in page))
        rest = self.store.packets(sort="size_asc", offset=300)[1]
        self.assertEqual(len({p[0] for p in page + rest}), 306)
        self.assertEqual(self.store.packets(sort="size_desc", limit=1)[1][0][2]["bytes"], 1000)

    def test_packet_time_sort_both_directions_with_filter(self):
        self.store.record("s1", [packet(size=1, stamp="2026-10-15T11:00:00+00:00"), packet(size=2),
                                 packet("other.example", size=3)])
        self.assertEqual([p[2]["bytes"] for p in self.store.packets(sort="time_asc", group="domain:one.example")[1]], [2, 1])
        self.assertEqual([p[2]["bytes"] for p in self.store.packets(sort="time_desc", group="domain:one.example")[1]], [1, 2])

    def test_name_sort_is_applied_before_group_limit(self):
        values = [packet(f"z{index:04}.example") for index in range(1000)]
        values.append(packet("a.example", stamp="2026-01-01T00:00:00+00:00"))
        self.store.record("s1", values)
        groups = self.store.groups(sort="name_asc")
        self.assertEqual(len(groups), 1000)
        self.assertEqual(groups[0]["title"], "a.example")

    def test_domains_only_filters_groups_and_packets_without_deleting_them(self):
        self.store.record("s1", [packet("named.example"), packet("named.example", direction="RX"), packet(None)])
        groups = self.store.groups(domains_only=True, search="example")
        self.assertEqual([row["title"] for row in groups], ["named.example"])
        self.assertEqual(groups[0]["count"], 2)
        self.assertEqual(self.store.packets(domains_only=True)[0], 2)
        self.assertEqual(self.store.packets(domains_only=True, group="ip:198.51.100.10")[0], 0)
        self.assertEqual(self.store.packets()[0], 3)

    def test_search_is_literal_and_works_on_both_pages(self):
        self.store.record("s1", [packet("one.example"), packet("two.example")])
        self.assertEqual([row["title"] for row in self.store.groups(search="ONE")], ["one.example"])
        self.assertEqual(self.store.packets(search="one.example")[0], 1)
        self.assertEqual(self.store.groups(search="%"), [])
        self.assertEqual(self.store.groups(search="' OR 1=1 --"), [])

    def test_time_range_is_inclusive_to_the_last_second(self):
        self.store.record("s1", [packet(stamp="2026-10-15T10:00:00+00:00"),
                                 packet(stamp="2026-10-15T10:00:01.500000+00:00"),
                                 packet(stamp="2026-10-15T10:00:02+00:00")])
        start, end = time_range("2026-10-15 13:00:00", "2026-10-15 13:00:01")
        self.assertEqual(self.store.packets(start=start, end=end)[0], 2)
        self.assertEqual(self.store.groups(start=start, end=end)[0]["count"], 2)

    def test_day_range_empty_bounds_and_invalid_ranges(self):
        start, end = time_range("2026-10-15", "2026-10-15")
        self.assertEqual(end - start, 86400)
        self.assertEqual(time_range(), (None, None))
        for first, last in (("bad", ""), ("2026-10-16", "2026-10-15")):
            with self.assertRaises(ValueError):
                time_range(first, last)

    def test_unknown_and_ambiguous_names_stay_in_ip_group_but_are_searchable(self):
        value = packet("a.example", evidence="dns")
        value["destination_domains"] = ["a.example", "b.example"]
        self.store.record("s1", [value, packet(None)])
        self.assertEqual(self.store.groups()[0]["group_key"], "ip:198.51.100.10")
        self.assertEqual(self.store.groups(search="b.example")[0]["count"], 1)
        self.assertEqual(group_for(packet("public.example", evidence="tls_sni_outer"))[0], "ip:198.51.100.10")

    def test_sessions_and_packet_pagination_survive_reopening(self):
        self.store.session("s2", {"name": "Other"}, "PASSIVE")
        self.store.record("s1", [packet(size=i) for i in range(20)])
        self.store.record("s2", [packet("other.example")])
        self.store.finish("s1")
        reopened = Store(self.store.path)
        total, rows = reopened.packets(session="s1", offset=5, limit=5)
        self.assertEqual(total, 20)
        self.assertEqual([row[2]["bytes"] for row in rows], [14, 13, 12, 11, 10])
        self.assertEqual(len(reopened.sessions()), 2)
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)

    def test_jsonl_import_is_idempotent_and_resumes_after_append(self):
        path = Path(self.folder.name) / "old.jsonl"
        session = {"type": "session", "started_at": "2026-10-15T10:00:00+00:00", "target_name": "Phone", "target_ip": "192.168.0.50", "target_mac": "02:00:00:00:00:50", "mode": "RELAY"}
        path.write_text(json.dumps(session) + "\n" + json.dumps({"type": "packet", **packet()}) + "\n")
        self.store.import_logs(self.folder.name)
        self.store.import_logs(self.folder.name)
        self.assertEqual(self.store.packets()[0], 1)
        with path.open("a") as output:
            output.write(json.dumps({"type": "packet", **packet("two.example")}) + "\n")
        self.store.import_logs(self.folder.name)
        self.assertEqual(self.store.packets()[0], 2)
        self.assertTrue(any(row["name"] == "Phone" for row in self.store.sessions()))

    def test_clear_removes_all_history_and_jsonl_sources_without_reimport(self):
        path = Path(self.folder.name) / "old.jsonl"
        path.write_text(json.dumps({"type": "packet", **packet("imported.example")}) + "\n")
        unrelated = Path(self.folder.name) / "keep.txt"
        unrelated.write_text("keep")
        self.store.record("s1", [packet("one.example"), packet("two.example")])
        self.store.import_logs(self.folder.name)
        result = self.store.clear_logs()
        self.assertEqual(result, {"packets": 3, "files": 1})
        self.assertFalse(path.exists())
        self.assertEqual(unrelated.read_text(), "keep")
        reopened = Store(self.store.path)
        reopened.import_logs(self.folder.name)
        self.assertEqual(reopened.sessions(), [])
        self.assertEqual(reopened.groups(), [])
        self.assertEqual(reopened.packets()[0], 0)
        reopened.session("new", {"name": "New"}, "TEST")
        reopened.record("new", [packet("new.example")])
        self.assertEqual(reopened.groups()[0]["title"], "new.example")

    def test_clear_skips_symlink_sources_and_is_repeatable(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "external.jsonl"
            target.write_text("external")
            (Path(self.folder.name) / "link.jsonl").symlink_to(target)
            self.assertEqual(self.store.clear_logs(), {"packets": 0, "files": 0})
            self.assertEqual(self.store.clear_logs(), {"packets": 0, "files": 0})
            self.assertEqual(target.read_text(), "external")


if __name__ == "__main__":
    unittest.main()
