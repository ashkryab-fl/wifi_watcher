import tempfile
import threading
import unittest
from pathlib import Path

from wifi_watcher.https_view import detail_sections, request_groups
from wifi_watcher.store import Store, remove_saved_history
from test_history import packet
from test_https import fixture


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.store.session('current', {}, 'HTTPS IPv4')

    def tearDown(self):
        self.store.close()

    def flow(self, identifier='one', url='https://api.example/test?a=1', ts=1792062000, **changes):
        flow = {**fixture(), 'id': identifier, 'url': url, 'ts': ts, **changes}
        self.store.record_http('current', flow)
        return flow

    def test_memory_store_shared_between_threads_and_discarded_on_new_session(self):
        self.flow()
        thread = threading.Thread(target=lambda: self.store.record('current', [packet()]))
        thread.start()
        thread.join()
        self.assertEqual(self.store.packets()[0], 1)
        self.assertEqual(len(self.store.requests()), 2)
        self.assertIsNone(self.store.path)
        self.store.session('next', {}, 'HTTPS IPv4')
        self.assertEqual(self.store.requests(), [])
        self.assertEqual(self.store.sessions()[0]['id'], 'next')
        self.assertEqual(self.store.packets()[0], 0)
        other = Store()
        self.assertEqual(other.groups(), [])
        other.close()

    def test_path_groups_ignore_query_and_keep_repeated_requests_in_time_order(self):
        self.flow('old', ts=10)
        self.flow('new', url='https://api.example/test?a=2', ts=30)
        self.flow('middle', url='https://api.example/other', ts=20)
        groups = request_groups(self.store.requests())
        self.assertEqual([g['text'] for g in groups], ['/test', '/other'])
        self.assertEqual([r['id'] for r in groups[0]['rows']], ['new', 'old'])
        self.assertEqual(groups[0]['rows'][0]['url'], 'https://api.example/test?a=2')

    def test_paths_remain_distinct_across_hosts_and_encoded_paths(self):
        self.flow('a', url='https://api.example/a%2Fb', ts=1)
        self.flow('b', url='https://api.example/a/b', ts=2)
        self.flow('c', url='https://other.example/a/b', host='other.example', ts=3)
        self.assertEqual(len(request_groups(self.store.requests())), 3)

    def test_http_only_host_is_present_on_main_page_with_literal_url_search(self):
        self.flow(url='https://api.example/test?literal=%_')
        groups = self.store.groups(search='%_')
        self.assertEqual(groups[0]['group_key'], 'domain:api.example')
        self.assertEqual(len(self.store.requests(group='domain:api.example', search='%_')), 1)
        self.assertEqual(self.store.requests(group='domain:other.example'), [])
        self.assertEqual(self.store.requests(search="' OR 1=1 --"), [])

    def test_http_filters_cover_session_time_and_domains_only(self):
        self.flow(ts=1792062000)
        self.flow('ip', url='https://203.0.113.1/a', host='203.0.113.1', ts=1792062001)
        self.assertEqual(len(self.store.requests(domains_only=True)), 1)
        self.assertEqual(len(self.store.requests(start=1792062001, end=1792062002)), 1)
        self.assertEqual(self.store.requests(session='other'), [])
        self.assertEqual(self.store.requests(end=1792062000), [])
        self.assertEqual([g['title'] for g in self.store.groups(domains_only=True)], ['api.example'])

    def test_same_connection_packets_collapse_to_domain_or_ip_fallback(self):
        self.store.record('current', [packet(), packet(direction='RX'), packet(None, address='203.0.113.1')])
        rows = self.store.requests()
        self.assertEqual(len(rows), 2)
        names = {r['host']: r for r in rows}
        self.assertEqual(names['one.example']['count'], 2)
        groups = request_groups(rows)
        self.assertTrue(all(not group['rows'] for group in groups))
        self.assertEqual(set(g['text'] for g in groups), {'one.example', '203.0.113.1'})
        overview, request, response = detail_sections(names['one.example'])
        self.assertIn('лише метадані', overview)
        self.assertIn('недоступний', request)
        self.assertIn('недоступна', response)

    def test_decoded_connection_does_not_duplicate_its_packets_or_hide_other_connections(self):
        self.store.record('current', [packet('api.example'), packet('api.example', direction='RX')])
        other = packet('api.example')
        other['source_port'] = 52000
        self.store.record('current', [other])
        self.flow(client=['192.168.0.50', 51000], server=['198.51.100.10', 443])
        rows = self.store.requests(group='domain:api.example')
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum('packet' in row for row in rows), 1)
        self.assertEqual(self.store.requests(search='not-found'), [])

    def test_tls_failure_uses_host_and_preserves_error_details(self):
        self.flow(method='TLS', request=None, error='TLS failed')
        rows = self.store.requests()
        self.assertEqual(rows[0]['url'], '')
        self.assertEqual(request_groups(rows)[0]['text'], 'api.example')
        overview = detail_sections(self.store.request_detail(rows[0]))[0]
        self.assertIn('TLS failed', overview)
        self.assertIn('Статус: помилка', overview)
        self.assertNotIn('очікування', overview)

    def test_response_updates_original_request_without_changing_tree_identity(self):
        self.flow()
        first = self.store.requests()[0]
        self.flow(status=200, response=fixture()['request'])
        second = self.store.requests()[0]
        self.assertEqual(first['key'], second['key'])
        self.assertGreater(second['revision'], first['revision'])
        self.assertNotIn('data', second)
        overview, request, response = detail_sections(self.store.request_detail(second))
        self.assertIn('Статус: 200', overview)
        self.assertIn('"test": true', request)
        self.assertIn('"test": true', response)

    def test_old_history_cleanup_preserves_ca_and_symlink_targets(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as outside:
            folder = Path(folder)
            names = ('traffic.sqlite3', 'traffic.sqlite3-wal', 'traffic.sqlite3-shm', 'traffic.sqlite3-journal', 'old.jsonl')
            for name in names:
                (folder / name).write_text('old')
            ca = folder / 'https-ca'
            ca.mkdir()
            (ca / 'private.pem').write_text('keep')
            target = Path(outside) / 'external.jsonl'
            target.write_text('keep')
            (folder / 'linked.jsonl').symlink_to(target)
            remove_saved_history(folder)
            self.assertTrue(all(not (folder / name).exists() for name in names))
            self.assertEqual((ca / 'private.pem').read_text(), 'keep')
            self.assertEqual(target.read_text(), 'keep')
            self.assertTrue((folder / 'linked.jsonl').is_symlink())
            remove_saved_history(folder)


if __name__ == '__main__':
    unittest.main()
