"""Controller checks are headless; native Tk checks require explicit opt-in."""
import os
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

try:
    import tkinter as tk
    from wifi_watcher.gui import Application
except ImportError:
    tk = None

from wifi_watcher.store import Store
from wifi_watcher.https import CA_DIR
from test_history import packet
from test_https import fixture


@unittest.skipUnless(tk is not None, 'Tk module unavailable')
class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.app = Application.__new__(Application)
        self.app.interface = Mock(get=lambda: 'en0')
        self.app.gateway = Mock(get=lambda: '192.168.0.1')
        self.app.device_box = Mock()
        self.app.device_box.current.return_value = 0
        self.app.devices = [{'ip': '192.168.0.50', 'mac': '02:00:00:00:00:50', 'name': 'Pixel'}]
        self.app.lan_ip = '192.168.0.108'
        self.app.set_status = Mock()
        self.app.request = Mock()

    def test_scan_requests_names_automatically(self):
        credentials = {'username': 'admin', 'password': 'test-password'}
        with patch('wifi_watcher.gui.router_credentials', return_value=credentials):
            self.app.scan()
        self.assertEqual(self.app.request.call_args.args[0], {
            'op': 'scan', 'interface': 'en0', 'gateway': '192.168.0.1', 'router': credentials})

    def test_https_is_always_requested_for_external_device(self):
        with patch('wifi_watcher.gui.executable', return_value='/mitmdump'), \
                patch.object(Path, 'is_file', return_value=True):
            self.app.connect()
        self.assertEqual(self.app.request.call_args.args[0]['https']['binary'], '/mitmdump')
        self.assertEqual(self.app.request.call_args.args[0]['mac'], self.app.devices[0]['mac'])
        self.assertFalse(hasattr(self.app, 'https_enabled'))

    def test_missing_ca_prevents_start(self):
        with patch('wifi_watcher.gui.executable', return_value='/mitmdump'), \
                patch.object(Path, 'is_file', return_value=False):
            self.app.connect()
        self.app.request.assert_not_called()
        self.assertIn('Сертифікат HTTPS', self.app.set_status.call_args.args[1])

    def test_missing_proxy_prevents_start_without_falling_back(self):
        with patch('wifi_watcher.gui.executable', side_effect=RuntimeError('missing mitmproxy')):
            self.app.connect()
        self.app.request.assert_not_called()
        self.assertEqual(self.app.set_status.call_args.args[0], 'HTTPS не підготовлено')

    def test_this_mac_requests_https_instead_of_silently_capturing_only_metadata(self):
        self.app.devices[0]['ip'] = self.app.lan_ip
        with patch('wifi_watcher.gui.executable', return_value='/mitmdump'), \
                patch.object(Path, 'is_file', return_value=True):
            self.app.connect()
        self.assertEqual(self.app.request.call_args.args[0]['https'], {
            'binary': '/mitmdump', 'directory': str(CA_DIR)})

    def test_disconnect_waits_for_helper_cleanup(self):
        self.app.demo_id = None
        self.app.active = True
        self.app.disconnect()
        self.app.request.assert_called_once_with({'op': 'disconnect'})
        self.assertTrue(self.app.active)


@unittest.skipUnless(tk is not None and os.environ.get('WIFI_WATCHER_GUI_TESTS') == '1',
                     'Native UI checks require WIFI_WATCHER_GUI_TESTS=1')
class GuiTests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.store = Store()
        with patch('wifi_watcher.gui.interfaces', return_value=['en0']):
            self.app = Application(self.root, self.store, 'en0', '192.168.0.1')
        self.pump(.2)

    def tearDown(self):
        if self.app.alive:
            self.app.close()
        self.store.close()

    def pump(self, seconds=.8):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and self.app.alive:
            self.root.update()
            time.sleep(.005)

    def seed(self):
        self.store.session('current', {}, 'HTTPS IPv4')
        self.store.record_http('current', fixture())
        self.app.on_event({'event': 'session', 'session': 'current'})
        self.pump()
        self.app.domain_table.selection_set('domain:api.example')
        self.app.open_domain()
        self.pump()

    def test_settings_are_hidden_and_history_and_https_toggle_are_absent(self):
        self.assertEqual(self.app.settings_window.state(), 'withdrawn')
        self.assertEqual(self.app.scan_button.winfo_toplevel(), self.app.settings_window)
        self.assertFalse(hasattr(self.app, 'history_box'))
        self.assertFalse(hasattr(self.app, 'https_checkbox'))
        self.app.open_settings()
        self.pump(.1)
        self.assertEqual(self.app.settings_window.state(), 'normal')

    def test_request_tree_has_one_column_and_updates_selected_response(self):
        self.seed()
        browser = self.app.request_browser
        self.assertFalse(browser.tree['columns'])
        parent = browser.tree.get_children()[0]
        child = browser.tree.get_children(parent)[0]
        browser.tree.selection_set(child)
        self.pump()
        self.assertIn('POST https://api.example', browser.texts[0].get('1.0', 'end'))
        browser.tree.item(parent, open=False)
        self.store.record_http('current', fixture(200))
        self.app.dirty = True
        self.pump()
        self.assertFalse(browser.tree.item(parent, 'open'))
        self.assertEqual(browser.tree.selection(), (child,))
        self.assertIn('Статус: 200', browser.texts[0].get('1.0', 'end'))

    def test_filters_clear_tree_and_selected_details(self):
        self.seed()
        browser = self.app.request_browser
        parent = browser.tree.get_children()[0]
        browser.tree.selection_set(browser.tree.get_children(parent)[0])
        self.pump()
        self.app.packet_filters.search.set('missing')
        self.pump(1)
        self.assertEqual(browser.tree.get_children(), ())
        self.assertIn('Обери запит', browser.texts[0].get('1.0', 'end'))

    def test_new_session_cannot_restore_rows_from_previous_query(self):
        self.seed()
        signature = (self.app.group, self.app.query_filters())
        rows = self.store.requests()
        self.store.session('new', {}, 'HTTPS IPv4')
        self.app.on_event({'event': 'session', 'session': 'new'})
        self.app.display_query({'signature': signature, 'result': rows})
        self.pump()
        self.assertEqual(self.app.domain_table.get_children(), ())
        self.assertEqual(self.app.request_browser.tree.get_children(), ())


if __name__ == '__main__':
    unittest.main()
