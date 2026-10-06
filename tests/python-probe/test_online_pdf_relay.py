"""Pure mocks: never bind sockets, fetch packages, install or change security."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'scripts/python-online-pdf-relay.py'
spec = importlib.util.spec_from_file_location('fixed_pdf_relay', SOURCE)
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class Response(io.BytesIO):
    def __init__(self, data, url, length=None, status=200, encoding='identity'):
        super().__init__(data)
        self.url, self.status = url, status
        self.headers = {'Content-Length': str(len(data) if length is None else length),
                        'Content-Encoding': encoding}
    def geturl(self):
        return self.url


class RelayTests(unittest.TestCase):
    def package(self, data=b'synthetic'):
        return {'name': 'synthetic', 'filename': 'synthetic.whl',
                'url': 'https://files.pythonhosted.org/packages/fixed/synthetic.whl',
                'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def fetch(self, package, response, events):
        context = SimpleNamespace(check_hostname=True, verify_mode=relay.ssl.CERT_REQUIRED)
        opener = Mock()
        opener.open.return_value = response
        with patch.object(relay.ssl, 'create_default_context', return_value=context), \
                patch.object(relay.urllib.request, 'build_opener', return_value=opener) as build:
            result = relay.fetch_wheel(package, lambda event, **fields: events.append((event, fields)),
                                       relay.time.monotonic() + 10)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, package['url'])
        self.assertEqual(request.get_method(), 'GET')
        self.assertEqual(opener.open.call_args.kwargs, {'timeout': 20})
        self.assertIsInstance(build.call_args.args[0], relay.urllib.request.ProxyHandler)
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[2], relay.NoRedirect)
        return result

    def test_live_fetch_verifies_complete_bytes_before_forwardable_result(self):
        package = self.package()
        events = []
        self.assertEqual(self.fetch(package, Response(b'synthetic', package['url']), events), b'synthetic')
        self.assertEqual([event for event, _ in events], ['upstream_fetch_started', 'upstream_hash_verified'])
        self.assertEqual(events[1][1], {'bytes': 9, 'sha256': package['sha256']})

    def test_wrong_hash_or_short_long_payload_never_produces_verified_event(self):
        for data in [b'corrupted', b'short', b'synthetic-plus']:
            package = self.package()
            events = []
            with self.subTest(data=data), self.assertRaises(RuntimeError):
                self.fetch(package, Response(data, package['url'], length=package['size']), events)
            self.assertNotIn('upstream_hash_verified', [event for event, _ in events])

    def test_status_redirect_encoding_and_length_are_rejected(self):
        package = self.package()
        responses = [Response(b'synthetic', package['url'], status=302),
                     Response(b'synthetic', 'https://other.invalid/wheel'),
                     Response(b'synthetic', package['url'], encoding='gzip'),
                     Response(b'synthetic', package['url'], length=10)]
        for response in responses:
            with self.subTest(response=response), self.assertRaises(RuntimeError):
                self.fetch(package, response, [])
        with self.assertRaises(RuntimeError):
            relay.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.invalid/')

    def test_tls_verification_cannot_be_disabled(self):
        for context in [SimpleNamespace(check_hostname=False, verify_mode=relay.ssl.CERT_REQUIRED),
                        SimpleNamespace(check_hostname=True, verify_mode=relay.ssl.CERT_NONE)]:
            with patch.object(relay.ssl, 'create_default_context', return_value=context), \
                    patch.object(relay.urllib.request, 'build_opener') as opener:
                with self.assertRaises(RuntimeError):
                    relay.fetch_wheel(self.package(), Mock(), relay.time.monotonic() + 10)
                opener.assert_not_called()

    def handler(self, path):
        handler = relay.Handler.__new__(relay.Handler)
        handler.path, handler.headers = path, {}
        handler.reply = Mock()
        handler.server = SimpleNamespace(requests=0, deadline=relay.time.monotonic()+10,
            routes={'/wheels/synthetic.whl': self.package()}, requested=set(), fetch_count=0, record=Mock())
        return handler

    def test_owner_health_never_triggers_package_fetch(self):
        handler = self.handler('/health')
        with patch.object(relay, 'fetch_wheel') as fetch:
            handler.do_GET()
        fetch.assert_not_called()
        self.assertEqual(handler.server.fetch_count, 0)
        self.assertEqual(json.loads(handler.reply.call_args.args[1]), {'schemaVersion': 1, 'packageFetchCount': 0})

    def test_actual_request_is_required_and_each_wheel_fetches_only_once(self):
        handler = self.handler('/wheels/synthetic.whl')
        with patch.object(relay, 'fetch_wheel', return_value=b'synthetic') as fetch:
            handler.do_GET()
            self.assertEqual(fetch.call_count, 1)
            handler.do_GET()
            self.assertEqual(fetch.call_count, 1)
        self.assertEqual(handler.server.fetch_count, 1)
        events = [call.args[0] for call in handler.server.record.call_args_list]
        self.assertEqual(events, ['package_request', 'wheel_served', 'request_rejected'])
        self.assertEqual(handler.reply.call_args.args[0], 403)

    def test_unapproved_route_upload_tunnel_and_body_do_not_fetch(self):
        with patch.object(relay, 'fetch_wheel') as fetch:
            for path in ['/wheels/synthetic.whl?x=1', 'https://files.pythonhosted.org/evil',
                         '/wheels/../synthetic.whl', '/unknown']:
                handler = self.handler(path)
                handler.do_GET()
                self.assertEqual(handler.reply.call_args.args[0], 403)
            for method in ['do_CONNECT', 'do_POST', 'do_HEAD']:
                handler = self.handler('/wheels/synthetic.whl')
                getattr(handler, method)()
            handler = self.handler('/wheels/synthetic.whl')
            handler.headers = {'Content-Length': '1'}
            handler.do_GET()
        fetch.assert_not_called()

    def test_failed_online_fetch_is_not_replaced_with_cached_payload(self):
        handler = self.handler('/wheels/synthetic.whl')
        with patch.object(relay, 'fetch_wheel', side_effect=TimeoutError('do not publish message')):
            handler.do_GET()
        self.assertEqual(handler.reply.call_args.args[0], 502)
        last = handler.server.record.call_args
        self.assertEqual(last.args[0], 'fetch_failed')
        self.assertEqual(last.kwargs['errorType'], 'TimeoutError')
        self.assertNotIn('do not publish', str(last))

    def test_manifest_has_only_exact_approved_non_yanked_registry_wheels(self):
        manifest = json.loads((ROOT/'scripts/python-online-pdf-packages.json').read_text())
        with patch.object(relay.pathlib.Path, 'stat', return_value=SimpleNamespace(st_size=10000)), \
                patch.object(relay.pathlib.Path, 'read_text', return_value=json.dumps(manifest)):
            routes = relay.load_manifest()
        self.assertEqual(len(routes), 3)
        self.assertEqual(sum(p['size'] for p in routes.values()), 9253267)
        requirements = (ROOT/'scripts/python-online-pdf-requirements.txt').read_text()
        for route, package in routes.items():
            self.assertIn('http://127.0.0.1:43873'+route, requirements)
            self.assertIn('--hash=sha256:'+package['sha256'], requirements)
        for bad in ['https://files.pythonhosted.org.evil.invalid/a.whl',
                    'http://files.pythonhosted.org/a.whl', 'https://user@files.pythonhosted.org/a.whl']:
            manifest['packages'][0]['url'] = bad
            with patch.object(relay.pathlib.Path, 'stat', return_value=SimpleNamespace(st_size=10000)), \
                    patch.object(relay.pathlib.Path, 'read_text', return_value=json.dumps(manifest)), \
                    self.assertRaises(RuntimeError):
                relay.load_manifest()

    def test_fixed_launch_and_absolute_lifetime_are_source_gated(self):
        source = SOURCE.read_text()
        for text in ['socket.SO_EXCLUSIVEADDRUSE', 'LIFETIME_SECONDS = 300',
                     'threading.Timer(LIFETIME_SECONDS, os._exit, args=(124,))',
                     'len(sys.argv) != 1', 'pathlib.Path.cwd() != TRUSTED',
                     'sys.version_info[:3] != (3, 12, 10)', 'NoRedirect()',
                     'upstream_hash_verified', 'wheel_served']:
            self.assertIn(text, source)
        self.assertNotIn('subprocess', source)
        self.assertNotIn('import reportlab', source)
        self.assertNotIn('CERT_NONE', source)
        self.assertNotIn('cache_dir', source)


if __name__ == '__main__':
    unittest.main()
