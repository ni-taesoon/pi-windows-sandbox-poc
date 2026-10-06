"""Pure online-PDF fixture mocks. Never import wheels, invoke pip or open sockets."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/'scripts/python-online-pdf-fixture.py'
spec = importlib.util.spec_from_file_location('online_pdf_fixture', SOURCE)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class OnlineFixtureTests(unittest.TestCase):
    def report(self):
        return {'version': '1', 'install': [
            {'metadata': {'name': name, 'version': version}, 'requested': True, 'is_direct': True,
             'download_info': {'url': 'http://127.0.0.1:43873/wheels/'+filename,
                               'archive_info': {'hashes': {'sha256': digest}}}}
            for name, version, filename, digest in fixture.PINS]}

    def verify_report(self, report):
        with patch.object(fixture.pathlib.Path, 'stat', return_value=SimpleNamespace(st_size=4096)), \
                patch.object(fixture.pathlib.Path, 'read_text', return_value=json.dumps(report)):
            return fixture.verify_report()

    def test_three_package_pins_match_registry_lock_and_rust_constants(self):
        packages = json.loads((ROOT/'scripts/python-online-pdf-packages.json').read_text())['packages']
        self.assertEqual(fixture.PINS, tuple((p['name'],p['version'],p['filename'],p['sha256']) for p in packages))
        native = (ROOT/'native/windows-sandbox/src/python_isolation.rs').read_text()
        for name, version, filename, digest in fixture.PINS:
            for value in [name, version, filename, digest]:
                self.assertIn('"'+value+'"', native)
        self.assertEqual(fixture.MODES, {'online-install','online-pdf'})

    def test_pip_is_fixed_online_direct_wheels_not_source_build_or_host_install(self):
        args = fixture.PIP_ARGS
        for flag in ['--no-index', '--require-hashes', '--only-binary=:all:', '--no-deps',
                     '--no-cache-dir', '--no-compile', '--disable-pip-version-check']:
            self.assertIn(flag, args)
        self.assertEqual(args[args.index('--target')+1], str(fixture.DEPS))
        self.assertEqual(args[args.index('--retries')+1], '0')
        self.assertNotIn('--trusted-host', args)
        self.assertNotIn('--user', args)
        source = SOURCE.read_text()
        self.assertIn('runpy.run_module("pip", run_name="__main__", alter_sys=True)', source)
        self.assertNotIn('pip._internal', source)
        self.assertNotIn('ensurepip', source)
        self.assertNotIn('subprocess', source)
        self.assertIn('"PIP_CONFIG_FILE": os.devnull', source)

    def test_environment_discards_all_unapproved_configuration(self):
        with patch.dict(os.environ, {'HTTPS_PROXY':'bad', 'PIP_INDEX_URL':'bad', 'SSL_CERT_FILE':'bad'}, clear=True), \
                patch.object(fixture.os, 'devnull', 'nul'):
            fixture.sanitize_environment()
            self.assertEqual(set(os.environ), {'SystemRoot','WINDIR','TEMP','TMP','PIP_CONFIG_FILE'})
            self.assertEqual(os.environ['PIP_CONFIG_FILE'], 'nul')
            self.assertEqual(os.environ['TEMP'], str(fixture.WORK))

    def test_exact_three_live_relay_receipts_required(self):
        self.assertTrue(self.verify_report(self.report()))
        for change in ['version','url','hash','requested','is_direct','duplicate','missing']:
            r = self.report()
            if change == 'version': r['install'][0]['metadata']['version']='0'
            elif change == 'url': r['install'][0]['download_info']['url']='https://pypi.org/other'
            elif change == 'hash': r['install'][0]['download_info']['archive_info']['hashes']['sha256']='0'*64
            elif change in ('requested','is_direct'): r['install'][0][change]=False
            elif change == 'duplicate': r['install'][1]=r['install'][0]
            else: r['install'].pop()
            with self.subTest(change=change), self.assertRaises(RuntimeError): self.verify_report(r)

    def test_distribution_inventory_rejects_extra_wrong_and_duplicate_packages(self):
        valid = [SimpleNamespace(metadata={'Name': n},version=v) for n,v,_,_ in fixture.PINS]
        with patch.object(fixture.importlib.metadata, 'distributions', return_value=valid) as discover:
            self.assertEqual(len(fixture.distribution_evidence()),3)
            discover.assert_called_once_with(path=[str(fixture.DEPS)])
        for values in [valid[:-1], valid+[valid[0]], [SimpleNamespace(metadata={'Name':'reportlab'},version='0'),*valid[1:]]]:
            with patch.object(fixture.importlib.metadata, 'distributions', return_value=values), self.assertRaises(RuntimeError):
                fixture.distribution_evidence()

    def test_prestaged_target_blocks_install_before_pip(self):
        with patch.object(fixture.pathlib.Path, 'exists', return_value=True), \
                patch.object(fixture.runpy, 'run_module') as pip:
            with self.assertRaises(RuntimeError): fixture.online_install()
            pip.assert_not_called()

    def test_imports_are_target_only_and_native_pillow_is_required(self):
        def module(name):
            filename = '_imaging.pyd' if name=='PIL._imaging' else '__init__.py'
            return SimpleNamespace(__file__=str(fixture.DEPS/name/filename))
        with patch.object(fixture.pathlib.Path, 'resolve', autospec=True, side_effect=lambda p,strict: p), \
                patch.object(fixture.importlib, 'import_module', side_effect=module):
            self.assertEqual(len(fixture.import_evidence()),4)
        for origin in [fixture.ROOT/'runtime'/'wrong.py', fixture.DEPS/'PIL'/'_imaging.py']:
            with patch.object(fixture.pathlib.Path, 'resolve', autospec=True, side_effect=lambda p,strict: p), \
                    patch.object(fixture.importlib, 'import_module', return_value=SimpleNamespace(__file__=str(origin))), \
                    self.assertRaises(RuntimeError):
                fixture.import_evidence()

    def test_output_is_bounded_in_utf8_bytes(self):
        output = fixture.BoundedOutput()
        self.assertEqual(output.write('한'*10000),10000)
        self.assertLessEqual(len(output.value().encode('utf-8')),1024)
        self.assertTrue(output.truncated)
        output.write('extra')
        self.assertLessEqual(output.size,1024)

    def test_fixed_pdf_metadata_shape_and_no_external_inputs(self):
        source = SOURCE.read_text()
        for required in ['pagesize=A4', 'pdfVersion=(1, 4)', 'pageCompression=0', 'invariant=1',
                         'canvas.setTitle("Sandbox PDF test")', 'canvas.setAuthor("Pi sandbox")',
                         'canvas.setCreator("Pi sandbox PDF acceptance")', 'canvas.setFont("Helvetica", 12)',
                         'canvas.drawString(72, 720, "Sandbox PDF test")', 'PDF.open("xb")']:
            self.assertIn(required,source)
        for forbidden in ['drawImage(', 'registerFont(', 'requests.', 'urllib.', 'eval(', 'exec(']:
            self.assertNotIn(forbidden,source)


if __name__ == '__main__':
    unittest.main()
