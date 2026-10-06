"""Pure online-PDF fixture mocks. Never import wheels, invoke pip or open sockets."""
import importlib.util
import hashlib
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
            # Windows os.environ normalizes keys to uppercase; preserve the exact allowlist.
            appdirs = {'USERPROFILE','APPDATA','LOCALAPPDATA','WIN_PD_OVERRIDE_LOCAL_APPDATA',
                       'WIN_PD_OVERRIDE_APPDATA','WIN_PD_OVERRIDE_COMMON_APPDATA'}
            self.assertEqual({key.upper() for key in os.environ},
                             {'SYSTEMROOT','WINDIR','TEMP','TMP','PIP_CONFIG_FILE'} | appdirs)
            self.assertEqual(len(os.environ), 11)
            for name in appdirs:
                self.assertEqual(os.environ[name],str(fixture.WORK))
            self.assertEqual(os.environ['PIP_CONFIG_FILE'], 'nul')
            self.assertEqual(os.environ['TEMP'], str(fixture.WORK))

    @unittest.skipUnless(os.name == 'nt', 'exact Windows pip known-folder regression runs in pre-security CI')
    def test_observed_pip_known_folder_resolver_uses_only_work_overrides(self):
        # Read the existing runtime module, not a fetched or newly installed wheel.
        # Exact official pip 26.2.1 bytes match the failed VM inventory.
        module = importlib.import_module('pip._vendor.platformdirs.windows')
        source = Path(module.__file__).read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(),
                         '60e75218d85da719bfc9d66aeee1bbe22f665f6fd659b70c480e1fa1b5f02f43')
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(module, '_resolve_win_folder', side_effect=OSError(22, 'SYNTHETIC_KNOWN_FOLDER_UNAVAILABLE')) as resolve:
            with self.assertRaises(OSError):
                module.get_win_folder('CSIDL_LOCAL_APPDATA')
            resolve.assert_called_once_with('CSIDL_LOCAL_APPDATA')
            resolve.reset_mock()
            fixture.sanitize_environment()
            for csidl in ['CSIDL_LOCAL_APPDATA','CSIDL_APPDATA','CSIDL_COMMON_APPDATA']:
                self.assertEqual(module.get_win_folder(csidl),str(fixture.WORK))
            paths = module.Windows('pip',appauthor=False,roaming=True)
            self.assertEqual(paths.user_cache_dir,str(fixture.WORK/'pip'/'Cache'))
            self.assertEqual(paths.user_config_dir,str(fixture.WORK/'pip'))
            self.assertEqual(paths.site_config_dir,str(fixture.WORK/'pip'))
            resolve.assert_not_called()
            with self.assertRaises(OSError):
                module.get_win_folder('CSIDL_PERSONAL')
            resolve.assert_called_once_with('CSIDL_PERSONAL')

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

    def test_failure_evidence_is_bounded_static_and_omits_private_strings(self):
        def trace(names):
            result = None
            for name in reversed(names):
                result = SimpleNamespace(tb_frame=SimpleNamespace(f_code=SimpleNamespace(co_filename=name)),
                                         tb_lineno=123, tb_next=result)
            return result
        pip = str(fixture.RUNTIME_SITE/'pip'/'_internal'/'cli'/'main.py')
        stdlib = str(fixture.ROOT/'runtime'/'Lib'/'pathlib.py')
        secret = r'C:\Users\private-name\secret.py'
        names = [str(SOURCE), pip, stdlib, secret, str(fixture.RUNTIME_SITE/'other_package'/'secret.py')]
        error = SimpleNamespace(errno=13, winerror=5, __traceback__=trace(names),
                                filename=secret, message='PRIVATE_TOKEN')
        with patch.object(fixture, '_PIP_CAPTURE', None), patch.object(fixture, '_OPERATION_STAGE', 'INSTALL_RUN_PIP'):
            evidence = fixture.failure_evidence(error)
            self.assertEqual(evidence['stage'], 'INSTALL_RUN_PIP')
            self.assertEqual((evidence['errno'],evidence['winerror']), (13,5))
            self.assertEqual([f['sourceRole'] for f in evidence['sourceTrace']],
                             ['FIXED_FIXTURE','TRUSTED_PIP','TRUSTED_STDLIB','OTHER','OTHER'])
            self.assertEqual(evidence['sourceTrace'][1]['module'], 'pip/_internal/cli/main.py')
            serialized = json.dumps(evidence)
            for private in ['private-name','secret.py','PRIVATE_TOKEN','filename','message']:
                self.assertNotIn(private, serialized)
            for bad in [str(fixture.RUNTIME_SITE/'pip'/'..'/'secret.py'),
                        str(fixture.RUNTIME_SITE/'pip_bad'/'secret.py'),
                        str(fixture.ROOT/'runtime'/'Lib_bad'/'secret.py')]:
                error.__traceback__ = trace([bad])
                self.assertEqual(fixture.failure_evidence(error)['sourceTrace'],
                                 [{'sourceRole':'OTHER','line':123}])
            error.__traceback__ = trace([pip]*100)
            error.errno = 'SECRET'; error.winerror = True
            evidence = fixture.failure_evidence(error)
            self.assertEqual(len(evidence['sourceTrace']),8)
            self.assertTrue(evidence['traceTruncated'])
            self.assertIsNone(evidence['errno']); self.assertIsNone(evidence['winerror'])
        with self.assertRaises(RuntimeError): fixture.mark_stage('user-selected-stage')

    def test_unexpected_pip_error_preserves_stage_codes_and_capture_count(self):
        def failing_pip(*args, **kwargs):
            fixture._PIP_CAPTURE.write('PRIVATE_PIP_TEXT')
            raise OSError(6, 'PRIVATE_OS_MESSAGE', r'C:\Users\private-name\secret')
        with patch.object(fixture.pathlib.Path, 'exists', return_value=False), \
                patch.object(fixture.pathlib.Path, 'mkdir'), \
                patch.object(fixture.pathlib.Path, 'iterdir', return_value=iter(())), \
                patch.object(fixture.sys, 'path', ['fixed-stdlib']), \
                patch.object(fixture.sys, 'argv', ['fixed']), \
                patch.object(fixture.runpy, 'run_module', side_effect=failing_pip):
            try:
                fixture.online_install()
            except OSError as error:
                evidence = fixture.failure_evidence(error)
            else:
                self.fail('unexpected pip exception must remain a failure')
            self.assertEqual(fixture.sys.path, ['fixed-stdlib'])
        self.assertEqual(evidence['stage'],'INSTALL_RUN_PIP')
        self.assertEqual(evidence['errno'],6)
        self.assertEqual(evidence['capturedPipOutputByteCount'],len('PRIVATE_PIP_TEXT'))
        for secret in ['PRIVATE_PIP_TEXT','PRIVATE_OS_MESSAGE','private-name']:
            self.assertNotIn(secret,json.dumps(evidence))

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
