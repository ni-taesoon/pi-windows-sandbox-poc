"""Portable fixture mocks and source contracts. These are not Windows runtime tests."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'native/windows-minimal-load/minimal_load.c'


class FixtureMockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('cc')
        if not compiler:
            raise unittest.SkipTest('portable C compiler unavailable; Windows behavior unverified')
        cls.directory = tempfile.TemporaryDirectory()
        cls.build = Path(cls.directory.name)
        (cls.build / 'windows.h').write_text(r'''
#include <stddef.h>
#include <stdint.h>
typedef uint32_t DWORD;
typedef wchar_t WCHAR;
#define MAX_PATH 260
typedef void *HMODULE;
typedef void *HANDLE;
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define ERROR_SUCCESS 0
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
HANDLE GetStdHandle(DWORD);
int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
void ExitProcess(DWORD);
HMODULE LoadLibraryExW(const wchar_t *, void *, DWORD);
DWORD GetLastError(void);
DWORD GetSystemDirectoryW(WCHAR *, DWORD);
HMODULE GetModuleHandleW(const WCHAR *);
''')
        (cls.build / 'harness.c').write_text(r'''
#include "windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
static unsigned calls;
static DWORD last_error;
static int failure;
HANDLE GetStdHandle(DWORD which) {
    if (which != STD_OUTPUT_HANDLE) exit(90);
    last_error = 777; /* Output APIs invalidate the previous last-error value. */
    return (void *)1;
}
int WriteFile(HANDLE handle, const void *data, DWORD size, DWORD *written, void *overlapped) {
    if (handle != (void *)1 || overlapped) exit(91);
    if (getenv("SHORT_WRITE")) { *written = 0; return 1; }
    *written = (DWORD)fwrite(data, 1, size, stdout);
    return 1;
}
void ExitProcess(DWORD status) { if (calls != (status == 3 ? 0u : 1u)) exit(92); exit((int)status); }
DWORD GetSystemDirectoryW(WCHAR *buffer, DWORD size) {
    const WCHAR *directory = getenv("BAD_DIRECTORY") ? L"D:\\Windows\\System32" : L"C:\\Windows\\system32";
    if (size < wcslen(directory) + 1) exit(95);
    wcscpy(buffer, directory);
    return (DWORD)wcslen(directory);
}
HMODULE GetModuleHandleW(const WCHAR *name) {
    if (calls != 0 || wcscmp(name, L"bcrypt.dll")) exit(96);
    return getenv("PRELOADED") ? (void *)3 : NULL;
}
HMODULE LoadLibraryExW(const wchar_t *name, void *file, DWORD flags) {
    ++calls;
    if (calls != 1 || wcscmp(name, L"C:\\Windows\\System32\\bcrypt.dll") || file
        || flags != LOAD_LIBRARY_SEARCH_SYSTEM32) exit(93);
    last_error = failure ? (DWORD)strtoul(getenv("MOCK_ERROR"), NULL, 10) : 888;
    return failure ? NULL : (void *)2;
}
DWORD GetLastError(void) { return last_error; }
void minimal_load_entry(void);
int main(void) { failure = getenv("MOCK_ERROR") != NULL; minimal_load_entry(); return 94; }
''')
        cls.binary = cls.build / 'minimal-load-mock'
        subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-I', str(cls.build), str(FIXTURE), str(cls.build / 'harness.c'),
                        '-o', str(cls.binary)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_fixture(self, **env):
        return subprocess.run([str(self.binary)], env=env, capture_output=True, timeout=5)

    def test_success_ignores_stale_last_error(self):
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(json.loads(result.stdout), {
            'schemaVersion': 1, 'library': r'C:\Windows\System32\bcrypt.dll',
            'loaded': True, 'win32Error': 0, 'preloaded': False})

    def test_failure_captures_error_before_output(self):
        for error in [5, 1114, 4294967295]:
            with self.subTest(error=error):
                result = self.run_fixture(MOCK_ERROR=str(error))
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b'')
                self.assertEqual(json.loads(result.stdout)['win32Error'], error)
                self.assertFalse(json.loads(result.stdout)['loaded'])

    def test_preloaded_is_separate_from_load_outcome(self):
        result = self.run_fixture(PRELOADED='1')
        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads(result.stdout)['preloaded'])
        self.assertTrue(json.loads(result.stdout)['loaded'])

    def test_unexpected_system_directory_does_not_load(self):
        result = self.run_fixture(BAD_DIRECTORY='1')
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)['status'], 'SYSTEM_DIRECTORY_MISMATCH')

    def test_short_write_never_reports_success(self):
        result = self.run_fixture(SHORT_WRITE='1')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')


class SourceContracts(unittest.TestCase):
    def test_fixture_has_one_fixed_documented_load(self):
        source = FIXTURE.read_text()
        self.assertEqual(source.count('LoadLibraryExW('), 1)
        for forbidden in ['GetProcAddress', 'Nt', 'ReadProcessMemory', 'WriteProcessMemory',
                          'CreateFile', 'OpenProcess', 'DebugActiveProcess', 'GetThreadContext',
                          'BCrypt', 'FreeLibrary']:
            self.assertNotIn(forbidden, source)
        self.assertIn('error = module ? ERROR_SUCCESS : GetLastError();', source)
        self.assertIn('GetModuleHandleW(L"bcrypt.dll")', source)
        self.assertIn('GetSystemDirectoryW(system_directory, MAX_PATH)', source)

    def test_mutually_exclusive_telemetry_gate(self):
        source = (ROOT / 'native/windows-sandbox/src/lib.rs').read_text()
        self.assertIn('pub const NATIVE_VALIDATED: bool = false;', source)
        self.assertIn('compile_error!("minimal load comparison cannot be combined', source)
        for feature in ['lab-loader-trace', 'lab-loader-probe', 'lab-sechost-breakpoints']:
            self.assertIn(f'feature = "{feature}"', source)
        broker = (ROOT / 'native/windows-sandbox/src/broker.rs').read_text()
        self.assertEqual(broker.count('#[cfg(not(feature = "lab-minimal-load-comparison"))]'), 2)
        self.assertIn('let result = crate::process::run_restricted_with_parent(', broker)

    def test_enforcement_sources_unchanged_from_reviewed_baseline(self):
        expected = {
            'src/admission.rs': '3f8f0a9e1e18b74bf0a12f605049e648e17fa2bda1c33872af27d5f7119e1ca3',
            'src/token.rs': '5cf5ec4c5b1d230130dd7809a0b2b6b1b12a44d9d6b46f975ae40e6dc29bf25f',
            'src/desktop.rs': 'c8a0922a34654a20260ba906dc90c4b12e0485a9aa84a7e12bc098f5a25c4a29',
            'src/acl.rs': 'f8097901f8c17cc45f3593eb6d4cbd46e967e0081fd6c89fb2bd943f4b33c402',
            'src/setup.rs': '0512c223efe10766d852e65007e1582587e6c6f4618b0fb233a38468557f6bed',
            'src/setup/accounts.rs': 'd5c80b98fa4aa53cf486157632cec736ada6e8a2971e8516f120b58ef7b08915',
            'src/network.rs': '487e79faa0d88cd6ff605715e7d385f004efb156c9bda8d577434ab3f09cfacd',
            'src/network/firewall.rs': 'c92c6c9f49708349d17e4bc473151dadd0f82dc5cd5d7ce6812702669ec5cf8c',
            'src/network/wfp.rs': 'ef0980326ed73dd693d4af2846b732f63027c091029cb48dfdd08b2311e6e2d3',
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((ROOT / 'native/windows-sandbox' / name).read_bytes()).hexdigest(), digest)

    def test_driver_never_uses_control_as_fallback_or_pass(self):
        source = (ROOT / 'native/windows-sandbox/examples/minimal_load_comparison/windows.rs').read_text()
        self.assertEqual(source.count('let control = run_control(&req);'), 1)
        self.assertEqual(source.count('broker::run_fixed_minimal_load_comparison('), 1)
        self.assertIn('.env_clear().envs(&req.env).current_dir(&req.cwd)', source)
        self.assertIn('req.clone()', source)
        self.assertIn('control_observation.is_ok() && account_observation.is_ok() && sandbox_observation.is_ok()', source)
        self.assertIn('"nativeValidated":false', source)
        self.assertIn('"normalValidationEligible":false', source)
        self.assertIn('"pythonValidationEligible":false', source)
        self.assertNotIn('PASS', source)
        self.assertIn('minimal-load-attempted', source)
        self.assertNotIn('.wait()', source)
        self.assertNotIn('.join()', source)
        self.assertIn('recv_timeout(Duration::from_secs(2))', source)
        # The optional pinned condition can only narrow the original eligibility.
        self.assertEqual(source.count('"freshLoadComparisonEligible"'), 3)
        setup_body = source[source.index('fn execute('):]
        for run_only in ['control_observation', 'account_observation', 'sandbox_observation', 'freshLoadComparisonEligible']:
            self.assertNotIn(run_only, setup_body)

    def test_fixed_account_control_is_feature_only_and_not_a_protocol_switch(self):
        base = ROOT / 'native/windows-sandbox'
        broker = (base / 'src/broker.rs').read_text()
        process = (base / 'src/process.rs').read_text()
        entry = (base / 'src/main.rs').read_text()
        protocol = (base / 'src/protocol.rs').read_text()
        contract = (base / 'src/minimal_load.rs').read_text()
        self.assertIn('#[cfg(feature = "lab-minimal-load-comparison")]\npub unsafe fn run_fixed_minimal_load_comparison(', broker)
        self.assertIn('#[cfg(feature = "lab-minimal-load-comparison")]\npub fn fixed_minimal_load_helper_main(', broker)
        self.assertIn('#[cfg(all(windows, feature = "lab-minimal-load-comparison"))]', entry)
        self.assertIn('internal-fixed-minimal-load-helper', entry)
        self.assertIn('pub struct FixedLoadRequest(RunRequest);', contract)
        self.assertEqual(broker.count('FixedLoadRequest::new(request.clone())?'), 3)
        self.assertIn('FixedLoadRequest::new(request.clone())?', process)
        self.assertIn('run_impl(ChildLaunch::FixedAccountControl', process)
        self.assertIn('#[cfg(feature = "lab-minimal-load-comparison")]\n    FixedAccountControl,', process)
        self.assertEqual(process.count('=> CreateProcessW('), 1)
        for forbidden in ['FixedAccountControl', 'FixedMinimalLoad', 'unrestricted']:
            self.assertNotIn(forbidden, protocol)
        self.assertNotIn('token == 0', process)
        self.assertNotIn('CREATE_BREAKAWAY_FROM_JOB', process)
        self.assertNotIn('AdjustTokenPrivileges', process)

    def test_production_runner_preparation_and_cleanup_are_byte_identical(self):
        source = (ROOT / 'native/windows-sandbox/src/process.rs').read_text()
        # Hash only unchanged shared preparation and cleanup from PR 28. The
        # creation dispatch is separately checked; no Windows behavior is claimed.
        preparation = source[source.index('    ensure!(\n        private_desktop'):source.index('    let created = match launch')]
        cleanup = source[source.index('    let process = Handle::from_raw(info.hProcess)?;'):]
        self.assertEqual(hashlib.sha256(preparation.encode()).hexdigest(),
                         '636e78a414906c88403365314a13156b05e62b39897b4359013f4ef443d826cf')
        self.assertEqual(hashlib.sha256(cleanup.encode()).hexdigest(),
                         '10f74c9cfd42e6488dada5d3b6d1fe31408ce006a56f75f3685197ff92b634d0')
        restricted = source[source.index('ChildLaunch::Restricted(token) => CreateProcessAsUserW('):]
        call = restricted[:restricted.index('        ),')]
        expected = '''ChildLaunch::Restricted(token) => CreateProcessAsUserW(
            token, executable.as_ptr(), command.as_mut_ptr(), null(), null(), 1,
            creation_flags, env.as_ptr().cast::<c_void>(), cwd.as_ptr(),
            &startup.StartupInfo, &mut info,'''
        self.assertEqual(''.join(call.split()), ''.join(expected.split()))
        wrapper = source[source.index('pub(crate) unsafe fn run_restricted_with_parent('):source.index('#[cfg(feature = "lab-loader-trace")]\npub(crate) unsafe fn')]
        self.assertIn('ChildLaunch::Restricted(token)', wrapper)
        self.assertNotIn('FixedAccountControl', wrapper)

    def test_fixed_pair_fail_stops_and_preserves_first_evidence(self):
        broker = (ROOT / 'native/windows-sandbox/src/broker.rs').read_text()
        owner, helper = broker.split('fn helper_main_impl(', 1)
        self.assertIn('HelperExecution::FixedMinimalLoad => Duration::from_secs(70)', owner)
        self.assertIn('record_account.as_mut()', owner)
        self.assertLess(owner.index('account.can_continue()'), owner.index('let result: RunResult = pipe'))
        self.assertLess(helper.index('run_fixed_account_control('), helper.index('account.can_continue()'))
        self.assertLess(helper.index('account.can_continue()'), helper.index('process::run_restricted_with_parent('))
        self.assertLess(helper.index('pipe.send(&account,'), helper.index('account.can_continue()'))
        self.assertIn('restricted child NOT_ATTEMPTED', helper)
        driver = (ROOT / 'native/windows-sandbox/examples/minimal_load_comparison/windows.rs').read_text()
        for required in ['minimal-load-account-control.json', 'account_observation.as_ref().is_ok_and(|r| !r.preloaded)',
                         'process-creation API', 'fixed ordinary-first order', 'RESULT_UNAVAILABLE']:
            self.assertIn(required, driver)

    def test_dedicated_workflow_and_mitigations(self):
        source = (ROOT / '.github/workflows/windows-minimal-load.yml').read_text()
        self.assertIn('branches: [lab/minimal-load-comparison]', source)
        self.assertIn("$env:EVENT_REPOSITORY -cne 'ni-taesoon/pi-windows-sandbox-poc'", source)
        self.assertIn('$env:SOURCE_SHA -cne $env:EVENT_SHA', source)
        self.assertIn('ref: ${{ github.sha }}', source)
        self.assertIn('persist-credentials: false', source)
        self.assertIn('checkout-index --force --all', source)
        self.assertIn('--no-default-features --features lab-minimal-load-comparison', source)
        self.assertIn('--test minimal_load_output_contract', source)
        for forbidden in ['lab/approved-windows-python', '--features lab-loader',
                          '--features lab-sechost', 'git config --global',
                          'inspect_windows_loader', 'inspect_sechost', 'collect_windows_loader',
                          '*.dll', '*.exe', '**', 'windows-python-lab.yml']:
            self.assertNotIn(forbidden, source)
        build = (ROOT / 'scripts/build_windows_minimal_load.ps1').read_text()
        self.assertIn('/GS ', build)
        self.assertNotIn('/GS-', build)
        self.assertIn('/DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA', build)


if __name__ == '__main__':
    unittest.main()
