"""Portable source contracts only. No Windows execution or security mutations."""
import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'native/windows-sandbox'
FEATURE = 'lab-pinned-codex-token-comparison'


class PinnedTokenContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broker = (BASE / 'src/broker.rs').read_text()
        cls.driver = (BASE / 'examples/minimal_load_comparison/windows.rs').read_text()
        cls.token = (BASE / 'src/token.rs').read_text()
        cls.workflow = (ROOT / '.github/workflows/windows-pinned-codex-token.yml').read_text()

    def test_sensitive_enforcement_and_fixture_are_byte_unchanged(self):
        expected = {
            'native/windows-minimal-load/minimal_load.c': '2ba8c57e0945175fe02fc5e0c16f33a85a6e0cbe6eb73b61017dc467dd6b3694',
            'native/windows-sandbox/src/token.rs': '5cf5ec4c5b1d230130dd7809a0b2b6b1b12a44d9d6b46f975ae40e6dc29bf25f',
            'native/windows-sandbox/src/process.rs': '42f69f6a6b58305a571589bdcf26437f2cd85dce90cbc2f68efac74e535a8b37',
            'native/windows-sandbox/src/protocol.rs': 'dd3416dbca519b3aeb71ec48934cac8ea02fc5aa23dc859e95b4d343c02795a3',
            'native/windows-sandbox/src/lib.rs': 'ad69b42809404f4d63277bee8b374ef378c260cce6cd6713190e6b9bdf554340',
            'native/windows-sandbox/src/admission.rs': '3f8f0a9e1e18b74bf0a12f605049e648e17fa2bda1c33872af27d5f7119e1ca3',
            'native/windows-sandbox/src/desktop.rs': 'c8a0922a34654a20260ba906dc90c4b12e0485a9aa84a7e12bc098f5a25c4a29',
            'native/windows-sandbox/src/acl.rs': 'f8097901f8c17cc45f3593eb6d4cbd46e967e0081fd6c89fb2bd943f4b33c402',
            'native/windows-sandbox/src/setup/accounts.rs': 'd5c80b98fa4aa53cf486157632cec736ada6e8a2971e8516f120b58ef7b08915',
            'native/windows-sandbox/src/setup/launch.rs': '20292cb9669a647d3bbb37ee5abfdea72ff4e45fc77f0c057d992432b4957cd6',
            'native/windows-sandbox/src/network.rs': '487e79faa0d88cd6ff605715e7d385f004efb156c9bda8d577434ab3f09cfacd',
            'native/windows-sandbox/src/network/firewall.rs': 'c92c6c9f49708349d17e4bc473151dadd0f82dc5cd5d7ce6812702669ec5cf8c',
            'native/windows-sandbox/src/network/wfp.rs': 'ef0980326ed73dd693d4af2846b732f63027c091029cb48dfdd08b2311e6e2d3',
            '.github/workflows/windows-minimal-load.yml': '86c63fcdbc72bf072712a58d0e66d56f7ff444bc15da4b86d6a5cf37433dd73a',
            'scripts/stage_windows_minimal_load.ps1': '957e6e8010f61b76a3f3ed1f4b3603a6e1b8c7f0d1d9f20386306aa60e021478',
            'scripts/build_windows_minimal_load.ps1': '6ab57429f422dfeccdd3855b2f3f616c818d9b55b5611c34636a66db429d8d1c',
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)

    def test_default_off_and_advanced_features_remain_incompatible(self):
        manifest = (BASE / 'Cargo.toml').read_text()
        self.assertIn('default = []', manifest)
        self.assertIn(f'{FEATURE} = ["lab-minimal-load-comparison"]', manifest)
        library = (BASE / 'src/lib.rs').read_text()
        self.assertIn('pub const NATIVE_VALIDATED: bool = false;', library)
        self.assertIn('compile_error!("minimal load comparison cannot be combined', library)
        for feature in ['lab-loader-trace', 'lab-loader-probe', 'lab-sechost-breakpoints']:
            self.assertIn(f'feature = "{feature}"', library)

    def test_exact_existing_constructor_and_default_dacl_alignment(self):
        call = 'token::create_workspace_write_token_with_caps_and_user_from('
        self.assertEqual(self.broker.count(call), 1)
        compact = ''.join(self.broker.split())
        self.assertIn(call + 'base.raw(),&[cap.as_ptr()],&[],', compact)
        self.assertEqual(self.broker.count('token::create_strict_write_token_from('), 1)
        self.assertIn('create_token_with_caps_impl(base_token, capabilities, extras, true)', self.token)
        self.assertIn('extra_restricting_sids.push(psid_user);', self.token)
        self.assertIn('entries[logon_idx].Sid = psid_logon;', self.token)
        self.assertIn('entries[logon_idx + 1].Sid = psid_everyone;', self.token)
        self.assertIn('if include_world {\n            &[]\n        } else {\n            psid_capabilities', self.token)
        # No new token manipulation or upstream device-ACL compatibility step.
        helper = self.broker.split('if matches!(execution, HelperExecution::FixedPinnedCodexToken) {')[-1]
        helper = helper.split('#[cfg(not(feature = "lab-minimal-load-comparison"))]')[0]
        for forbidden in ['allow_null_device', 'AdjustTokenPrivileges', 'SetTokenInformation',
                          'SetSecurityInfo', 'Impersonate', 'CreateProcessW', 'DebugActive',
                          'ReadProcessMemory', 'WriteProcessMemory', 'GetThreadContext']:
            self.assertNotIn(forbidden, helper)

    def test_fixed_entrypoint_cannot_select_arbitrary_policy(self):
        entry = (BASE / 'src/main.rs').read_text()
        protocol = (BASE / 'src/protocol.rs').read_text()
        self.assertIn(f'#[cfg(feature = "{FEATURE}")]\npub unsafe fn run_fixed_pinned_codex_token_comparison(', self.broker)
        self.assertIn(f'#[cfg(feature = "{FEATURE}")]\npub fn fixed_pinned_codex_token_helper_main(', self.broker)
        self.assertIn(f'#[cfg(all(windows, feature = "{FEATURE}"))]', entry)
        self.assertIn('internal-fixed-pinned-codex-token-helper', entry)
        api = self.broker.split('pub unsafe fn run_fixed_pinned_codex_token_comparison(', 1)[1].split('\n#[cfg', 1)[0]
        self.assertIn('request: crate::minimal_load::FixedLoadRequest', api)
        self.assertIn(r'C:\PiSandboxLab\store', api)
        self.assertIn(r'C:\PiSandboxLab\trusted\pi-windows-sandbox.exe', api)
        for forbidden in ['PinnedCodex', 'pinned', 'unrestricted', 'token_mode', 'restricting_sid']:
            self.assertNotIn(forbidden, protocol)
        normal = self.broker.split('pub unsafe fn run_via_dedicated_helper(', 1)[1].split('\n///', 1)[0]
        self.assertIn('HelperExecution::Restricted', normal)
        self.assertNotIn('FixedPinnedCodexToken', normal)

    def test_strict_is_saved_and_acknowledged_before_extra_launch(self):
        owner = self.broker.split('fn receive_pinned_token_comparison(', 1)[1].split('unsafe fn run_helper_impl', 1)[0]
        self.assertLess(owner.index('record(&strict_frame)?'), owner.index('pipe.send(&PinnedTokenReady'))
        self.assertLess(owner.index('strict.can_continue()'), owner.index('pipe.send(&PinnedTokenReady'))
        self.assertLess(owner.index('pipe.send(&PinnedTokenReady'), owner.index('let pinned_frame:'))
        helper = self.broker.split('if matches!(execution, HelperExecution::FixedPinnedCodexToken) {')[-1]
        self.assertLess(helper.index('restricted.raw()'), helper.index('PinnedTokenFrame::UnchangedStrict'))
        self.assertLess(helper.index('strict.can_continue()'), helper.index('let _: PinnedTokenReady'))
        self.assertLess(helper.index('let _: PinnedTokenReady'), helper.index('token::create_workspace_write_token'))
        self.assertLess(helper.index('token::create_workspace_write_token'), helper.index('pinned_token.raw()'))
        self.assertLess(helper.index('PinnedTokenFrame::PinnedCodexToken'), helper.index('return Ok(())'))
        recorder = self.driver.split('fn record_pinned_frame(', 1)[1].split('fn run_comparison(', 1)[0]
        self.assertLess(recorder.index('fresh_write('), recorder.index('if strict { observed.context('))
        self.assertIn('f.sync_all()?;', self.driver)

    def test_framing_counts_and_no_success_substitution(self):
        receiver = self.broker.split('fn receive_pinned_token_comparison(', 1)[1].split('unsafe fn run_helper_impl', 1)[0]
        self.assertEqual(receiver.count('pipe.receive(deadline)'), 2)
        self.assertEqual(receiver.count('pipe.send('), 1)
        self.assertIn('strict_frame.expect_unchanged_strict()?', receiver)
        self.assertIn('pinned_frame.expect_pinned_codex_token()?', receiver)
        self.assertIn('let result = strict.run().context("strict result missing")?.clone();', receiver)
        self.assertIn('Ok(result)', receiver)
        self.assertNotIn('pinned.run()', receiver)
        self.assertEqual(self.broker.count('pipe.send(&PinnedTokenFrame::'), 2)
        self.assertEqual(self.broker.count('let _: PinnedTokenReady = pipe.receive('), 1)
        self.assertIn('HelperExecution::FixedMinimalLoad => Duration::from_secs(70)', self.broker)
        self.assertIn('HelperExecution::FixedPinnedCodexToken => Duration::from_secs(105)', self.broker)
        self.assertIn('lease.finish_after_verified_cleanup(result)', self.broker)

    def test_output_cannot_claim_python_or_isolation_success(self):
        for required in ['"nativeValidated":false', '"normalValidationEligible":false',
                         '"pythonValidationEligible":false', '"isolationValidated":false',
                         '"independentTargetTokenObservation":false',
                         'outside writableRoots without a capability ACE',
                         'same CreateProcessAsUserW path as unchanged strict condition']:
            self.assertIn(required, self.driver)
        self.assertIn('let complete = complete && pinned_observation.is_ok();', self.driver)
        self.assertIn('&& pinned_observation.as_ref().is_ok_and(|r| !r.preloaded)', self.driver)
        self.assertNotIn('PASS', self.driver)
        for filename in ['minimal-load-strict-control.json', 'minimal-load-pinned-codex-control.json']:
            self.assertIn(filename, self.driver)
            self.assertIn(filename, self.workflow)
        self.assertIn('["accountControl", "sandbox", "pinnedCodexToken"]', self.driver)

    def test_workflow_requires_reviewed_exact_branch_immutable_launch(self):
        self.assertIn('  workflow_dispatch:', self.workflow)
        self.assertIn('  push:\n    branches: [lab/pinned-codex-token-comparison]', self.workflow)
        self.assertIn("$env:PUSH_DELETED -cne 'false'", self.workflow)
        self.assertNotIn('  pull_request:', self.workflow)
        self.assertIn("refs/heads/lab/pinned-codex-token-comparison", self.workflow)
        self.assertIn("$env:EVENT_REPOSITORY -cne 'ni-taesoon/pi-windows-sandbox-poc'", self.workflow)
        self.assertIn('$env:SOURCE_SHA -cne $env:EVENT_SHA', self.workflow)
        self.assertIn('ref: ${{ github.sha }}', self.workflow)
        self.assertIn('persist-credentials: false', self.workflow)
        self.assertIn('--no-default-features --features lab-minimal-load-comparison', self.workflow)
        self.assertIn(f'--no-default-features --features {FEATURE}', self.workflow)
        self.assertIn('--test pinned_token_comparison_contract', self.workflow)
        self.assertIn('python -B tests/windows-lab/test_pinned_codex_token.py', self.workflow)
        self.assertLess(self.workflow.index('Pinned token source contracts failed'), self.workflow.index('id: setup'))
        self.assertIn("if: ${{ always() && steps.stage.outcome == 'success' && steps.setup.outcome != 'skipped' }}", self.workflow)
        for forbidden in ['--features lab-loader', '--features lab-sechost', 'allow_null_device',
                          'git config --global', '*.dll', '*.exe', '**', 'inspect_sechost']:
            self.assertNotIn(forbidden, self.workflow)


if __name__ == '__main__':
    unittest.main()
