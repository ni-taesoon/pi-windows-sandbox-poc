"""Read-only contracts for the approved online-install/PDF laboratory workflow."""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[2]

class OnlineWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w=(ROOT/'.github/workflows/windows-python-online-pdf.yml').read_text()
        cls.s=(ROOT/'scripts/stage_windows_python_isolation.ps1').read_text()

    def test_distinct_branch_exact_source_and_closed_gate(self):
        for text in ['branches: [lab/python-online-pdf-acceptance]',
                     "$env:EVENT_REF -cne 'refs/heads/lab/python-online-pdf-acceptance'",
                     '$env:SOURCE_SHA -cne $env:EVENT_SHA', "APPROVED_SECURITY_CHANGES -cne 'true'",
                     'ref: ${{ github.sha }}', 'persist-credentials: false', 'contents: read',
                     'pub const NATIVE_VALIDATED: bool = false;']:
            self.assertIn(text,self.w)
        for bad in ['pull_request:', 'schedule:', 'self-hosted', 'contents: write', 'git push', 'secrets.']:
            self.assertNotIn(bad,self.w)
        self.assertIn("if (-not $CodexPolicyAcceptance -or $env:GITHUB_REF -cne 'refs/heads/lab/python-online-pdf-acceptance')", self.s)
        self.assertIn('$stage.onlinePdfAcceptance -ne [bool]$OnlinePdfAcceptance',self.s)

    def test_installer_relay_and_pins_are_staged_immutable_only_when_enabled(self):
        for role,name in [('Fixture','fixture.py'),('Relay','relay.py'),('Packages','packages.json'),('Requirements','requirements.txt')]:
            self.assertIn('$ExpectedOnlinePdf'+role+'Sha256',self.s)
            self.assertIn("name='python-online-pdf-"+name+"'",self.s)
            self.assertIn('onlinePdf'+role+'Sha256=',self.w)
            self.assertIn('onlinePdf'+role+'Sha256=',self.s)
            self.assertIn(' -Hash $stage.onlinePdf'+role+'Sha256',self.s)
        self.assertIn("if ($Phase -ne 'Disable')",self.s)
        self.assertNotIn('pdf-deps',self.s)
        self.assertNotIn('.whl',self.s)

    def test_no_wheel_prefetch_or_installer_before_sandbox(self):
        commands = []
        in_run = False
        for line in self.w.splitlines():
            if line == '        run: |':
                in_run = True
            elif in_run and line.strip() and not line.startswith('          '):
                in_run = False
            elif in_run and not line.lstrip().startswith('#'):
                commands.append(line)
        self.assertTrue(commands)
        command_lines = '\n'.join(commands)
        for bad in ['pip install', 'pip download', 'Invoke-WebRequest', 'Start-BitsTransfer',
                    'curl ', 'wget ', 'winget ', 'choco ', 'files.pythonhosted.org/packages/']:
            self.assertNotIn(bad,command_lines)
        stage=self.w.index('        id: stage')
        for check in ['cargo build --locked --no-default-features --features lab-python-online-pdf',
                      '--test python_isolation_contract', '--test wfp_offline_scope_contract',
                      '--example python_isolation_acceptance online_pdf::tests',
                      "-p 'test_online_pdf_*.py'", "-p 'test_*sources.py'"]:
            self.assertLess(self.w.index(check),stage)
        self.assertIn('totalScopedWfpFilters=16',self.w)
        self.assertIn("networkProfile='FIXED_ONLINE_PYPI_RELAY'",self.w)

    def test_all_security_phases_are_fixed_and_cleanup_is_always_attempted(self):
        for phase in ['Stage','Setup','Run','Disable']:
            self.assertEqual(self.w.count('-Phase '+phase+' -ApprovedDisposableVm -CodexPolicyAcceptance -OnlinePdfAcceptance'),1)
        self.assertIn("if: ${{ always() && steps.stage.outcome == 'success' && steps.setup.outcome != 'skipped' }}",self.w)
        self.assertNotIn('continue-on-error:',self.w)

    def test_safe_artifact_allowlist_includes_pdf_only_after_verified_receipt(self):
        uploaded=[line.strip() for line in self.w.split('          path: |',1)[1].splitlines() if line.strip()]
        self.assertEqual(len(uploaded),len(set(uploaded)))
        for path in uploaded:
            self.assertRegex(path,r'\Aonline-pdf-evidence/[a-z-]+\.(json|log|pdf)\Z')
            for secret in ['credentials','store','deps','whl']: self.assertNotIn(secret,path)
        self.assertIn('online-pdf-evidence/sandbox-test.pdf',uploaded)
        for text in ['$receipt.pdfValidated -eq $true',"$receipt.pageCount -ne 1",
                     "$receipt.expectedText -cne 'Sandbox PDF test'",'$item.Length -gt 1048576',
                     '$item.Length -ne $receipt.byteCount','-ine $receipt.pdfSha256']:
            self.assertIn(text,self.w)
        self.assertIn('include-hidden-files: false',self.w)
        self.assertIn('retention-days: 7',self.w)

    def test_owner_relay_uses_no_unbound_standard_handle_override(self):
        owner=(ROOT/'native/windows-sandbox/examples/python_isolation_acceptance/online_pdf.rs').read_text()
        launch=owner.split('    fn launch(&mut self) -> Result<()> {',1)[1].split('    fn validate_ready(',1)[0]
        self.assertIn('let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };',launch)
        self.assertIn('startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;',launch)
        self.assertIn('std::ptr::null(), 0, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,',launch)
        for forbidden in ['STARTF_USESTDHANDLES','startup.dwFlags','startup.hStd']:
            self.assertNotIn(forbidden,owner)

    def test_exact_three_actions_and_all_new_source_surfaces_pinned(self):
        actions=re.findall(r'^\s+uses: (\S+)',self.w,re.M)
        self.assertEqual(actions,[
            'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683',
            'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065',
            'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'])
        for path in ['scripts/python-online-pdf-relay.py','scripts/python-online-pdf-fixture.py',
                     'scripts/python-online-pdf-packages.json','scripts/python-online-pdf-requirements.txt',
                     'native/windows-sandbox/examples/python_isolation_acceptance/online_pdf.rs',
                     'tests/python-probe/test_online_pdf_relay.py','tests/python-probe/test_online_pdf_fixture.py',
                     'tests/windows-lab/test_online_pdf_network_sources.py','tests/windows-lab/test_online_pdf_workflow_sources.py']:
            self.assertIn("'"+path+"'",self.w)


if __name__=='__main__': unittest.main()
