"""Read-only source contracts for the separate, default-off Codex-policy lab."""
from pathlib import Path
import hashlib
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/windows-codex-python-policy.yml'
EVIDENCE = {
    'python-isolation-stage.json', 'python-isolation-runtime-manifest.json',
    'python-isolation-baseline.json', 'python-isolation-ordinary-outside.json',
    'python-isolation-codex-boundary.json', 'python-isolation-codex-file-operations.json',
    'python-isolation-codex-child-normal-exit.json', 'python-isolation-codex-child-timeout.json',
    'python-isolation-codex-fixtures.json', 'python-isolation-run.json',
    'python-isolation-recovery.json', 'python-isolation-summary.json',
}


class CodexPolicySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text()
        cls.stager = (ROOT / 'scripts/stage_windows_python_isolation.ps1').read_text()

    def test_profile_has_distinct_branch_and_no_external_trigger(self):
        w = self.workflow
        self.assertIn('branches: [lab/codex-python-policy-acceptance]', w)
        self.assertIn("$env:EVENT_REF -cne 'refs/heads/lab/codex-python-policy-acceptance'", w)
        self.assertIn("$env:EVENT_REPOSITORY -cne 'ni-taesoon/pi-windows-sandbox-poc'", w)
        self.assertIn('$env:SOURCE_SHA -cne $env:EVENT_SHA', w)
        self.assertIn("$env:APPROVED_SECURITY_CHANGES -cne 'true'", w)
        self.assertIn('ref: ${{ github.sha }}', w)
        self.assertIn('persist-credentials: false', w)
        self.assertIn('contents: read', w)
        for forbidden in ['pull_request:', 'pull_request_target:', 'schedule:', 'workflow_run:',
                          'self-hosted', 'contents: write', 'git push', 'secrets.']:
            self.assertNotIn(forbidden, w)

    def test_security_stages_follow_build_and_pure_contracts(self):
        w = self.workflow
        stage = w.index('        id: stage')
        for marker in ['cargo check --locked --no-default-features --target',
                       '--features lab-python-isolation-acceptance',
                       '--features lab-python-policy-repair-comparison',
                       '--features lab-python-logon-sid-comparison',
                       'cargo build --locked --no-default-features --features lab-python-codex-policy-acceptance',
                       'cargo test --locked --no-default-features --features lab-python-codex-policy-acceptance',
                       '--test admission_policy_contract', '--test python_isolation_contract',
                       '--test wfp_offline_scope_contract', '--lib network::wfp::tests::', '--lib policy_masks::tests::',
                       '--lib python_isolation::codex_fixtures::tests::',
                       "-p 'test_*python*source*.py'", 'tests/python-probe/test_isolation_fixture.py']:
            self.assertLess(w.index(marker), stage)
        self.assertNotIn('rustup toolchain install', w)
        self.assertNotIn('rustup target add', w)
        for phase in ['Stage', 'Setup', 'Run', 'Disable']:
            self.assertEqual(w.count(f'-Phase {phase} -ApprovedDisposableVm -CodexPolicyAcceptance'), 1)
        self.assertIn("if: ${{ always() && steps.stage.outcome == 'success' && steps.setup.outcome != 'skipped' }}", w)
        self.assertNotIn('continue-on-error:', w)

    def test_official_pinned_runtime_and_no_extra_downloads(self):
        w = self.workflow
        self.assertIn("python-version: '3.12.10'", w)
        self.assertIn('architecture: x64', w)
        self.assertIn("sys.version_info[:3] == (3, 12, 10)", w)
        actions = re.findall(r'^\s+uses: (\S+)', w, re.M)
        self.assertEqual(actions, [
            'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683',
            'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065',
            'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
        ])
        for forbidden in ['pip install', 'Invoke-WebRequest', 'Start-BitsTransfer', 'curl ',
                          'winget ', 'choco ', '--features lab-loader', '--features lab-sechost']:
            self.assertNotIn(forbidden, w)

    def test_artifacts_are_fixed_and_historical_comparison_is_not_overwritten(self):
        w = self.workflow
        section = w.split('foreach ($name in @(', 1)[1].split(')) {', 1)[0]
        self.assertEqual(set(re.findall(r"'([^']+\.json)'", section)), EVIDENCE)
        upload = [line.strip() for line in w.split('          path: |', 1)[1].splitlines() if line.strip()]
        self.assertEqual(len(upload), len(set(upload)))
        for name in EVIDENCE:
            self.assertIn('codex-python-policy-evidence/' + name, upload)
        for name in upload:
            self.assertRegex(name, r'\Acodex-python-policy-evidence/[a-z-]+\.(json|log)\Z')
            self.assertNotIn('credential', name)
            self.assertNotIn('store', name)
        self.assertIn('retention-days: 7', w)
        self.assertIn('include-hidden-files: false', w)
        self.assertIn('no retained file handles', w)
        self.assertIn('does not overwrite previous failed comparisons', w)
        self.assertIn('known exception', w)
        self.assertIn('strictWorkspaceOnlyAcceptance=$false', w)
        self.assertIn('Production activation stays false', w)
        self.assertIn('totalOfflineWfpFilters=14', w)

    def test_new_stager_switch_is_exact_branch_and_stage_identity_bound(self):
        s = self.stager
        self.assertIn('[switch]$CodexPolicyAcceptance', s)
        self.assertIn("if ($env:GITHUB_REF -cne 'refs/heads/lab/codex-python-policy-acceptance')", s)
        self.assertIn("elseif ($env:GITHUB_REF -cne 'refs/heads/lab/python-isolation-acceptance')", s)
        self.assertIn('$stage.codexPolicyAcceptance -ne [bool]$CodexPolicyAcceptance', s)
        self.assertIn("$Phase -ne 'Disable'", s)
        self.assertIn("Where-Object { $_ -cne 'fixtures\\outside-logon' }", s)
        self.assertIn("@('fixtures\\outside-private')", s)
        self.assertIn('outsidePrivateOwnerOnly=[bool]$CodexPolicyAcceptance', s)
        line = next(line for line in s.splitlines() if '$privateAcl.SetSecurityDescriptorSddlForm' in line)
        self.assertEqual(line.strip(), '$privateAcl.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$ownerSid)")')
        self.assertIn('Set-Acl -LiteralPath "$root\\fixtures\\outside-private" -AclObject $privateAcl', s)
        # It creates only the directory. The native broker prepares late targets
        # and proves exact identity/ACLs before allowing helper execution.
        self.assertNotIn('codex-protected-file.txt', s)
        self.assertNotIn('codex-protected-dir', s)
        self.assertNotIn('owner-control.txt', s)

    def test_required_manifest_includes_new_security_surface(self):
        for name in ['.github/workflows/windows-codex-python-policy.yml',
                     'tests/windows-lab/test_codex_python_policy_sources.py',
                     'native/windows-sandbox/src/python_isolation/codex_fixtures.rs',
                     'native/windows-sandbox/src/policy_masks.rs']:
            self.assertIn("'" + name + "'", self.workflow)
        self.assertIn('Source manifest mismatch:', self.workflow)
        self.assertIn('pub const NATIVE_VALIDATED: bool = false;', self.workflow)


if __name__ == '__main__':
    unittest.main()
