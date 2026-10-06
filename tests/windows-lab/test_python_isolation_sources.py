"""Portable, read-only source contracts; no fixture execution or Windows claims.

Only standard-library text/AST inspection runs here. These tests neither execute
PowerShell nor start native/Python canaries, open sockets, or modify security.
"""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / '.github/workflows/windows-python-isolation.yml'
STAGER_PATH = ROOT / 'scripts/stage_windows_python_isolation.ps1'
NATIVE = ROOT / 'native/windows-sandbox'

EVIDENCE_JSON = {
    'python-isolation-stage.json',
    'python-isolation-runtime-manifest.json',
    'python-isolation-baseline.json',
    'python-isolation-ordinary-outside.json',
    'python-isolation-strict-boundary.json',
    'python-isolation-strict-child-normal-exit.json',
    'python-isolation-strict-child-timeout.json',
    'python-isolation-pinned-boundary.json',
    'python-isolation-pinned-child-normal-exit.json',
    'python-isolation-pinned-child-timeout.json',
    'python-isolation-run.json',
    'python-isolation-recovery.json',
    'python-isolation-summary.json',
}


def executable_lines(text):
    """Drop full-line comments so safety prose is not mistaken for an action."""
    return '\n'.join(line for line in text.splitlines()
                     if not line.lstrip().startswith('#'))


class PythonIsolationWorkflowContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW_PATH.read_text(encoding='utf-8')
        cls.actions = executable_lines(cls.workflow)
        cls.stager = STAGER_PATH.read_text(encoding='utf-8')
        cls.stage_actions = executable_lines(cls.stager)

    def test_only_exact_repository_branch_and_events(self):
        source = self.workflow
        self.assertIn('branches: [lab/python-isolation-acceptance]', source)
        self.assertIn("$env:EVENT_REPOSITORY -cne 'ni-taesoon/pi-windows-sandbox-poc'", source)
        self.assertIn("$env:EVENT_REF -cne 'refs/heads/lab/python-isolation-acceptance'", source)
        self.assertIn("$env:PUSH_DELETED -cne 'false'", source)
        self.assertIn("$env:EVENT_NAME -ceq 'push'", source)
        self.assertIn("$env:EVENT_NAME -ceq 'workflow_dispatch'", source)
        for forbidden in ['pull_request:', 'pull_request_target:', 'schedule:',
                          'repository_dispatch:', 'self-hosted', 'workflow_run:']:
            self.assertNotIn(forbidden, source)
        self.assertIn('runs-on: windows-2022', source)
        self.assertIn("$env:ImageOS -ne 'win22'", source)

    def test_dispatch_cannot_substitute_a_mutable_commit(self):
        source = self.workflow
        self.assertIn("$env:SOURCE_SHA -cnotmatch '\\A[0-9a-f]{40}\\z'", source)
        self.assertIn('$env:SOURCE_SHA -cne $env:EVENT_SHA', source)
        self.assertIn("$env:APPROVED_SECURITY_CHANGES -cne 'true'", source)
        self.assertIn('default: false', source)
        self.assertIn('ref: ${{ github.sha }}', source)
        self.assertIn('SOURCE_SHA: ${{ github.sha }}', source)
        self.assertIn('$actual -cne $env:SOURCE_SHA', source)
        self.assertNotIn('default: main', source)
        self.assertNotIn('ls-remote', source)
        self.assertNotIn('steps.source.outputs.sha', source)
        self.assertIn('never authorization evidence', source)

    def test_actions_are_immutable_and_credentials_are_not_persisted(self):
        actions = re.findall(r'^\s+uses: ([^\s#]+)', self.workflow, re.MULTILINE)
        self.assertEqual(actions, [
            'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683',
            'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065',
            'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
        ])
        for action in actions:
            self.assertRegex(action, r'\Aactions/[a-z-]+@[0-9a-f]{40}\Z')
        for required in ['contents: read', 'persist-credentials: false',
                         'set-safe-directory: false', 'fetch-depth: 1',
                         'checkout-index --force --all']:
            self.assertIn(required, self.workflow)
        for forbidden in ['write-all', 'contents: write', 'secrets.',
                          'git config --global', 'git push']:
            self.assertNotIn(forbidden, self.actions)

    def test_runtime_version_and_architecture_are_exact(self):
        source = self.workflow
        for required in ["python-version: '3.12.10'", 'architecture: x64',
                         'check-latest: false', 'update-environment: false',
                         'PYTHON_EXECUTABLE: ${{ steps.python.outputs.python-path }}',
                         "sys.version_info[:3] == (3, 12, 10)",
                         "struct.calcsize('P') == 8", '-I -S -B -c',
                         'Per-run hashes are not independent']:
            self.assertIn(required, source)
        # update-environment:false requires the action output, not an unset env.
        self.assertNotIn('pythonLocation', source)
        for forbidden in ['pip install', 'ensurepip', 'Invoke-WebRequest',
                          'Start-BitsTransfer', 'curl ', 'wget ', 'choco ', 'winget ']:
            self.assertNotIn(forbidden, self.actions)
            self.assertNotIn(forbidden, self.stage_actions)

    def test_default_and_feature_checks_and_pure_tests_precede_security(self):
        source = self.workflow
        first_stage = source.index('      - name: Stage fixed protected lab')
        for required in [
            'cargo check --locked --no-default-features --target',
            'cargo check --locked --no-default-features --features lab-python-isolation-acceptance',
            'cargo build --locked --no-default-features --features lab-python-isolation-acceptance',
            'cargo test --locked --no-default-features --features lab-python-isolation-acceptance',
            '--test python_isolation_contract',
            '-m unittest discover -s tests/windows-lab -p test_python_isolation_sources.py',
            '-I -S -B tests/python-probe/test_isolation_fixture.py',
        ]:
            self.assertLess(source.index(required), first_stage)
        self.assertIn('rustup run stable rustc --version --verbose', source)
        self.assertNotIn('rustup toolchain install', source)
        self.assertNotIn('rustup target add', source)
        for forbidden in ['--features lab-minimal', '--features lab-pinned',
                          '--features lab-loader', '--features lab-sechost',
                          'inspect_windows_loader', 'inspect_sechost',
                          'build_windows_loader_probe', 'collect_windows_loader']:
            self.assertNotIn(forbidden, source)

    def test_required_manifest_sources_include_the_new_surface(self):
        source = self.workflow
        required = [
            '.github/workflows/windows-python-isolation.yml',
            'scripts/stage_windows_python_isolation.ps1',
            'scripts/windows_lab_stage_sources.ps1',
            'scripts/python-isolation-fixture.py',
            'tests/windows-lab/test_python_isolation_sources.py',
            'tests/python-probe/test_isolation_fixture.py',
            'native/windows-sandbox/src/python_isolation.rs',
            'native/windows-sandbox/src/python_isolation/broker.rs',
            'native/windows-sandbox/src/python_isolation/observer.rs',
            'native/windows-sandbox/examples/python_isolation_acceptance.rs',
            'native/windows-sandbox/examples/python_isolation_acceptance/windows.rs',
            'native/windows-sandbox/tests/python_isolation_contract.rs',
        ]
        for path in required:
            self.assertIn("'" + path + "'", source)
        self.assertIn('Duplicate or case-colliding source manifest path.', source)
        self.assertIn('Source manifest mismatch:', source)
        self.assertIn('pub const NATIVE_VALIDATED: bool = false;', source)

    def test_disable_always_runs_after_setup_attempt_even_when_run_fails(self):
        source = self.workflow
        self.assertIn("if: ${{ always() && steps.stage.outcome == 'success' && steps.setup.outcome != 'skipped' }}", source)
        self.assertEqual(source.count('-Phase Stage -ApprovedDisposableVm'), 1)
        self.assertEqual(source.count('-Phase Setup -ApprovedDisposableVm'), 1)
        self.assertEqual(source.count('-Phase Run -ApprovedDisposableVm'), 1)
        self.assertEqual(source.count('-Phase Disable -ApprovedDisposableVm'), 1)
        self.assertEqual(source.count('continue-on-error: true'), 1)
        self.assertIn('continue-on-error: true', self.firewall_observation())
        self.assertNotIn('retry', self.actions.lower().replace('no automatic in-job retry', '').replace('no retry', ''))
        self.assertIn('NOT_TESTED', source)
        self.assertIn('Production activation stays false', source)
        self.assertIn('hosted job teardown', source)

    def test_evidence_copy_and_upload_are_exact_fixed_allowlists(self):
        source = self.workflow
        copy_section = source.split('foreach ($name in @(', 1)[1].split(')) {', 1)[0]
        copied = set(re.findall(r"'([^']+\.json)'", copy_section))
        self.assertEqual(copied, EVIDENCE_JSON)
        upload_section = source.split('          path: |', 1)[1]
        uploaded = [line.strip() for line in upload_section.splitlines() if line.strip()]
        for name in EVIDENCE_JSON:
            self.assertIn('python-isolation-evidence/' + name, uploaded)
        self.assertEqual(len(uploaded), len(set(uploaded)))
        for path in uploaded:
            self.assertRegex(path, r'\Apython-isolation-evidence/[a-z-]+\.(json|log)\Z')
            if path != 'python-isolation-evidence/python-isolation-firewall-active-store.json':
                self.assertNotIn('store', path)
            self.assertNotIn('credential', path)
        self.assertIn('include-hidden-files: false', source)
        self.assertIn('retention-days: 7', source)
        self.assertIn("Assert-LabSourceAncestors -Path $source -Role 'isolation-evidence'", source)
        self.assertIn('.Length -gt 8388608', source)
        self.assertNotIn('**', upload_section)

    def firewall_observation(self):
        return self.workflow.split('      - name: Observe only five owned ActiveStore rules', 1)[1].split(
            '      - name: Run fixed ordinary control', 1)[0]

    def test_optional_firewall_metadata_cannot_replace_or_gate_runtime(self):
        source = self.workflow
        observation = self.firewall_observation()
        self.assertLess(source.index('id: setup'), source.index('id: firewall_observation'))
        self.assertLess(source.index('id: firewall_observation'), source.index('id: run'))
        self.assertIn("if: ${{ steps.setup.outcome == 'success' }}", observation)
        self.assertIn('continue-on-error: true', observation)
        self.assertIn('timeout-minutes: 2', observation)
        self.assertIn('exit 0', observation)
        self.assertIn('provesConnectionBlocking=$false', observation)
        self.assertIn('liveConnectionObservationsAuthoritative=$true', observation)
        self.assertIn("observation='INCONCLUSIVE'", observation)
        for reason in ['MISSING_RULE', 'DUPLICATE_RULE', 'QUERY_OR_PROPERTY_UNAVAILABLE']:
            self.assertIn(reason, observation)
        run = source.split('        id: run', 1)[1].split('      - name:', 1)[0]
        self.assertNotIn('firewall_observation', run)
        self.assertIn('-Phase Run -ApprovedDisposableVm', run)

    def test_firewall_metadata_reads_exact_five_names_and_associated_filters_only(self):
        observation = self.firewall_observation()
        specs = observation.split('$specifications = @(', 1)[1].split('          )', 1)[0]
        self.assertEqual(re.findall(r"name='([^']+)'", specs), [
            'pi_sandbox_offline_block_outbound', 'pi_sandbox_offline_block_inbound',
            'pi_sandbox_offline_block_loopback_tcp', 'pi_sandbox_offline_block_loopback_udp',
            'pi_sandbox_offline_block_loopback_inbound',
        ])
        self.assertEqual(observation.count('Get-NetFirewallRule '), 1)
        self.assertIn('Get-NetFirewallRule -PolicyStore ActiveStore -Name $spec.name -ErrorAction Stop', observation)
        for filter_name in ['Address', 'Port', 'Security']:
            self.assertIn(f'Get-NetFirewall{filter_name}Filter -AssociatedNetFirewallRule $rule -ErrorAction Stop', observation)
        for forbidden in ['Set-NetFirewall', 'New-NetFirewall', 'Remove-NetFirewall',
                          'Enable-NetFirewall', 'Disable-NetFirewall', 'netsh ', 'auditpol ',
                          'pktmon ', 'netsh.exe', 'Get-NetFirewallProfile', 'Get-LocalUser',
                          'Get-NetFirewallRule -All', 'Get-NetFirewallRule -DisplayName']:
            self.assertNotIn(forbidden, observation)
        self.assertIn('$rules.Count -ne 1', observation)
        self.assertIn('$address.Count -ne 1', observation)
        self.assertIn('$port.Count -ne 1', observation)
        self.assertIn('$security.Count -ne 1', observation)

    def test_firewall_metadata_serializes_only_normalized_status_and_scope_facts(self):
        observation = self.firewall_observation()
        observed = observation.split("name=$spec.name; observation='OBSERVED'", 1)[1].split('              }', 1)[0]
        for field in ['enforcementStatus=$enforcement', 'primaryStatus=(Safe-Enum',
                      'action=$action', 'direction=$direction', 'enabled=$enabled',
                      'profile=$profile', 'protocol=$protocol', 'expectedMatches=$matches']:
            self.assertIn(field, observed)
        for field in ['localAddressAny=', 'remoteAddressScope=', 'localPortAny=',
                      'remotePortAny=', 'localUserScope=', 'remoteUserAny=', 'remoteMachineAny=']:
            self.assertIn(field, observation)
        self.assertIn('User-Scope-Matches $security[0].LocalUser $accountSid', observation)
        self.assertIn('$descriptor.DiscretionaryAcl.Count -ne 1', observation)
        self.assertIn('$ace.AccessMask -eq 1', observation)
        self.assertIn('$ace.SecurityIdentifier.Value -ceq $Sid', observation)
        for forbidden in ['accountSid=$accountSid', 'localUser=$', 'SDDL=', '$_.Exception',
                          '$_.ToString', '$rule | ConvertTo-Json', '$security | ConvertTo-Json',
                          'Format-List', 'Format-Table', 'Write-Error', 'Write-Warning']:
            self.assertNotIn(forbidden, observation)
        self.assertIn("return 'UNKNOWN'", observation)
        self.assertIn("'LocalUserEmpty'", observation)
        self.assertIn("'LocalFirewallRulesDisallowed'", observation)
        self.assertIn("$entry.reason='BASELINE_IDENTITY_UNAVAILABLE'", observation)
        self.assertIn('[Net.IPAddress]::Parse', observation)
        self.assertNotIn('GetHost', observation)
        self.assertNotIn('TcpClient', observation)
        self.assertNotIn('socket', executable_lines(observation))

    def test_firewall_metadata_has_one_exact_artifact_destination(self):
        observation = self.firewall_observation()
        artifact = 'python-isolation-evidence/python-isolation-firewall-active-store.json'
        self.assertIn('Set-Content -LiteralPath ' + artifact, observation)
        upload = self.workflow.split('          path: |', 1)[1]
        self.assertEqual(upload.count(artifact), 1)
        self.assertEqual(self.workflow.count(artifact), 2)
        self.assertNotIn('python-isolation-firewall-active-store.json',
                         self.workflow.split('foreach ($name in @(', 1)[1].split(')) {', 1)[0])

    def test_stager_requires_fresh_elevated_exact_scope(self):
        source = self.stager
        for required in [
            "[ValidateSet('Stage','Setup','Run','Disable')]",
            'if (-not $ApprovedDisposableVm)',
            "$env:GITHUB_REPOSITORY -cne 'ni-taesoon/pi-windows-sandbox-poc'",
            "$env:GITHUB_REF -cne 'refs/heads/lab/python-isolation-acceptance'",
            "$env:ImageOS -ne 'win22'", "$os.BuildNumber -ne '20348'",
            '[Security.Principal.WindowsBuiltInRole]::Administrator',
            'if (Test-Path -LiteralPath $root)',
            '$SourceCommit -cne $env:GITHUB_SHA',
            "$root = 'C:\\PiSandboxLab'",
        ]:
            self.assertIn(required, source)
        self.assertLess(source.index('Set-Acl -LiteralPath $root'), source.index('Copy-Item -LiteralPath $file.source'))
        self.assertIn('no retry or host fallback', source)
        self.assertEqual(self.stage_actions.count('& $driver ($Phase.ToLowerInvariant())'), 1)

    def test_runtime_selection_inspects_before_traversal_and_never_reuses_old_driver(self):
        source = self.stager
        selector = source.split('function Get-PythonIsolationRuntimeEntries', 1)[1].split("if ($Phase -eq 'Stage')", 1)[0]
        self.assertLess(selector.index('Assert-LabSourceAncestors'), selector.index('$pending.Enqueue'))
        self.assertLess(selector.index('Assert-LabSourceItem'), selector.index('Get-ChildItem'))
        self.assertIn('Queue[string]', selector)
        self.assertIn('HashSet[string]', selector)
        self.assertIn('OrdinalIgnoreCase', selector)
        self.assertIn('GetRelativePath', selector)
        self.assertIn("$parts | Where-Object { $_ -in @('', '.', '..')", selector)
        self.assertIn("-ceq 'SymbolicLink'", selector)
        self.assertIn("Join-Path $sourceRootFull 'python3.exe'", selector)
        self.assertIn('-not $item.PSIsContainer', selector)
        self.assertIn('unused-root-symbolic-link-not-read-or-copied', selector)
        for forbidden in ['-Recurse', '-FollowSymlink', 'Resolve-Path', '.Target', 'Get-LabStageSources', 'python_lab.exe']:
            self.assertNotIn(forbidden, self.stage_actions)
        self.assertIn('if ($actual.skipped.Count -ne 0)', source)

    def test_runtime_all_file_hashes_are_preserved_and_reverified(self):
        source = self.stager
        for required in [
            "schemaVersion=1; pythonVersion='3.12.10'; inputs=$inputs",
            '$inputs.Add($destination, $entry.sha256)',
            'Assert-FixedFile -Path $entry.source -Hash $entry.sha256',
            'Assert-FixedFile -Path $destination -Hash $entry.sha256',
            'runtimeManifestSha256=',
            'Assert-FixedFile -Path $runtimeManifest -Hash $stage.runtimeManifestSha256',
            '$actualFiles.Count -ne $expectedFiles.Count',
            '$actualFiles.Count -ne $stage.runtimeFileCount',
            '$entry.sha256 -cne $expected.Value',
            'not independent upstream provenance verification',
            'Trusted quiescent official runtime',
            "foreach ($entry in $selection.entries)",
        ]:
            self.assertIn(required, source)
        self.assertIn('20000', source)
        self.assertIn('$parts.Count -gt 32', source)
        self.assertIn('$ExpectedDriverSha256.ToLowerInvariant()', source)
        self.assertIn('$ExpectedHelperSha256.ToLowerInvariant()', source)
        self.assertIn('$ExpectedFixtureSha256.ToLowerInvariant()', source)
        self.assertIn('$ExpectedPythonSha256.ToLowerInvariant()', source)
        self.assertIn('2147483648', source)
        self.assertNotRegex(self.stage_actions, r'Copy-Item[^\n]*\*')

    def test_only_outside_world_synthetic_leaf_gets_everyone_modify(self):
        source = self.stager
        self.assertIn("'work\\denied-write', 'work\\denied-read', 'fixtures', 'fixtures\\outside-world'", source)
        self.assertIn("@($trusted, $runtime, \"$root\\work\", \"$root\\fixtures\")", source)
        grant_lines = [line.strip() for line in self.stage_actions.splitlines() if "'/grant:r'" in line]
        self.assertEqual(grant_lines, [
            "Invoke-Icacls -Arguments @(\"$root\\fixtures\\outside-world\", '/grant:r', '*S-1-1-0:(OI)(CI)(M)', '/Q')"
        ])
        self.assertEqual(source.count('*S-1-1-0:'), 1)
        self.assertIn('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', source)
        self.assertIn('All fixed policy roots must already exist.', source)
        self.assertNotIn('input.txt', self.stage_actions)
        self.assertNotIn('secret.txt', self.stage_actions)

    def test_disable_does_not_require_python_or_fixture_integrity(self):
        source = self.stager
        tail = source.split("if ($Phase -ne 'Disable') {", 1)
        self.assertEqual(len(tail), 2)
        before, gated = tail
        self.assertIn('Assert-FixedFile -Path $driver -Hash $stage.driverSha256', before)
        self.assertIn('$stage.sourceCommit -cne $env:GITHUB_SHA', before)
        for pin in ['$stage.helperSha256', '$stage.fixtureSha256', '$stage.pythonSha256',
                    '$stage.runtimeManifestSha256']:
            self.assertIn(pin, gated)
            self.assertNotIn(pin, before)
        self.assertIn('owned-SID disable', source)

    def test_closed_feature_gate_and_no_advanced_feature_dependencies(self):
        cargo = (NATIVE / 'Cargo.toml').read_text(encoding='utf-8')
        library = (NATIVE / 'src/lib.rs').read_text(encoding='utf-8')
        self.assertRegex(cargo, r'(?m)^default = \[\]$')
        self.assertRegex(cargo, r'(?m)^lab-python-isolation-acceptance = \[\]$')
        self.assertIn('pub const NATIVE_VALIDATED: bool = false;', library)
        self.assertIn('feature = "lab-python-isolation-acceptance"', library)

    def test_fixture_source_parses_without_importing_or_executing_it(self):
        fixture = (ROOT / 'scripts/python-isolation-fixture.py').read_text(encoding='utf-8')
        tree = ast.parse(fixture, filename='python-isolation-fixture.py')
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split('.')[0])
        self.assertTrue(modules)
        self.assertTrue(modules <= {
            'base64', 'ctypes', 'errno', 'hashlib', 'io', 'json', 'os', 'pathlib',
            'socket', 'subprocess', 'sys', 'time', 'traceback',
        }, modules)
        for forbidden in ['requests', 'urllib', 'http.client', 'pip', 'getaddrinfo', 'gethostbyname']:
            self.assertNotIn(forbidden, fixture)
        for literal in ['127.0.0.1', '::1', '43871', '43872']:
            self.assertIn(literal, fixture)


if __name__ == '__main__':
    unittest.main()
