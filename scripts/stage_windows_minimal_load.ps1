# LAB ONLY. A branch push, dispatch checkbox, or switch never grants approval.
# Obtain external, explicit action-time authorization for the disposable win22
# account/ACL/store/firewall/WFP lifecycle and this fixed comparison first.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Stage','Setup','Run','Disable')][string]$Phase,
  [Parameter(Mandatory=$true)][switch]$ApprovedDisposableVm,
  [string]$BuildDirectory,
  [string]$ExpectedDriverSha256,
  [string]$ExpectedHelperSha256,
  [string]$ExpectedMinimalLoadSha256,
  [string]$ApprovedSourceSha256,
  [string]$SourceCommit
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ApprovedDisposableVm) { throw 'Explicit disposable VM security-change approval required.' }
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') { throw 'This lab is scoped to a fresh GitHub-hosted Windows runner.' }
if ($env:ImageOS -ne 'win22') { throw 'Approved scope requires the Windows Server 2022 runner image (win22).' }
$os = Get-CimInstance -ClassName Win32_OperatingSystem
if ($os.BuildNumber -ne '20348' -or $os.Caption -notlike '*Windows Server 2022*') { throw 'Actual OS is outside the approved Server 2022 scope.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Already-elevated runner required. No elevation is provided.' }
. "$PSScriptRoot/windows_lab_stage_sources.ps1"
$root = 'C:\PiSandboxLab'
$trusted = "$root\trusted"
$driver = "$trusted\minimal_load_comparison.exe"
$stageEvidence = "$trusted\minimal-load-stage.json"
$icacls = "$env:SystemRoot\System32\icacls.exe"
function Invoke-Icacls([string[]]$Arguments) {
  & $icacls @Arguments
  if ($LASTEXITCODE -ne 0) { throw "Scoped icacls failed ($LASTEXITCODE). Dispose VM; do not broaden ACLs." }
}
function Assert-FixedFile([string]$Path, [string]$Hash, [string]$Role) {
  if ($Hash -notmatch '\A[0-9a-fA-F]{64}\z') { throw "Missing SHA256 pin for $Role." }
  Assert-LabSourceAncestors -Path $Path -Role $Role
  if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) { throw "Expected fixed file for $Role." }
  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash -ine $Hash) { throw "Fixed file hash mismatch for $Role." }
}
if ($Phase -eq 'Stage') {
  if (Test-Path -LiteralPath $root) { throw 'Existing lab root refused. Start a fresh disposable VM.' }
  if (-not $BuildDirectory) { throw 'Stage requires an explicit BuildDirectory.' }
  if ($SourceCommit -cnotmatch '\A[0-9a-f]{40}\z') { throw 'Immutable reviewed source commit required.' }
  $manifest = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\SOURCE_SHA256SUMS.txt'))
  Assert-FixedFile -Path $manifest -Hash $ApprovedSourceSha256 -Role 'source-manifest'
  $build = [IO.Path]::GetFullPath($BuildDirectory).TrimEnd('\')
  $files = @(
    [pscustomobject]@{ source=(Join-Path $build 'pi-windows-sandbox.exe'); name='pi-windows-sandbox.exe'; hash=$ExpectedHelperSha256; role='helper-executable' },
    [pscustomobject]@{ source=(Join-Path $build 'examples\minimal_load_comparison.exe'); name='minimal_load_comparison.exe'; hash=$ExpectedDriverSha256; role='comparison-driver' },
    [pscustomobject]@{ source=(Join-Path $build 'minimal_load.exe'); name='minimal_load.exe'; hash=$ExpectedMinimalLoadSha256; role='minimal-load-executable' }
  )
  foreach ($file in $files) { Assert-FixedFile -Path $file.source -Hash $file.hash -Role $file.role }
  Assert-LabSourceAncestors -Path 'C:\' -Role 'lab-root-parent'
  New-Item -ItemType Directory -Path $root | Out-Null
  # Same protected synthetic-root ACL as the existing disposable lifecycle.
  # Replace inheritance before introducing executables or an account store.
  $ownerSid = $identity.User.Value
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $acl.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$ownerSid)(A;OICI;FRFX;;;BU)")
  Set-Acl -LiteralPath $root -AclObject $acl
  foreach ($directory in @('trusted', 'work')) { New-Item -ItemType Directory -Path "$root\$directory" | Out-Null }
  # Exactly three validated executables; no runtime tree or wildcard traversal.
  # Recheck at copy time. This assumes a trusted quiescent build directory and
  # does not claim race-free source pinning against a concurrent administrator.
  foreach ($file in $files) {
    Assert-FixedFile -Path $file.source -Hash $file.hash -Role $file.role
    $destination = Join-Path $trusted $file.name
    Copy-Item -LiteralPath $file.source -Destination $destination
    Assert-FixedFile -Path $destination -Hash $file.hash -Role "staged-$($file.role)"
  }
  # ACL reset/ownership changes are restricted to the newly created lab tree.
  Invoke-Icacls -Arguments @($trusted, '/reset', '/T', '/Q')
  Invoke-Icacls -Arguments @("$root\work", '/reset', '/T', '/Q')
  Invoke-Icacls -Arguments @($root, '/setowner', '*S-1-5-32-544', '/T', '/Q')
  [ordered]@{
    scope='LAB_MINIMAL_LOAD_COMPARISON'; machine=$env:COMPUTERNAME; runnerOs=$env:RUNNER_OS;
    osCaption=$os.Caption; osBuild=$os.BuildNumber; imageOs=$env:ImageOS; ownerSid=$ownerSid;
    sourceCommit=$SourceCommit; sourceManifestSha256=$ApprovedSourceSha256;
    driverSha256=$ExpectedDriverSha256; helperSha256=$ExpectedHelperSha256;
    minimalLoadSha256=$ExpectedMinimalLoadSha256; nativeValidated=$false
  } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $stageEvidence -Encoding UTF8
  Write-Output 'LAB_MINIMAL_LOAD_STAGED_ONLY: three fixed executables; no account or child process created.'
  exit 0
}
Assert-LabSourceAncestors -Path $stageEvidence -Role 'stage-evidence'
if ((Get-Item -LiteralPath $stageEvidence -Force).PSIsContainer) { throw 'Invalid stage evidence.' }
$stage = Get-Content -LiteralPath $stageEvidence -Raw | ConvertFrom-Json
if ($stage.scope -cne 'LAB_MINIMAL_LOAD_COMPARISON' -or $stage.nativeValidated -ne $false) { throw 'Unexpected stage identity.' }
Assert-FixedFile -Path $driver -Hash $stage.driverSha256 -Role 'staged-comparison-driver'
if ($Phase -ne 'Disable') {
  Assert-FixedFile -Path "$trusted\pi-windows-sandbox.exe" -Hash $stage.helperSha256 -Role 'staged-helper-executable'
  Assert-FixedFile -Path "$trusted\minimal_load.exe" -Hash $stage.minimalLoadSha256 -Role 'staged-minimal-load-executable'
}
& $driver ($Phase.ToLowerInvariant())
if ($LASTEXITCODE -ne 0) { throw "Minimal-load lab $Phase failed ($LASTEXITCODE). Retain allowlisted evidence and dispose VM; do not retry or use a host fallback." }
