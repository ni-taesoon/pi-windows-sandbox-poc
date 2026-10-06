# LAB ONLY. A branch push, dispatch checkbox, or switch never grants approval.
# Obtain explicit external action-time authorization for this reviewed source and
# fresh win22 account/ACL/store/firewall/WFP lifecycle, including the synthetic
# outside-world Everyone Modify leaf, native-owned session grant on outside-logon,
# loopback canaries, disable, and VM disposal.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Stage','Setup','Run','Disable')][string]$Phase,
  [Parameter(Mandatory=$true)][switch]$ApprovedDisposableVm,
  [string]$PythonHome,
  [string]$BuildDirectory,
  [string]$ExpectedDriverSha256,
  [string]$ExpectedHelperSha256,
  [string]$ExpectedFixtureSha256,
  [string]$ExpectedPythonSha256,
  [string]$ApprovedSourceSha256,
  [string]$SourceCommit
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ApprovedDisposableVm) { throw 'Explicit disposable VM security-change approval required.' }
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') { throw 'This lab requires a fresh GitHub-hosted Windows runner.' }
if ($env:GITHUB_REPOSITORY -cne 'ni-taesoon/pi-windows-sandbox-poc' -or $env:GITHUB_REF -cne 'refs/heads/lab/python-isolation-acceptance') { throw 'Unexpected repository or lab branch.' }
if ($env:GITHUB_SHA -cnotmatch '\A[0-9a-f]{40}\z') { throw 'Immutable event SHA required.' }
if ($env:ImageOS -ne 'win22') { throw 'Only Windows Server 2022 (win22) is in scope.' }
$os = Get-CimInstance -ClassName Win32_OperatingSystem
if ($os.BuildNumber -ne '20348' -or $os.Caption -notlike '*Windows Server 2022*') { throw 'Actual OS is outside the approved Server 2022 scope.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Already-elevated runner required. No elevation is provided.' }
. "$PSScriptRoot/windows_lab_stage_sources.ps1"
$root = 'C:\PiSandboxLab'
$trusted = "$root\trusted"
$runtime = "$root\runtime"
$driver = "$trusted\python_isolation_acceptance.exe"
$stageEvidence = "$trusted\python-isolation-stage.json"
$runtimeManifest = "$trusted\python-isolation-runtime-manifest.json"
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
# This narrow selector does not call Get-LabStageSources: that older selector
# chooses another driver. Inspection always precedes traversal; no link target is
# resolved. The one unused setup-python root python3.exe SymbolicLink is excluded.
function Get-PythonIsolationRuntimeEntries([string]$SourceRoot) {
  $sourceRootFull = [IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
  Assert-LabSourceAncestors -Path $sourceRootFull -Role 'python-runtime-root'
  if (-not (Get-Item -LiteralPath $sourceRootFull -Force).PSIsContainer) { throw 'Runtime source must be a directory.' }
  $pending = [Collections.Generic.Queue[string]]::new()
  $pending.Enqueue($sourceRootFull)
  $entries = [Collections.Generic.List[object]]::new()
  $skipped = [Collections.Generic.List[object]]::new()
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $totalBytes = [long]0
  while ($pending.Count) {
    $source = $pending.Dequeue()
    $item = Get-Item -LiteralPath $source -Force
    if ($source -ceq (Join-Path $sourceRootFull 'python3.exe') -and
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
        -not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::Directory) -and
        $item.PSObject.Properties['LinkType'] -and $item.LinkType -ceq 'SymbolicLink') {
      $skipped.Add([pscustomobject]@{ relative='python3.exe'; reason='unused-root-symbolic-link-not-read-or-copied' })
      continue
    }
    Assert-LabSourceItem -Item $item -Role 'python-isolation-runtime'
    if ($source -cne $sourceRootFull) {
      $relative = [IO.Path]::GetRelativePath($sourceRootFull, $item.FullName)
      $parts = @($relative.Split('\'))
      if ($parts.Count -gt 32 -or [IO.Path]::IsPathRooted($relative) -or @($parts | Where-Object { $_ -in @('', '.', '..') -or $_.Contains(':') -or $_.EndsWith('.') -or $_.EndsWith(' ') }).Count) { throw 'Runtime entry escaped or has an ambiguous name.' }
      if (-not $seen.Add($relative)) { throw 'Duplicate or case-colliding runtime entry.' }
      if ($entries.Count -ge 20000) { throw 'Runtime entry count exceeds bound.' }
      $digest = $null
      $length = [long]0
      if (-not $item.PSIsContainer) {
        $length = $item.Length
        $totalBytes += $length
        if ($length -gt 134217728 -or $totalBytes -gt 2147483648) { throw 'Runtime file or total size exceeds bound.' }
        $digest = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
      }
      $entries.Add([pscustomobject]@{ source=$item.FullName; relative=$relative; isDirectory=[bool]$item.PSIsContainer; length=$length; sha256=$digest })
    }
    if ($item.PSIsContainer) {
      # Immediate children only. Each child is inspected on dequeue before use.
      foreach ($child in Get-ChildItem -LiteralPath $source -Force | Sort-Object Name) { $pending.Enqueue($child.FullName) }
    }
  }
  if (-not ($entries | Where-Object { $_.relative -ceq 'python.exe' -and -not $_.isDirectory })) { throw 'Missing exact runtime/python.exe.' }
  [pscustomobject]@{ root=$sourceRootFull; entries=$entries.ToArray(); skipped=$skipped.ToArray() }
}
if ($Phase -eq 'Stage') {
  if (Test-Path -LiteralPath $root) { throw 'Existing lab root refused. Start a fresh disposable VM.' }
  if (-not $BuildDirectory -or -not $PythonHome) { throw 'Stage requires explicit BuildDirectory and PythonHome.' }
  if ($SourceCommit -cnotmatch '\A[0-9a-f]{40}\z' -or $SourceCommit -cne $env:GITHUB_SHA) { throw 'Reviewed source commit must exactly equal the immutable event SHA.' }
  $sourceManifest = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\SOURCE_SHA256SUMS.txt'))
  Assert-FixedFile -Path $sourceManifest -Hash $ApprovedSourceSha256 -Role 'source-manifest'
  $build = [IO.Path]::GetFullPath($BuildDirectory).TrimEnd('\')
  $files = @(
    [pscustomobject]@{ source=(Join-Path $build 'pi-windows-sandbox.exe'); name='pi-windows-sandbox.exe'; hash=$ExpectedHelperSha256; role='helper-executable' },
    [pscustomobject]@{ source=(Join-Path $build 'examples\python_isolation_acceptance.exe'); name='python_isolation_acceptance.exe'; hash=$ExpectedDriverSha256; role='isolation-driver' },
    [pscustomobject]@{ source=(Join-Path $PSScriptRoot 'python-isolation-fixture.py'); name='python-isolation-fixture.py'; hash=$ExpectedFixtureSha256; role='fixed-fixture' }
  )
  foreach ($file in $files) { Assert-FixedFile -Path $file.source -Hash $file.hash -Role $file.role }
  $selection = Get-PythonIsolationRuntimeEntries -SourceRoot $PythonHome
  Assert-FixedFile -Path (Join-Path $selection.root 'python.exe') -Hash $ExpectedPythonSha256 -Role 'official-python-executable'
  # The workflow checks sys.version_info == (3, 12, 10) and x64 before hashing.
  # Windows FileVersion's build field is not Python's micro-version number.
  $pythonFileVersion = (Get-Item -LiteralPath (Join-Path $selection.root 'python.exe') -Force).VersionInfo.FileVersion
  Assert-LabSourceAncestors -Path 'C:\' -Role 'lab-root-parent'
  New-Item -ItemType Directory -Path $root | Out-Null
  # Replace inheritance before introducing runtime, trusted executables or store.
  $ownerSid = $identity.User.Value
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $acl.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$ownerSid)(A;OICI;FRFX;;;BU)")
  Set-Acl -LiteralPath $root -AclObject $acl
  foreach ($directory in @('trusted', 'runtime', 'work', 'work\denied-write', 'work\denied-read', 'fixtures', 'fixtures\outside-world', 'fixtures\outside-logon')) {
    New-Item -ItemType Directory -Path (Join-Path $root $directory) | Out-Null
  }
  foreach ($file in $files) {
    Assert-FixedFile -Path $file.source -Hash $file.hash -Role $file.role
    $destination = Join-Path $trusted $file.name
    Copy-Item -LiteralPath $file.source -Destination $destination
    Assert-FixedFile -Path $destination -Hash $file.hash -Role "staged-$($file.role)"
  }
  $inputs = [ordered]@{}
  # Consume this inspected selection only, never a wildcard copy or new recursive
  # source traversal. Trusted quiescent setup-python files are a lab assumption;
  # this does not claim race-free pinning against concurrent administrator writes.
  foreach ($entry in $selection.entries) {
    Assert-LabSourceAncestors -Path $entry.source -Role 'runtime-copy-source'
    $item = Get-Item -LiteralPath $entry.source -Force
    if ([bool]$item.PSIsContainer -ne $entry.isDirectory) { throw 'Runtime source type changed.' }
    $destination = Join-Path $runtime $entry.relative
    if ($entry.isDirectory) { New-Item -ItemType Directory -Path $destination | Out-Null }
    else {
      Assert-FixedFile -Path $entry.source -Hash $entry.sha256 -Role 'runtime-copy-source'
      Copy-Item -LiteralPath $entry.source -Destination $destination
      Assert-FixedFile -Path $destination -Hash $entry.sha256 -Role 'staged-runtime-file'
      if ((Get-Item -LiteralPath $destination -Force).Length -ne $entry.length) { throw 'Runtime file length changed.' }
      $inputs.Add($destination, $entry.sha256)
    }
  }
  foreach ($directory in @($trusted, $runtime, "$root\work", "$root\fixtures")) { Invoke-Icacls -Arguments @($directory, '/reset', '/T', '/Q') }
  Invoke-Icacls -Arguments @($root, '/setowner', '*S-1-5-32-544', '/T', '/Q')
  # outside-logon retains the protected inherited root ACL and BA ownership.
  # Only the native broker may later grant the authenticated helper Logon SID,
  # after ten durable control frames. Staging never selects or grants that SID.
  # This sole staging exception is a newly created synthetic negative-control
  # leaf, never an executable/input location. No real user directory is changed.
  Invoke-Icacls -Arguments @("$root\fixtures\outside-world", '/grant:r', '*S-1-1-0:(OI)(CI)(M)', '/Q')
  [ordered]@{
    schemaVersion=1; pythonVersion='3.12.10'; inputs=$inputs;
    excludedRuntimeEntries=@($selection.skipped);
    provenance='Official actions/setup-python exact 3.12.10 x64 runtime. Per-run all-file hashes bind staged bytes; they are not independent upstream provenance verification.';
    sourceAssumption='Trusted quiescent official runtime; no claim of race-free source pinning against a concurrent administrator.'
  } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $runtimeManifest -Encoding UTF8
  [ordered]@{
    scope='LAB_PYTHON_ISOLATION_ACCEPTANCE'; machine=$env:COMPUTERNAME; runnerOs=$env:RUNNER_OS;
    osCaption=$os.Caption; osBuild=$os.BuildNumber; imageOs=$env:ImageOS; ownerSid=$ownerSid;
    sourceCommit=$SourceCommit; sourceManifestSha256=$ApprovedSourceSha256.ToLowerInvariant();
    driverSha256=$ExpectedDriverSha256.ToLowerInvariant(); helperSha256=$ExpectedHelperSha256.ToLowerInvariant();
    fixtureSha256=$ExpectedFixtureSha256.ToLowerInvariant(); pythonSha256=$ExpectedPythonSha256.ToLowerInvariant();
    runtimeManifestSha256=(Get-FileHash -LiteralPath $runtimeManifest -Algorithm SHA256).Hash.ToLowerInvariant();
    runtimeFileCount=$inputs.Count; pythonVersion='3.12.10'; pythonFileVersion=$pythonFileVersion;
    outsideLogonInitiallyProtected=$true; outsideLogonGrantOwner='native-verified-helper-logon-only'; nativeValidated=$false
  } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $stageEvidence -Encoding UTF8
  Write-Output 'LAB_PYTHON_ISOLATION_STAGED_ONLY: no account, fixture execution or network probe. Native setup creates fixed benign content.'
  exit 0
}
Assert-LabSourceAncestors -Path $stageEvidence -Role 'stage-evidence'
if ((Get-Item -LiteralPath $stageEvidence -Force).PSIsContainer -or (Get-Item -LiteralPath $stageEvidence -Force).Length -gt 65536) { throw 'Invalid stage evidence.' }
$stage = Get-Content -LiteralPath $stageEvidence -Raw | ConvertFrom-Json
if ($stage.scope -cne 'LAB_PYTHON_ISOLATION_ACCEPTANCE' -or $stage.nativeValidated -ne $false -or $stage.sourceCommit -cne $env:GITHUB_SHA) { throw 'Unexpected stage identity.' }
Assert-FixedFile -Path $driver -Hash $stage.driverSha256 -Role 'staged-isolation-driver'
# Disable requires only its hash-bound driver and stage identity. A changed or
# missing Python/input must not prevent attempting authenticated owned-SID disable.
if ($Phase -ne 'Disable') {
  Assert-FixedFile -Path "$trusted\pi-windows-sandbox.exe" -Hash $stage.helperSha256 -Role 'staged-helper-executable'
  Assert-FixedFile -Path "$trusted\python-isolation-fixture.py" -Hash $stage.fixtureSha256 -Role 'staged-fixed-fixture'
  Assert-FixedFile -Path "$runtime\python.exe" -Hash $stage.pythonSha256 -Role 'staged-python-executable'
  Assert-FixedFile -Path $runtimeManifest -Hash $stage.runtimeManifestSha256 -Role 'staged-runtime-manifest'
  if ((Get-Item -LiteralPath $runtimeManifest -Force).Length -gt 8388608) { throw 'Runtime manifest exceeds bound.' }
  $manifest = Get-Content -LiteralPath $runtimeManifest -Raw | ConvertFrom-Json
  if ($manifest.schemaVersion -ne 1 -or $manifest.pythonVersion -cne '3.12.10') { throw 'Unexpected runtime manifest schema.' }
  $actual = Get-PythonIsolationRuntimeEntries -SourceRoot $runtime
  if ($actual.skipped.Count -ne 0) { throw 'Staged runtime may not contain aliases.' }
  $actualFiles = @($actual.entries | Where-Object { -not $_.isDirectory })
  $expectedFiles = @($manifest.inputs.PSObject.Properties)
  if ($actualFiles.Count -ne $expectedFiles.Count -or $actualFiles.Count -ne $stage.runtimeFileCount) { throw 'Runtime file inventory changed.' }
  foreach ($entry in $actualFiles) {
    $expected = $manifest.inputs.PSObject.Properties[$entry.source]
    if ($null -eq $expected -or $entry.sha256 -cne $expected.Value) { throw 'Runtime all-file hash verification failed.' }
  }
  foreach ($directory in @('work\denied-read', 'work\denied-write', 'fixtures\outside-world', 'fixtures\outside-logon')) {
    $path = Join-Path $root $directory
    Assert-LabSourceAncestors -Path $path -Role 'existing-synthetic-policy-root'
    if (-not (Get-Item -LiteralPath $path -Force).PSIsContainer) { throw 'All fixed policy roots must already exist.' }
  }
}
& $driver ($Phase.ToLowerInvariant())
if ($LASTEXITCODE -ne 0) { throw "Python isolation lab $Phase failed ($LASTEXITCODE). Retain allowlisted evidence and dispose VM; no retry or host fallback." }
