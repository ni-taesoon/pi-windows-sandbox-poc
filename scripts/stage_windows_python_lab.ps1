# LAB ONLY. A workflow dispatch or this switch is NOT proof of user approval.
# Obtain explicit action-time approval for the scope in WINDOWS_PYTHON_LAB.md first.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Stage','Setup','Run','Disable')][string]$Phase,
  [Parameter(Mandatory=$true)][switch]$ApprovedDisposableVm,
  [string]$PythonHome,
  [string]$BuildDirectory,
  [string]$ExpectedDriverSha256,
  [string]$ExpectedHelperSha256,
  [string]$ExpectedPythonSha256,
  [string]$ApprovedSourceSha256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ApprovedDisposableVm) { throw 'Explicit disposable VM security-change approval required.' }
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') { throw 'This lab script is scoped to a fresh GitHub-hosted Windows runner.' }
if ($env:ImageOS -ne 'win22') { throw 'Approved scope requires the Windows Server 2022 runner image (win22).' }
$os = Get-CimInstance -ClassName Win32_OperatingSystem
if ($os.BuildNumber -ne '20348' -or $os.Caption -notlike '*Windows Server 2022*') { throw 'Actual OS is outside the approved Server 2022 scope.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Already-elevated runner required. No UAC bypass or elevation is provided.' }
$root = 'C:\PiSandboxLab'
$driver = "$root\trusted\python_lab.exe"
$icacls = "$env:SystemRoot\System32\icacls.exe"
function Invoke-Icacls([string[]]$Arguments) {
  & $icacls @Arguments
  if ($LASTEXITCODE -ne 0) { throw "Scoped icacls failed ($LASTEXITCODE). Dispose VM; do not broaden ACLs." }
}
if ($Phase -eq 'Stage') {
  if (Test-Path -LiteralPath $root) { throw 'Existing lab root refused. Start a fresh disposable VM.' }
  if (-not $PythonHome -or -not $BuildDirectory) { throw 'Stage requires explicit PythonHome and BuildDirectory.' }
  $PythonHome = (Resolve-Path -LiteralPath $PythonHome).Path
  $BuildDirectory = (Resolve-Path -LiteralPath $BuildDirectory).Path
  if (-not (Test-Path -LiteralPath "$PythonHome\python.exe")) { throw 'Missing existing official runner Python runtime.' }
  foreach ($source in @($PythonHome, $BuildDirectory)) {
    $targets = @((Get-Item -LiteralPath $source)) + @(Get-ChildItem -LiteralPath $source -Recurse -Force)
    if ($targets | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw 'Reparse-containing stage source refused.' }
  }
  $approvedHashes = @($ExpectedDriverSha256, $ExpectedHelperSha256, $ExpectedPythonSha256, $ApprovedSourceSha256)
  if (@($approvedHashes | Where-Object { $_ -notmatch '^[0-9a-fA-F]{64}$' }).Count) { throw 'Explicit approved build/runtime/source SHA256 pins are required.' }
  foreach ($pin in @(
    @("$BuildDirectory\examples\python_lab.exe", $ExpectedDriverSha256),
    @("$BuildDirectory\pi-windows-sandbox.exe", $ExpectedHelperSha256),
    @("$PythonHome\python.exe", $ExpectedPythonSha256))) {
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $pin[0]).Hash -ne $pin[1]) { throw "Approved executable hash mismatch: $($pin[0])" }
  }
  New-Item -ItemType Directory -Path $root | Out-Null
  # Replace inherited ACL before putting executables or credentials in this tree.
  $ownerSid = $identity.User.Value
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $acl.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$ownerSid)(A;OICI;FRFX;;;BU)")
  Set-Acl -LiteralPath $root -AclObject $acl
  foreach ($directory in @('trusted','runtime','work')) { New-Item -ItemType Directory -Path "$root\$directory" | Out-Null }
  Copy-Item -LiteralPath "$BuildDirectory\pi-windows-sandbox.exe" -Destination "$root\trusted\pi-windows-sandbox.exe"
  Copy-Item -LiteralPath "$BuildDirectory\examples\python_lab.exe" -Destination $driver
  # No downloading, package installation, pip, or execution of the source Python.
  Copy-Item -Path "$PythonHome\*" -Destination "$root\runtime" -Recurse -Force
  foreach ($pin in @(
    @($driver, $ExpectedDriverSha256),
    @("$root\trusted\pi-windows-sandbox.exe", $ExpectedHelperSha256),
    @("$root\runtime\python.exe", $ExpectedPythonSha256))) {
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $pin[0]).Hash -ne $pin[1]) { throw "Staged executable hash mismatch: $($pin[0])" }
  }
  # Scope all reset/owner changes strictly to the new synthetic tree.
  Invoke-Icacls -Arguments @("$root\trusted", '/reset', '/T', '/Q')
  Invoke-Icacls -Arguments @("$root\runtime", '/reset', '/T', '/Q')
  Invoke-Icacls -Arguments @("$root\work", '/reset', '/T', '/Q')
  Invoke-Icacls -Arguments @($root, '/setowner', '*S-1-5-32-544', '/T', '/Q')
  [ordered]@{ scope='LAB_ONLY'; machine=$env:COMPUTERNAME; runnerOs=$env:RUNNER_OS; ownerSid=$ownerSid;
    osCaption=$os.Caption; osBuild=$os.BuildNumber; imageOs=$env:ImageOS; sourceManifestSha256=$ApprovedSourceSha256; pythonSourcePath=$PythonHome; pythonFileVersion=(Get-Item -LiteralPath "$PythonHome\python.exe").VersionInfo.FileVersion; driverSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $driver).Hash;
    helperSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath "$root\trusted\pi-windows-sandbox.exe").Hash;
    pythonSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath "$root\runtime\python.exe").Hash;
    nativeValidated=$false } | ConvertTo-Json | Set-Content -LiteralPath "$root\trusted\stage-evidence.json" -Encoding UTF8
  Write-Output 'LAB_STAGED_ONLY: no account or sandbox Python process created.'
  exit 0
}
if (-not (Test-Path -LiteralPath $driver)) { throw 'Stage must complete first.' }
& $driver ($Phase.ToLowerInvariant())
if ($LASTEXITCODE -ne 0) { throw "Lab $Phase failed ($LASTEXITCODE). Retain evidence and dispose VM; never run Python outside broker as a substitute." }
