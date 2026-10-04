# Mocked selector regression, NOT Windows sandbox execution or filesystem testing.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. "$PSScriptRoot/../../scripts/windows_lab_stage_sources.ps1"
$script:nodes = @{}
$script:children = @{}
$script:enumerated = [Collections.Generic.List[string]]::new()
function Add-Node([string]$Path, [bool]$Directory, [bool]$Reparse=$false, [string]$LinkType='Junction') {
  $attributes = if ($Directory) { [IO.FileAttributes]::Directory } else { [IO.FileAttributes]::Normal }
  if ($Reparse) { $attributes = $attributes -bor [IO.FileAttributes]::ReparsePoint }
  $script:nodes[$Path] = [pscustomobject]@{ FullName=$Path; PSIsContainer=$Directory; Attributes=$attributes; LinkType=$(if ($Reparse) { $LinkType } else { $null }) }
}
# Shadow filesystem reads: the test never creates or traverses an actual link.
function Get-Item { param([string]$LiteralPath,[switch]$Force)
  if (-not $script:nodes.ContainsKey($LiteralPath)) { throw "Unexpected mocked read: $LiteralPath" }
  $script:nodes[$LiteralPath]
}
function Get-ChildItem { param([string]$LiteralPath,[switch]$Force)
  $script:enumerated.Add($LiteralPath)
  if ($script:children.ContainsKey($LiteralPath)) { foreach ($path in $script:children[$LiteralPath]) { $script:nodes[$path] } }
}
foreach ($dir in @('C:\','C:\Lab','C:\Lab\python','C:\Lab\python\Lib','C:\Lab\build','C:\Lab\build\examples')) { Add-Node $dir $true }
foreach ($file in @('C:\Lab\python\python.exe','C:\Lab\python\Lib\pathlib.py','C:\Lab\build\pi-windows-sandbox.exe','C:\Lab\build\examples\python_lab.exe')) { Add-Node $file $false }
Add-Node 'C:\Lab\build\irrelevant-junction' $true $true
$script:children['C:\Lab\python'] = @('C:\Lab\python\python.exe','C:\Lab\python\Lib')
$script:children['C:\Lab\python\Lib'] = @('C:\Lab\python\Lib\pathlib.py')
$script:children['C:\Lab\build'] = @('C:\Lab\build\irrelevant-junction')
$selection = Get-LabStageSources -PythonHome 'C:\Lab\python' -BuildDirectory 'C:\Lab\build'
if ($selection.runtimeEntries.Count -ne 3) { throw 'Runtime selection incomplete.' }
if ($script:enumerated.Contains('C:\Lab\build')) { throw 'Uncopied build tree was enumerated.' }
function Assert-Rejected([string]$ExpectedPath, [string]$ExpectedRole, [string]$ExpectedLinkType='Junction') {
  $caught = $null
  try { $null = Get-LabStageSources -PythonHome 'C:\Lab\python' -BuildDirectory 'C:\Lab\build' }
  catch { $caught = $_.Exception.Message }
  if (-not $caught -or -not $caught.StartsWith('Reparse-containing stage source refused: ')) { throw 'Expected a specific reparse refusal.' }
  $detail = $caught.Substring('Reparse-containing stage source refused: '.Length) | ConvertFrom-Json
  if ($detail.path -ne $ExpectedPath -or $detail.sourceRole -ne $ExpectedRole -or $detail.linkType -ne $ExpectedLinkType) { throw 'Missing or inaccurate refusal diagnostic.' }
}
# The exact observed root alias is unused and its target must never be accessed.
Add-Node 'C:\Lab\python\python3.exe' $false $true 'SymbolicLink'
$script:nodes['C:\Lab\python\python3.exe'] | Add-Member -MemberType ScriptProperty -Name Target -Value { throw 'Alias target must not be read.' }
$script:children['C:\Lab\python'] += 'C:\Lab\python\python3.exe'
$selection = Get-LabStageSources -PythonHome 'C:\Lab\python' -BuildDirectory 'C:\Lab\build'
if ($selection.runtimeEntries.Count -ne 3 -or $selection.skippedRuntimeEntries.Count -ne 1) { throw 'Only the unused root alias may be excluded.' }
if ($selection.skippedRuntimeEntries[0].relative -ne 'python3.exe') { throw 'Wrong exclusion recorded.' }
if ($script:enumerated.Contains('C:\Lab\python\python3.exe')) { throw 'Alias was traversed.' }
Add-Node 'C:\Lab\python\python.exe' $false $true 'SymbolicLink'
Assert-Rejected 'C:\Lab\python\python.exe' 'python-runtime' 'SymbolicLink'
Add-Node 'C:\Lab\python\python.exe' $false
Add-Node 'C:\Lab\python\Lib\python3.exe' $false $true 'SymbolicLink'
$script:children['C:\Lab\python\Lib'] += 'C:\Lab\python\Lib\python3.exe'
Assert-Rejected 'C:\Lab\python\Lib\python3.exe' 'python-runtime' 'SymbolicLink'
$script:children['C:\Lab\python\Lib'] = @('C:\Lab\python\Lib\pathlib.py')
foreach ($reparse in @($false, $true)) {
  Add-Node 'C:\Lab\python\python3.exe' $true $reparse 'SymbolicLink'
  $message = $null
  try { $null = Get-LabStageSources -PythonHome 'C:\Lab\python' -BuildDirectory 'C:\Lab\build' }
  catch { $message = $_.Exception.Message }
  if (-not $message -or -not $message.StartsWith('Unused root alias must not be a directory:')) { throw 'Root alias directory masquerade was not refused.' }
}
Add-Node 'C:\Lab\python\python3.exe' $false $true 'Junction'
Assert-Rejected 'C:\Lab\python\python3.exe' 'python-runtime'
Add-Node 'C:\Lab\python\python3.exe' $false $true 'SymbolicLink'
$script:enumerated.Clear()
Add-Node 'C:\Lab\python\Lib' $true $true
Assert-Rejected 'C:\Lab\python\Lib' 'python-runtime'
if ($script:enumerated.Contains('C:\Lab\python\Lib')) { throw 'Reparse directory was traversed before refusal.' }
Add-Node 'C:\Lab\python\Lib' $true
Add-Node 'C:\Lab\build\pi-windows-sandbox.exe' $false $true
Assert-Rejected 'C:\Lab\build\pi-windows-sandbox.exe' 'helper-executable'
Add-Node 'C:\Lab\build\pi-windows-sandbox.exe' $false
Add-Node 'C:\Lab\build\examples' $true $true
Assert-Rejected 'C:\Lab\build\examples' 'driver-executable'
Write-Output 'MOCK_SELECTOR_PASS: exact unused root alias excluded without target access; required interpreter, nested alias, directory masquerade and unknown links rejected; copied input selection and runtime/helper/ancestor refusal. No native sandbox execution.'
