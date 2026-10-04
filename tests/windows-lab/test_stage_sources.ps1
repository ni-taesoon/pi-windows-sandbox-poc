# Mocked selector regression, NOT Windows sandbox execution or filesystem testing.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. "$PSScriptRoot/../../scripts/windows_lab_stage_sources.ps1"
$script:nodes = @{}
$script:children = @{}
$script:enumerated = [Collections.Generic.List[string]]::new()
function Add-Node([string]$Path, [bool]$Directory, [bool]$Reparse=$false) {
  $attributes = if ($Directory) { [IO.FileAttributes]::Directory } else { [IO.FileAttributes]::Normal }
  if ($Reparse) { $attributes = $attributes -bor [IO.FileAttributes]::ReparsePoint }
  $script:nodes[$Path] = [pscustomobject]@{ FullName=$Path; PSIsContainer=$Directory; Attributes=$attributes; LinkType=$(if ($Reparse) { 'Junction' } else { $null }) }
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
function Assert-Rejected([string]$ExpectedPath, [string]$ExpectedRole) {
  $caught = $null
  try { $null = Get-LabStageSources -PythonHome 'C:\Lab\python' -BuildDirectory 'C:\Lab\build' }
  catch { $caught = $_.Exception.Message }
  if (-not $caught -or -not $caught.StartsWith('Reparse-containing stage source refused: ')) { throw 'Expected a specific reparse refusal.' }
  $detail = $caught.Substring('Reparse-containing stage source refused: '.Length) | ConvertFrom-Json
  if ($detail.path -ne $ExpectedPath -or $detail.sourceRole -ne $ExpectedRole -or $detail.linkType -ne 'Junction') { throw 'Missing or inaccurate refusal diagnostic.' }
}
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
Write-Output 'MOCK_SELECTOR_PASS: copied input selection, irrelevant build link ignored, runtime/helper/ancestor link refusal, exact diagnostics. No native sandbox execution.'
