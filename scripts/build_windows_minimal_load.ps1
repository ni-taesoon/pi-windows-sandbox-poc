# Build only the fixed no-CRT compatibility fixture with the installed MSVC tools.
# This does not inspect DLLs or import tables, run the fixture, or change security.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'Installed official MSVC tools are required.' }
$installation = @(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
if ($LASTEXITCODE -ne 0 -or $installation.Count -ne 1 -or -not $installation[0]) { throw 'Installed MSVC environment unavailable.' }
$devcmd = Join-Path $installation[0] 'Common7\Tools\VsDevCmd.bat'
$source = Join-Path $repo 'native\windows-minimal-load\minimal_load.c'
$build = Join-Path $repo 'native\windows-sandbox\target\x86_64-pc-windows-msvc\debug'
foreach ($value in @($devcmd, $source, $build)) {
  if ($value -match '["\r\n&|<>^%!]') { throw 'Unsupported build path.' }
}
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Fixed minimal-load source is missing.' }
New-Item -ItemType Directory -Path $build -Force | Out-Null
# Keep /GS enabled. The fixed fixture uses no stack buffers, and /Zl plus
# /NODEFAULTLIB admit no implicit CRT. The entrypoint calls only kernel32 APIs.
$command = "call `"$devcmd`" -arch=x64 -host_arch=x64 >nul && cl.exe /nologo /Bv /TC /std:c11 /Od /GS /Zl /Brepro /Fo`"$build\minimal_load.obj`" /Fe`"$build\minimal_load.exe`" `"$source`" /link /NODEFAULTLIB /ENTRY:minimal_load_entry /SUBSYSTEM:CONSOLE /MACHINE:X64 /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /Brepro kernel32.lib"
& "$env:SystemRoot\System32\cmd.exe" /d /s /c $command
if ($LASTEXITCODE -ne 0) { throw 'Fixed minimal-load MSVC build failed.' }
if (-not (Test-Path -LiteralPath "$build\minimal_load.exe" -PathType Leaf)) { throw 'Fixed minimal-load executable was not produced.' }
