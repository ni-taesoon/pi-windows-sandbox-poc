# Compile a fixed diagnostic executable with the installed official MSVC toolchain.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or @($installation).Count -ne 1) { throw 'Installed MSVC environment unavailable.' }
$devcmd = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
$source = Join-Path $PWD 'native\windows-loader-probe\loader_probe.c'
$build = Join-Path $PWD 'native\windows-sandbox\target\x86_64-pc-windows-msvc\debug'
foreach ($value in @($devcmd,$source,$build)) { if ($value -match '["\r\n&|<>^%!]') { throw 'Unsupported build path.' } }
$command = "call `"$devcmd`" -arch=x64 -host_arch=x64 >nul && cl.exe /nologo /Bv /TC /std:c11 /Od /GS /Zl /Brepro /Fo`"$build\loader_probe.obj`" /Fe`"$build\loader_probe.exe`" `"$source`" /link /NODEFAULTLIB /ENTRY:lab_probe_entry /SUBSYSTEM:CONSOLE /MACHINE:X64 /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /Brepro kernel32.lib"
& "$env:SystemRoot\System32\cmd.exe" /d /s /c $command
if ($LASTEXITCODE -ne 0) { throw 'Fixed loader probe MSVC build failed.' }
python scripts/inspect_windows_loader.py verify-probe
if ($LASTEXITCODE -ne 0) { throw 'Probe import allowlist failed; staging prohibited.' }
