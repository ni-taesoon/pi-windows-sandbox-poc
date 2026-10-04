# Run in an ordinary (non-administrator) Developer PowerShell with CMake and Windows SDK.
$ErrorActionPreference = 'Stop'
cmake -S $PSScriptRoot -B "$PSScriptRoot/build" -A x64
if ($LASTEXITCODE -ne 0) { throw 'Configure failed' }
cmake --build "$PSScriptRoot/build" --config Release
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
& "$PSScriptRoot/build/Release/pi-job-supervisor.exe" --capabilities
if ($LASTEXITCODE -ne 0) { throw 'Capability command failed' }
Write-Output 'Built source only. Native containment integration has NOT been validated.'
