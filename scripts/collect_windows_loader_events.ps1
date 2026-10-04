# Read existing records only. Never enable logs, tracing, providers or privileges.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$window = Get-Content -LiteralPath 'lab-evidence/run-window.json' -Raw | ConvertFrom-Json
$start = [DateTimeOffset]::Parse($window.start)
$end = [DateTimeOffset]::Parse($window.end)
if ($end -lt $start -or ($end - $start).TotalSeconds -gt 120) { throw 'Diagnostic run window exceeds fixed bounds.' }
$records = [Collections.Generic.List[object]]::new()
$errors = [Collections.Generic.List[object]]::new()
foreach ($query in @(
  @{ channel='Application'; provider='Application Error' },
  @{ channel='Application'; provider='Windows Error Reporting' },
  @{ channel='Application'; provider='SideBySide' },
  @{ channel='System'; provider='Application Popup' }
)) {
  try {
    $events = Get-WinEvent -FilterHashtable @{ LogName=$query.channel; ProviderName=$query.provider; StartTime=$start.UtcDateTime; EndTime=$end.UtcDateTime } -MaxEvents 32 -ErrorAction Stop
    foreach ($event in $events) {
      $xml = $event.ToXml()
      if ([Text.Encoding]::UTF8.GetByteCount($xml) -le 16384) { $records.Add(@{channel=$query.channel;xml=$xml}) }
    }
  } catch {
    $errors.Add(@{channel=$query.channel; provider=$query.provider; noMatchingEvents=($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'); hresult=[int]$_.Exception.HResult})
  }
}
# Raw XML stays in memory/stdin. Only the Python sanitizer's whitelist is saved.
@{window=@{start=$start.ToString('o');end=$end.ToString('o')};records=$records.ToArray();queryErrors=$errors.ToArray()} |
  ConvertTo-Json -Compress -Depth 5 |
  python scripts/inspect_windows_loader.py events |
  Set-Content -LiteralPath 'lab-evidence/loader-events.json' -Encoding UTF8
if ($LASTEXITCODE -ne 0) { throw 'Existing-event sanitizer failed; no raw event output is permitted.' }
