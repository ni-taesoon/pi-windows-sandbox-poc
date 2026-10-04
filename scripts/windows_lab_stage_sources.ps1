# Pure read-only selection helpers for the fixed disposable lab stager.
# No directory is traversed before its own reparse attribute is inspected.
function Assert-LabSourceItem {
  param([Parameter(Mandatory=$true)]$Item, [Parameter(Mandatory=$true)][string]$Role)
  if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    $detail = [ordered]@{
      sourceRole = $Role
      path = $Item.FullName
      linkType = $(if ($Item.PSObject.Properties['LinkType']) { $Item.LinkType } else { 'unavailable' })
      attributes = $Item.Attributes.ToString()
    } | ConvertTo-Json -Compress
    # Deliberately do not resolve/read the link target or expose file contents.
    throw "Reparse-containing stage source refused: $detail"
  }
}
function Assert-LabSourceAncestors {
  param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Role)
  $absolute = [IO.Path]::GetFullPath($Path)
  $ancestors = [Collections.Generic.Stack[string]]::new()
  $current = $absolute
  while ($current) {
    $ancestors.Push($current)
    $parent = [IO.Path]::GetDirectoryName($current)
    if ($parent -eq $current) { break }
    $current = $parent
  }
  while ($ancestors.Count) {
    $candidate = $ancestors.Pop()
    $item = Get-Item -LiteralPath $candidate -Force
    Assert-LabSourceItem -Item $item -Role $Role
    if ($candidate -ne $absolute -and -not $item.PSIsContainer) { throw "Non-directory source ancestor: $candidate" }
  }
}
function Get-LabStageSources {
  param([Parameter(Mandatory=$true)][string]$PythonHome, [Parameter(Mandatory=$true)][string]$BuildDirectory)
  # GetFullPath normalizes lexical spelling without resolving junction targets.
  $runtime = [IO.Path]::GetFullPath($PythonHome).TrimEnd('\')
  $build = [IO.Path]::GetFullPath($BuildDirectory).TrimEnd('\')
  $helper = Join-Path $build 'pi-windows-sandbox.exe'
  $driver = Join-Path $build 'examples\python_lab.exe'
  foreach ($sourceSpec in @(@($helper, 'helper-executable'), @($driver, 'driver-executable'))) {
    Assert-LabSourceAncestors -Path $sourceSpec[0] -Role $sourceSpec[1]
    if ((Get-Item -LiteralPath $sourceSpec[0] -Force).PSIsContainer) { throw "Executable source is a directory: $($sourceSpec[0])" }
  }
  Assert-LabSourceAncestors -Path $runtime -Role 'python-runtime'
  if (-not (Get-Item -LiteralPath $runtime -Force).PSIsContainer) { throw 'Python runtime source is not a directory.' }
  $pending = [Collections.Generic.Queue[string]]::new()
  $pending.Enqueue($runtime)
  $entries = [Collections.Generic.List[object]]::new()
  while ($pending.Count) {
    $source = $pending.Dequeue()
    $item = Get-Item -LiteralPath $source -Force
    Assert-LabSourceItem -Item $item -Role 'python-runtime'
    if ($source -ne $runtime) {
      $relative = [IO.Path]::GetRelativePath($runtime, $item.FullName)
      if ([IO.Path]::IsPathRooted($relative) -or $relative -eq '..' -or $relative.StartsWith('..\')) { throw 'Runtime entry escaped selected root.' }
      $entries.Add([pscustomobject]@{ source=$item.FullName; relative=$relative; isDirectory=[bool]$item.PSIsContainer })
    }
    if ($item.PSIsContainer) {
      # No -Recurse or -FollowSymlink: inspect each child before descending.
      foreach ($child in Get-ChildItem -LiteralPath $source -Force) { $pending.Enqueue($child.FullName) }
    }
  }
  if (-not ($entries | Where-Object { $_.relative -eq 'python.exe' -and -not $_.isDirectory })) { throw 'Missing existing official runner Python runtime.' }
  [pscustomobject]@{ runtimeRoot=$runtime; helper=$helper; driver=$driver; runtimeEntries=$entries.ToArray() }
}
