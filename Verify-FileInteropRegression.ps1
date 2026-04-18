param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredFiles = @(
    (Join-Path $RepoRoot 'FileInteropTests.ps1'),
    (Join-Path $RepoRoot 'Run-TestBundleRegression.ps1')
)

foreach ($path in $requiredFiles) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$fileInteropText = Get-Content (Join-Path $RepoRoot 'FileInteropTests.ps1') -Raw
$bundleRunnerText = Get-Content (Join-Path $RepoRoot 'Run-TestBundleRegression.ps1') -Raw

if ($fileInteropText -notmatch 'Copy-Item') {
    throw 'FileInteropTests.ps1 must still validate protected-driver overwrite attempts.'
}

if ($fileInteropText -notmatch 'Rename-Item') {
    throw 'FileInteropTests.ps1 must validate protected-driver rename attempts.'
}

if ($fileInteropText -notmatch 'Remove-Item') {
    throw 'FileInteropTests.ps1 must validate protected-driver delete attempts.'
}

if ($bundleRunnerText -notmatch 'SkipFileInterop') {
    throw 'Run-TestBundleRegression.ps1 must expose a SkipFileInterop switch.'
}

if ($bundleRunnerText -notmatch 'FileInteropTests\.ps1') {
    throw 'Run-TestBundleRegression.ps1 must invoke FileInteropTests.ps1 as part of bundle regression.'
}

Write-Host '[+] File interop regression checks passed.'
