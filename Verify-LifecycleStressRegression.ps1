param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$runnerPath = Join-Path $RepoRoot 'Run-TestBundleRegression.ps1'
$testPath = Join-Path $RepoRoot 'LifecycleStressTests.ps1'

foreach ($path in @($runnerPath, $testPath)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$runnerText = Get-Content $runnerPath -Raw
$testText = Get-Content $testPath -Raw

if ($runnerText -notmatch 'SkipLifecycleStress') {
    throw 'Run-TestBundleRegression.ps1 must expose -SkipLifecycleStress.'
}

if ($runnerText -notmatch 'LifecycleStressTests\.ps1') {
    throw 'Run-TestBundleRegression.ps1 must execute LifecycleStressTests.ps1.'
}

if ($testText -notmatch 'status --json') {
    throw 'LifecycleStressTests.ps1 must validate lifecycle state through status --json.'
}

if ($testText -notmatch 'hostguard_service_exists') {
    throw 'LifecycleStressTests.ps1 must validate hostguard_service_exists.'
}

if ($testText -notmatch 'driver_service_exists') {
    throw 'LifecycleStressTests.ps1 must validate driver_service_exists.'
}

if ($testText -notmatch 'driver_connected') {
    throw 'LifecycleStressTests.ps1 must validate driver_connected.'
}

if ($testText -notmatch 'install') {
    throw 'LifecycleStressTests.ps1 must exercise HostGuard install.'
}

if ($testText -notmatch 'start') {
    throw 'LifecycleStressTests.ps1 must exercise HostGuard start.'
}

if ($testText -notmatch 'stop') {
    throw 'LifecycleStressTests.ps1 must exercise HostGuard stop.'
}

if ($testText -notmatch 'uninstall') {
    throw 'LifecycleStressTests.ps1 must exercise HostGuard uninstall.'
}

Write-Host '[+] HostGuard lifecycle-stress regression checks passed.'
