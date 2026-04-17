param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$runnerPath = Join-Path $RepoRoot 'Run-TestBundleRegression.ps1'
$testPath = Join-Path $RepoRoot 'RegistryRollbackTests.ps1'

foreach ($path in @($runnerPath, $testPath)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$runnerText = Get-Content $runnerPath -Raw
$testText = Get-Content $testPath -Raw

if ($runnerText -notmatch 'SkipRegistryRollback') {
    throw 'Run-TestBundleRegression.ps1 must expose -SkipRegistryRollback.'
}

if ($runnerText -notmatch 'RegistryRollbackTests\.ps1') {
    throw 'Run-TestBundleRegression.ps1 must execute RegistryRollbackTests.ps1.'
}

if ($testText -notmatch 'config_reload_rollback') {
    throw 'RegistryRollbackTests.ps1 must validate config_reload_rollback events.'
}

if ($testText -notmatch 'rollback_retained') {
    throw 'RegistryRollbackTests.ps1 must validate rollback_retained results.'
}

if ($testText -notmatch 'policy_epoch') {
    throw 'RegistryRollbackTests.ps1 must validate policy_epoch stability across rollback.'
}

Write-Host '[+] HostGuard registry rollback regression checks passed.'
