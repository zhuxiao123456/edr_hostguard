param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$runnerPath = Join-Path $RepoRoot 'Run-TestBundleRegression.ps1'
$testPath = Join-Path $RepoRoot 'RegistryBatchSyncTests.ps1'

foreach ($path in @($runnerPath, $testPath)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$runnerText = Get-Content $runnerPath -Raw
$testText = Get-Content $testPath -Raw

if ($runnerText -notmatch 'SkipRegistryBatchSync') {
    throw 'Run-TestBundleRegression.ps1 must expose -SkipRegistryBatchSync.'
}

if ($runnerText -notmatch 'RegistryBatchSyncTests\.ps1') {
    throw 'Run-TestBundleRegression.ps1 must execute RegistryBatchSyncTests.ps1.'
}

if ($testText -notmatch 'policy_epoch') {
    throw 'RegistryBatchSyncTests.ps1 must validate policy_epoch changes.'
}

if ($testText -notmatch 'registry_rule_count') {
    throw 'RegistryBatchSyncTests.ps1 must validate registry_rule_count.'
}

if ($testText -notmatch 'registry_allow_rule_count') {
    throw 'RegistryBatchSyncTests.ps1 must validate registry_allow_rule_count.'
}

Write-Host '[+] HostGuard registry batch-sync regression checks passed.'
