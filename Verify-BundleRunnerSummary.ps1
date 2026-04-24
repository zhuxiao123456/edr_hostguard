param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$runnerPath = Join-Path $RepoRoot 'Run-TestBundleRegression.ps1'
if (-not (Test-Path $runnerPath)) {
    throw "Required file not found: $runnerPath"
}

$runnerText = Get-Content $runnerPath -Raw

foreach ($requiredToken in @(
    'Initialize-RegressionResultMap',
    'Set-RegressionResult',
    'Write-RegressionSummary',
    'Write-RegressionSummaryFiles',
    'bundle-regression-summary.json',
    'bundle-regression-summary.txt',
    'Regression summary:',
    '-Status ''PASS''',
    '-Status ''SKIP'''
)) {
    if ($runnerText -notmatch [regex]::Escape($requiredToken)) {
        throw "Run-TestBundleRegression.ps1 must include $requiredToken."
    }
}

foreach ($testName in @(
    'ProcessObservedTests.ps1',
    'FileInteropTests.ps1',
    'FileProtectionRuntimeCountersTests.ps1',
    'StatusRuntimeCountersTests.ps1',
    'RegistryBatchSyncTests.ps1',
    'RegistryRuleScaleTests.ps1',
    'RegistryRuleOrderTests.ps1',
    'RegistryRollbackTests.ps1',
    'RegistryInteropTests.ps1',
    'LifecycleStressTests.ps1'
)) {
    if ($runnerText -notmatch [regex]::Escape($testName)) {
        throw "Run-TestBundleRegression.ps1 must keep $testName in the regression summary scope."
    }
}

Write-Host '[+] Bundle runner summary checks passed.'
