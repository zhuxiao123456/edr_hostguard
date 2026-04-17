param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$runnerPath = Join-Path $RepoRoot 'Run-TestBundleRegression.ps1'
$scaleTestPath = Join-Path $RepoRoot 'RegistryRuleScaleTests.ps1'

if (-not (Test-Path $runnerPath)) {
    throw "Required file not found: $runnerPath"
}

if (-not (Test-Path $scaleTestPath)) {
    throw "Required file not found: $scaleTestPath"
}

$runnerText = Get-Content $runnerPath -Raw
$scaleTestText = Get-Content $scaleTestPath -Raw

if ($runnerText -notmatch 'SkipRegistryRuleScale') {
    throw 'Run-TestBundleRegression.ps1 must expose -SkipRegistryRuleScale.'
}

if ($runnerText -notmatch 'RegistryRuleScaleTests\.ps1') {
    throw 'Run-TestBundleRegression.ps1 must execute RegistryRuleScaleTests.ps1.'
}

if ($scaleTestText -notmatch 'registry_rule_count') {
    throw 'RegistryRuleScaleTests.ps1 must validate registry_rule_count.'
}

if ($scaleTestText -notmatch 'registry_allow_rule_count') {
    throw 'RegistryRuleScaleTests.ps1 must validate registry_allow_rule_count.'
}

if ($scaleTestText -notmatch 'registry_rule_classes') {
    throw 'RegistryRuleScaleTests.ps1 must validate registry_rule_classes.'
}

if ($scaleTestText -notmatch 'registry_allow_rule_classes') {
    throw 'RegistryRuleScaleTests.ps1 must validate registry_allow_rule_classes.'
}

if ($scaleTestText -notmatch 'policy_epoch') {
    throw 'RegistryRuleScaleTests.ps1 must validate policy_epoch transitions.'
}

Write-Host '[+] HostGuard registry scale regression checks passed.'
