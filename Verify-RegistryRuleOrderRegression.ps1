param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$runnerPath = Join-Path $RepoRoot 'Run-TestBundleRegression.ps1'
$testPath = Join-Path $RepoRoot 'RegistryRuleOrderTests.ps1'

foreach ($path in @($runnerPath, $testPath)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$runnerText = Get-Content $runnerPath -Raw
$testText = Get-Content $testPath -Raw

if ($runnerText -notmatch 'SkipRegistryRuleOrder') {
    throw 'Run-TestBundleRegression.ps1 must expose -SkipRegistryRuleOrder.'
}

if ($runnerText -notmatch 'RegistryRuleOrderTests\.ps1') {
    throw 'Run-TestBundleRegression.ps1 must execute RegistryRuleOrderTests.ps1.'
}

foreach ($expectedRuleId in @(
    'order-a-prefix',
    'order-b-suffix',
    'order-c-contains'
)) {
    if ($testText -notmatch [Regex]::Escape($expectedRuleId)) {
        throw "RegistryRuleOrderTests.ps1 must validate $expectedRuleId."
    }
}

if ($testText -notmatch 'blocked_registry_operation') {
    throw 'RegistryRuleOrderTests.ps1 must validate blocked_registry_operation events.'
}

if ($testText -notmatch 'rule_id') {
    throw 'RegistryRuleOrderTests.ps1 must validate emitted rule_id values.'
}

if ($testText -notmatch 'registry_rule_classes') {
    throw 'RegistryRuleOrderTests.ps1 must validate registry_rule_classes after hot reload.'
}

if ($testText -notmatch 'policy_epoch') {
    throw 'RegistryRuleOrderTests.ps1 must validate policy_epoch transitions.'
}

Write-Host '[+] HostGuard registry rule order regression checks passed.'
