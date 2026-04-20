param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$counterScriptPath = Join-Path $RepoRoot 'FileProtectionRuntimeCountersTests.ps1'
$bundleRunnerPath = Join-Path $RepoRoot 'Run-TestBundleRegression.ps1'

foreach ($path in @($counterScriptPath, $bundleRunnerPath)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$counterScriptText = Get-Content $counterScriptPath -Raw
$bundleRunnerText = Get-Content $bundleRunnerPath -Raw

$requiredStatusFields = @(
    'file_protection_block_count',
    'file_protection_create_block_count',
    'file_protection_set_information_block_count',
    'last_file_protection_info_class'
)

foreach ($field in $requiredStatusFields) {
    if ($counterScriptText -notmatch [regex]::Escape($field)) {
        throw "FileProtectionRuntimeCountersTests.ps1 must validate $field."
    }
}

foreach ($mutation in @('Copy-Item', 'Rename-Item', 'Remove-Item')) {
    if ($counterScriptText -notmatch $mutation) {
        throw "FileProtectionRuntimeCountersTests.ps1 must exercise $mutation protected-driver mutations."
    }
}

foreach ($expectedInfoClass in @('IRP_MJ_CREATE', 'FileRenameInformation', 'FileDispositionInformation')) {
    if ($counterScriptText -notmatch [regex]::Escape($expectedInfoClass)) {
        throw "FileProtectionRuntimeCountersTests.ps1 must assert $expectedInfoClass as a runtime status outcome."
    }
}

if ($counterScriptText -notmatch 'status --json') {
    throw 'FileProtectionRuntimeCountersTests.ps1 must query HostGuard status --json.'
}

if ($bundleRunnerText -notmatch 'SkipFileProtectionCounters') {
    throw 'Run-TestBundleRegression.ps1 must expose -SkipFileProtectionCounters.'
}

if ($bundleRunnerText -notmatch 'FileProtectionRuntimeCountersTests\.ps1') {
    throw 'Run-TestBundleRegression.ps1 must execute FileProtectionRuntimeCountersTests.ps1.'
}

Write-Host '[+] File protection runtime counter regression checks passed.'
