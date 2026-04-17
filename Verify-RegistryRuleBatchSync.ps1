param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sharedHeaderPath = Join-Path $RepoRoot 'Common\PebMonitorShared.h'
$driverUtilsHeaderPath = Join-Path $RepoRoot 'DriverUtils.h'
$driverUtilsSourcePath = Join-Path $RepoRoot 'DriverUtils.cpp'
$hostGuardPath = Join-Path $RepoRoot 'HostGuard.cpp'

foreach ($path in @($sharedHeaderPath, $driverUtilsHeaderPath, $driverUtilsSourcePath, $hostGuardPath)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$sharedHeaderText = Get-Content $sharedHeaderPath -Raw
$driverUtilsHeaderText = Get-Content $driverUtilsHeaderPath -Raw
$driverUtilsSourceText = Get-Content $driverUtilsSourcePath -Raw
$hostGuardText = Get-Content $hostGuardPath -Raw

if ($sharedHeaderText -notmatch 'IOCTL_REPLACE_REGISTRY_RULES') {
    throw 'Common\PebMonitorShared.h must define IOCTL_REPLACE_REGISTRY_RULES.'
}

if ($sharedHeaderText -notmatch 'IOCTL_REPLACE_REGISTRY_ALLOW_RULES') {
    throw 'Common\PebMonitorShared.h must define IOCTL_REPLACE_REGISTRY_ALLOW_RULES.'
}

if ($sharedHeaderText -notmatch 'REGISTRY_RULE_BATCH_UPDATE') {
    throw 'Common\PebMonitorShared.h must define REGISTRY_RULE_BATCH_UPDATE.'
}

if ($driverUtilsHeaderText -notmatch 'ReplaceRegistryRules') {
    throw 'DriverUtils.h must declare ReplaceRegistryRules.'
}

if ($driverUtilsHeaderText -notmatch 'ReplaceRegistryAllowRules') {
    throw 'DriverUtils.h must declare ReplaceRegistryAllowRules.'
}

if ($driverUtilsSourceText -notmatch 'IOCTL_REPLACE_REGISTRY_RULES') {
    throw 'DriverUtils.cpp must issue IOCTL_REPLACE_REGISTRY_RULES.'
}

if ($driverUtilsSourceText -notmatch 'IOCTL_REPLACE_REGISTRY_ALLOW_RULES') {
    throw 'DriverUtils.cpp must issue IOCTL_REPLACE_REGISTRY_ALLOW_RULES.'
}

if ($driverUtilsSourceText -notmatch 'REGISTRY_RULE_BATCH_UPDATE') {
    throw 'DriverUtils.cpp must build REGISTRY_RULE_BATCH_UPDATE payloads.'
}

if ($hostGuardText -notmatch 'ReplaceRegistryRules\s*\(\s*hDevice\s*,\s*config\.registryRules') {
    throw 'HostGuard.cpp must sync block rules through ReplaceRegistryRules.'
}

if ($hostGuardText -notmatch 'ReplaceRegistryAllowRules\s*\(\s*hDevice\s*,\s*config\.registryAllowRules') {
    throw 'HostGuard.cpp must sync allow rules through ReplaceRegistryAllowRules.'
}

Write-Host '[+] HostGuard registry batch-sync checks passed.'
