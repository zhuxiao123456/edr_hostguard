param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredPaths = @(
    (Join-Path $RepoRoot 'Common\PebMonitorShared.h'),
    (Join-Path $RepoRoot 'HostGuard.cpp'),
    (Join-Path $RepoRoot 'FileInteropTests.ps1')
)

foreach ($path in $requiredPaths) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$sharedHeaderText = Get-Content (Join-Path $RepoRoot 'Common\PebMonitorShared.h') -Raw
$hostGuardText = Get-Content (Join-Path $RepoRoot 'HostGuard.cpp') -Raw
$fileInteropText = Get-Content (Join-Path $RepoRoot 'FileInteropTests.ps1') -Raw

if ($sharedHeaderText -notmatch 'DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION') {
    throw 'Common\PebMonitorShared.h must define DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION.'
}

if ($hostGuardText -notmatch 'blocked_file_operation') {
    throw 'HostGuard.cpp must expose blocked_file_operation as a stable driver event name.'
}

if ($hostGuardText -notmatch 'DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION') {
    throw 'HostGuard.cpp must implement a dedicated blocked-file event branch.'
}

if ($hostGuardText -notmatch 'driver_self_protection') {
    throw 'HostGuard.cpp must preserve driver_self_protection rule identifiers in JSON/log output.'
}

if ($fileInteropText -notmatch 'blocked_file_operation') {
    throw 'FileInteropTests.ps1 must assert blocked_file_operation events.'
}

if ($fileInteropText -notmatch 'driver_self_protection') {
    throw 'FileInteropTests.ps1 must assert the driver_self_protection rule id.'
}

if ($fileInteropText -notmatch 'ConvertFrom-Json') {
    throw 'FileInteropTests.ps1 must parse events.jsonl to verify the blocked-file telemetry.'
}

if ($fileInteropText -notmatch 'HostGuard file self-protection telemetry validated successfully') {
    throw 'FileInteropTests.ps1 must report a clear success message for blocked-file telemetry validation.'
}

Write-Host '[+] Blocked file event handling checks passed.'
