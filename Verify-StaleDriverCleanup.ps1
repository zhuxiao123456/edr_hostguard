param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$driverUtilsHeaderPath = Join-Path $RepoRoot 'DriverUtils.h'
$driverUtilsSourcePath = Join-Path $RepoRoot 'DriverUtils.cpp'

foreach ($path in @($driverUtilsHeaderPath, $driverUtilsSourcePath)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$driverUtilsHeaderText = Get-Content $driverUtilsHeaderPath -Raw
$driverUtilsSourceText = Get-Content $driverUtilsSourcePath -Raw

if ($driverUtilsHeaderText -notmatch 'EnsureFreshKernelDriverInstall') {
    throw 'DriverUtils.h must declare EnsureFreshKernelDriverInstall.'
}

if ($driverUtilsSourceText -notmatch 'EnsureFreshKernelDriverInstall') {
    throw 'DriverUtils.cpp must implement EnsureFreshKernelDriverInstall.'
}

if ($driverUtilsSourceText -notmatch 'QueryServiceBinaryPath') {
    throw 'DriverUtils.cpp must inspect the existing service binary path before reusing PebMonitor.'
}

if ($driverUtilsSourceText -notmatch 'UninstallKernelDriverViaInf') {
    throw 'DriverUtils.cpp must reuse INF uninstall flow for stale PebMonitor cleanup.'
}

if ($driverUtilsSourceText -notmatch 'DeleteFileW') {
    throw 'DriverUtils.cpp must delete the stale on-disk driver image during forced refresh.'
}

if ($driverUtilsSourceText -notmatch 'Hash mismatch') {
    throw 'DriverUtils.cpp must log when a stale driver hash mismatch triggers cleanup.'
}

if ($driverUtilsSourceText -notmatch 'EnsureFreshKernelDriverInstall\(driverPath, serviceName\)') {
    throw 'LoadKernelDriver must call EnsureFreshKernelDriverInstall before installing/reusing PebMonitor.'
}

Write-Host '[+] Stale driver cleanup checks passed.'
