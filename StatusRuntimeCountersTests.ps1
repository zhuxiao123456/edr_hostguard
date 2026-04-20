param(
    [string]$HostGuardPath = '',
    [int]$RepeatCount = 4,
    [int]$PauseMs = 200,
    [switch]$SkipCounterDelta
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Resolve-HostGuardPath {
    param([string]$PreferredPath)

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
        if (-not (Test-Path $PreferredPath)) {
            throw "HostGuard.exe not found: $PreferredPath"
        }

        return (Resolve-Path $PreferredPath).ProviderPath
    }

    $candidates = @(
        (Join-Path $PSScriptRoot 'HostGuard.exe'),
        'C:\ransomware\HostGuard.exe',
        'C:\ProgramData\HostGuard\HostGuard.exe'
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).ProviderPath
        }
    }

    throw 'Unable to locate HostGuard.exe. Pass -HostGuardPath explicitly.'
}

function Invoke-StatusJson {
    param([string]$ResolvedHostGuardPath)

    $output = & $ResolvedHostGuardPath status --json 2>&1
    $exitCode = $LASTEXITCODE
    $text = (($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine).Trim()

    if ($exitCode -ne 0) {
        throw "HostGuard status --json failed with exit code $exitCode. Output:`n$text"
    }

    if ([string]::IsNullOrWhiteSpace($text)) {
        throw 'HostGuard status --json returned empty output.'
    }

    try {
        return ($text | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw "HostGuard status --json did not return valid JSON. Output:`n$text"
    }
}

function Get-JsonPropertyValue {
    param(
        [object]$Object,
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        throw "JSON object is null while reading property '$PropertyName'."
    }

    $property = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        throw "Missing required JSON property: $PropertyName"
    }

    return $property.Value
}

function Get-RequiredUInt64 {
    param(
        [object]$Object,
        [string]$PropertyName
    )

    $value = Get-JsonPropertyValue -Object $Object -PropertyName $PropertyName
    try {
        return [UInt64]$value
    }
    catch {
        throw "Property '$PropertyName' is not a valid unsigned integer: $value"
    }
}

function Write-CounterSnapshot {
    param(
        [string]$Label,
        [object]$DriverStatus
    )

    [pscustomobject]@{
        Label = $Label
        ProtectionMode = [string](Get-JsonPropertyValue -Object $DriverStatus -PropertyName 'protection_mode')
        PolicyEpoch = Get-RequiredUInt64 -Object $DriverStatus -PropertyName 'policy_epoch'
        Requests = Get-RequiredUInt64 -Object $DriverStatus -PropertyName 'process_verdict_request_count'
        FastPathHits = Get-RequiredUInt64 -Object $DriverStatus -PropertyName 'fast_path_hit_count'
        CacheHits = Get-RequiredUInt64 -Object $DriverStatus -PropertyName 'cache_hit_count'
        CacheMisses = Get-RequiredUInt64 -Object $DriverStatus -PropertyName 'cache_miss_count'
        CacheFlushes = Get-RequiredUInt64 -Object $DriverStatus -PropertyName 'cache_flush_count'
        SlowPath = Get-RequiredUInt64 -Object $DriverStatus -PropertyName 'slow_path_count'
        FileProtectionBlocks = Get-RequiredUInt64 -Object $DriverStatus -PropertyName 'file_protection_block_count'
        FileProtectionCreateBlocks = Get-RequiredUInt64 -Object $DriverStatus -PropertyName 'file_protection_create_block_count'
        FileProtectionSetInfoBlocks = Get-RequiredUInt64 -Object $DriverStatus -PropertyName 'file_protection_set_information_block_count'
        LastFileProtectionInfoClass = [string](Get-JsonPropertyValue -Object $DriverStatus -PropertyName 'last_file_protection_info_class')
    } | Format-Table -AutoSize
}

$resolvedHostGuardPath = Resolve-HostGuardPath -PreferredPath $HostGuardPath
Write-Step "Using HostGuard binary: $resolvedHostGuardPath"

$statusEnvelope = Invoke-StatusJson -ResolvedHostGuardPath $resolvedHostGuardPath
$driverConnected = [bool](Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'driver_connected')
if (-not $driverConnected) {
    $driverErrorCode = 0
    try {
        $driverErrorCode = [int](Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'driver_error_code')
    }
    catch {
        $driverErrorCode = 0
    }

    throw "Driver is not connected. Start HostGuard foreground/service first. driver_error_code=$driverErrorCode"
}

$driverStatus = Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'driver_status'

$requiredDriverStatusProperties = @(
    'abi_version',
    'policy_epoch',
    'protection_mode',
    'process_callback_registered',
    'process_port_connected',
    'fast_path_hit_count',
    'cache_hit_count',
    'cache_miss_count',
    'cache_flush_count',
    'slow_path_count',
    'process_verdict_request_count',
    'file_protection_block_count',
    'file_protection_create_block_count',
    'file_protection_set_information_block_count',
    'last_file_protection_info_class'
)

foreach ($propertyName in $requiredDriverStatusProperties) {
    [void](Get-JsonPropertyValue -Object $driverStatus -PropertyName $propertyName)
}

Write-Host ''
Write-Step 'Baseline runtime counters:'
Write-CounterSnapshot -Label 'baseline' -DriverStatus $driverStatus

$protectionMode = [string](Get-JsonPropertyValue -Object $driverStatus -PropertyName 'protection_mode')
if ($SkipCounterDelta -or $protectionMode -eq 'monitor_only') {
    if ($protectionMode -eq 'monitor_only' -and -not $SkipCounterDelta) {
        Write-Step 'Driver is running in monitor_only mode; skipping cache delta validation.'
    }

    Write-Success 'Runtime status field validation completed.'
    return
}

$processCallbackRegistered = [bool](Get-JsonPropertyValue -Object $driverStatus -PropertyName 'process_callback_registered')
$processPortConnected = [bool](Get-JsonPropertyValue -Object $driverStatus -PropertyName 'process_port_connected')
if (-not $processCallbackRegistered -or -not $processPortConnected) {
    throw 'Blocking-mode counter validation requires process callbacks and the user-mode verdict port to be connected.'
}

if ($RepeatCount -lt 3) {
    throw 'RepeatCount must be at least 3 to exercise both slow path and cache hits.'
}

$baselineRequests = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'process_verdict_request_count'
$baselineCacheHits = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'cache_hit_count'
$baselineSlowPath = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'slow_path_count'

$cmdPath = Join-Path $env:SystemRoot 'System32\cmd.exe'
Write-Step "Launching repeated cmd.exe children from the same PowerShell parent ($RepeatCount runs)..."
for ($index = 0; $index -lt $RepeatCount; ++$index) {
    & $cmdPath /c exit 0
    if ($LASTEXITCODE -ne 0) {
        throw "cmd.exe exercise failed at iteration $($index + 1) with exit code $LASTEXITCODE"
    }

    Start-Sleep -Milliseconds $PauseMs
}

$finalEnvelope = Invoke-StatusJson -ResolvedHostGuardPath $resolvedHostGuardPath
if (-not [bool](Get-JsonPropertyValue -Object $finalEnvelope -PropertyName 'driver_connected')) {
    throw 'Driver disconnected while validating runtime counter deltas.'
}

$finalDriverStatus = Get-JsonPropertyValue -Object $finalEnvelope -PropertyName 'driver_status'
$finalRequests = Get-RequiredUInt64 -Object $finalDriverStatus -PropertyName 'process_verdict_request_count'
$finalCacheHits = Get-RequiredUInt64 -Object $finalDriverStatus -PropertyName 'cache_hit_count'
$finalSlowPath = Get-RequiredUInt64 -Object $finalDriverStatus -PropertyName 'slow_path_count'

$requestDelta = [int64]($finalRequests - $baselineRequests)
$cacheHitDelta = [int64]($finalCacheHits - $baselineCacheHits)
$slowPathDelta = [int64]($finalSlowPath - $baselineSlowPath)

Write-Host ''
Write-Step 'Final runtime counters:'
Write-CounterSnapshot -Label 'final' -DriverStatus $finalDriverStatus

if ($requestDelta -lt 1) {
    throw "Expected process_verdict_request_count to increase, but delta=$requestDelta"
}

if ($slowPathDelta -lt 1) {
    throw "Expected slow_path_count to increase, but delta=$slowPathDelta"
}

if ($cacheHitDelta -lt 1) {
    throw "Expected cache_hit_count to increase after repeated launches, but delta=$cacheHitDelta"
}

Write-Host ''
Write-Success "Runtime counter deltas validated. request_delta=$requestDelta cache_hit_delta=$cacheHitDelta slow_path_delta=$slowPathDelta"
