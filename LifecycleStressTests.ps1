param(
    [string]$HostGuardPath = '',
    [int]$Iterations = 5,
    [int]$ReadyTimeoutSeconds = 45,
    [int]$PollIntervalMs = 500,
    [int]$PauseMs = 500
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

function Invoke-HostGuardCommand {
    param(
        [string]$ResolvedHostGuardPath,
        [string[]]$Arguments,
        [string]$Description
    )

    Write-Step $Description
    $output = & $ResolvedHostGuardPath @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = (($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine).Trim()

    if ($exitCode -ne 0) {
        if ([string]::IsNullOrWhiteSpace($text)) {
            throw "$Description failed with exit code $exitCode."
        }

        throw "$Description failed with exit code $exitCode. Output:`n$text"
    }

    return $text
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
        throw "HostGuard status --json returned invalid JSON. Output:`n$text"
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

function Get-RequiredString {
    param(
        [object]$Object,
        [string]$PropertyName
    )

    return [string](Get-JsonPropertyValue -Object $Object -PropertyName $PropertyName)
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

function Get-ServicesJson {
    param([object]$StatusEnvelope)

    return Get-JsonPropertyValue -Object $StatusEnvelope -PropertyName 'services'
}

function Test-ReadyState {
    param([object]$StatusEnvelope)

    $services = Get-ServicesJson -StatusEnvelope $StatusEnvelope
    $hostguardExists = [bool](Get-JsonPropertyValue -Object $services -PropertyName 'hostguard_service_exists')
    $hostguardState = Get-RequiredString -Object $services -PropertyName 'hostguard_service_state'
    $driverServiceExists = [bool](Get-JsonPropertyValue -Object $services -PropertyName 'driver_service_exists')
    $driverConnected = [bool](Get-JsonPropertyValue -Object $StatusEnvelope -PropertyName 'driver_connected')
    $rulesLoaded = [bool](Get-JsonPropertyValue -Object $StatusEnvelope -PropertyName 'rules_loaded')

    if (-not $hostguardExists -or
        $hostguardState -ne 'running' -or
        -not $driverServiceExists -or
        -not $driverConnected -or
        -not $rulesLoaded) {
        return $false
    }

    $driverStatus = Get-JsonPropertyValue -Object $StatusEnvelope -PropertyName 'driver_status'
    if ($null -eq $driverStatus) {
        return $false
    }

    $protectionMode = Get-RequiredString -Object $driverStatus -PropertyName 'protection_mode'
    if ($protectionMode -eq 'monitor_only') {
        return $true
    }

    $processCallbackRegistered = [bool](Get-JsonPropertyValue -Object $driverStatus -PropertyName 'process_callback_registered')
    $processPortConnected = [bool](Get-JsonPropertyValue -Object $driverStatus -PropertyName 'process_port_connected')
    return $processCallbackRegistered -and $processPortConnected
}

function Test-StoppedState {
    param([object]$StatusEnvelope)

    $services = Get-ServicesJson -StatusEnvelope $StatusEnvelope
    $hostguardExists = [bool](Get-JsonPropertyValue -Object $services -PropertyName 'hostguard_service_exists')
    $hostguardState = Get-RequiredString -Object $services -PropertyName 'hostguard_service_state'
    $driverConnected = [bool](Get-JsonPropertyValue -Object $StatusEnvelope -PropertyName 'driver_connected')
    $driverServiceExists = [bool](Get-JsonPropertyValue -Object $services -PropertyName 'driver_service_exists')

    return $hostguardExists -and $hostguardState -eq 'stopped' -and -not $driverConnected -and -not $driverServiceExists
}

function Test-UninstalledState {
    param([object]$StatusEnvelope)

    $services = Get-ServicesJson -StatusEnvelope $StatusEnvelope
    $hostguardExists = [bool](Get-JsonPropertyValue -Object $services -PropertyName 'hostguard_service_exists')
    $driverServiceExists = [bool](Get-JsonPropertyValue -Object $services -PropertyName 'driver_service_exists')
    $driverConnected = [bool](Get-JsonPropertyValue -Object $StatusEnvelope -PropertyName 'driver_connected')
    return (-not $hostguardExists) -and (-not $driverServiceExists) -and (-not $driverConnected)
}

function Test-InstalledStoppedState {
    param([object]$StatusEnvelope)

    $services = Get-ServicesJson -StatusEnvelope $StatusEnvelope
    $hostguardExists = [bool](Get-JsonPropertyValue -Object $services -PropertyName 'hostguard_service_exists')
    $hostguardState = Get-RequiredString -Object $services -PropertyName 'hostguard_service_state'
    return $hostguardExists -and $hostguardState -eq 'stopped'
}

function Wait-ForStatusCondition {
    param(
        [string]$ResolvedHostGuardPath,
        [scriptblock]$Condition,
        [string]$Description,
        [int]$TimeoutSeconds,
        [int]$PollIntervalMs
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $statusEnvelope = Invoke-StatusJson -ResolvedHostGuardPath $ResolvedHostGuardPath
        if (& $Condition $statusEnvelope) {
            return $statusEnvelope
        }

        Start-Sleep -Milliseconds $PollIntervalMs
    }

    throw "Timed out waiting for $Description."
}

if ($Iterations -lt 1) {
    throw 'Iterations must be at least 1.'
}

if ($PauseMs -lt 0) {
    throw 'PauseMs cannot be negative.'
}

$resolvedHostGuardPath = Resolve-HostGuardPath -PreferredPath $HostGuardPath
Write-Step "Using HostGuard binary: $resolvedHostGuardPath"

$baselineReady = Wait-ForStatusCondition `
    -ResolvedHostGuardPath $resolvedHostGuardPath `
    -Condition { param($statusEnvelope) Test-ReadyState -StatusEnvelope $statusEnvelope } `
    -Description 'HostGuard ready state before lifecycle stress' `
    -TimeoutSeconds $ReadyTimeoutSeconds `
    -PollIntervalMs $PollIntervalMs

$baselineDriverStatus = Get-JsonPropertyValue -Object $baselineReady -PropertyName 'driver_status'
$baselinePolicyEpoch = Get-RequiredUInt64 -Object $baselineDriverStatus -PropertyName 'policy_epoch'
$results = New-Object System.Collections.Generic.List[object]

for ($iteration = 1; $iteration -le $Iterations; ++$iteration) {
    Write-Host ''
    Write-Step "Lifecycle iteration $iteration/$Iterations"

    Invoke-HostGuardCommand -ResolvedHostGuardPath $resolvedHostGuardPath -Arguments @('stop') -Description "Stopping HostGuard service (iteration $iteration)" | Out-Null
    $stoppedEnvelope = Wait-ForStatusCondition `
        -ResolvedHostGuardPath $resolvedHostGuardPath `
        -Condition { param($statusEnvelope) Test-StoppedState -StatusEnvelope $statusEnvelope } `
        -Description "HostGuard stopped state after iteration $iteration stop" `
        -TimeoutSeconds $ReadyTimeoutSeconds `
        -PollIntervalMs $PollIntervalMs

    if ($PauseMs -gt 0) {
        Start-Sleep -Milliseconds $PauseMs
    }

    Invoke-HostGuardCommand -ResolvedHostGuardPath $resolvedHostGuardPath -Arguments @('uninstall') -Description "Uninstalling HostGuard service (iteration $iteration)" | Out-Null
    $uninstalledEnvelope = Wait-ForStatusCondition `
        -ResolvedHostGuardPath $resolvedHostGuardPath `
        -Condition { param($statusEnvelope) Test-UninstalledState -StatusEnvelope $statusEnvelope } `
        -Description "HostGuard uninstalled state after iteration $iteration uninstall" `
        -TimeoutSeconds $ReadyTimeoutSeconds `
        -PollIntervalMs $PollIntervalMs

    if ($PauseMs -gt 0) {
        Start-Sleep -Milliseconds $PauseMs
    }

    Invoke-HostGuardCommand -ResolvedHostGuardPath $resolvedHostGuardPath -Arguments @('install') -Description "Installing HostGuard service (iteration $iteration)" | Out-Null
    $installedEnvelope = Wait-ForStatusCondition `
        -ResolvedHostGuardPath $resolvedHostGuardPath `
        -Condition { param($statusEnvelope) Test-InstalledStoppedState -StatusEnvelope $statusEnvelope } `
        -Description "HostGuard installed state after iteration $iteration install" `
        -TimeoutSeconds $ReadyTimeoutSeconds `
        -PollIntervalMs $PollIntervalMs

    if ($PauseMs -gt 0) {
        Start-Sleep -Milliseconds $PauseMs
    }

    Invoke-HostGuardCommand -ResolvedHostGuardPath $resolvedHostGuardPath -Arguments @('start') -Description "Starting HostGuard service (iteration $iteration)" | Out-Null
    $readyEnvelope = Wait-ForStatusCondition `
        -ResolvedHostGuardPath $resolvedHostGuardPath `
        -Condition { param($statusEnvelope) Test-ReadyState -StatusEnvelope $statusEnvelope } `
        -Description "HostGuard ready state after iteration $iteration start" `
        -TimeoutSeconds $ReadyTimeoutSeconds `
        -PollIntervalMs $PollIntervalMs

    $readyDriverStatus = Get-JsonPropertyValue -Object $readyEnvelope -PropertyName 'driver_status'
    $readyPolicyEpoch = Get-RequiredUInt64 -Object $readyDriverStatus -PropertyName 'policy_epoch'
    $services = Get-ServicesJson -StatusEnvelope $readyEnvelope

    $results.Add([pscustomobject]@{
        Iteration = $iteration
        StoppedHostGuardState = (Get-RequiredString -Object (Get-ServicesJson -StatusEnvelope $stoppedEnvelope) -PropertyName 'hostguard_service_state')
        StoppedDriverExists = [bool](Get-JsonPropertyValue -Object (Get-ServicesJson -StatusEnvelope $stoppedEnvelope) -PropertyName 'driver_service_exists')
        UninstalledHostGuardExists = [bool](Get-JsonPropertyValue -Object (Get-ServicesJson -StatusEnvelope $uninstalledEnvelope) -PropertyName 'hostguard_service_exists')
        InstalledHostGuardState = (Get-RequiredString -Object (Get-ServicesJson -StatusEnvelope $installedEnvelope) -PropertyName 'hostguard_service_state')
        ReadyHostGuardState = (Get-RequiredString -Object $services -PropertyName 'hostguard_service_state')
        ReadyDriverExists = [bool](Get-JsonPropertyValue -Object $services -PropertyName 'driver_service_exists')
        ReadyDriverConnected = [bool](Get-JsonPropertyValue -Object $readyEnvelope -PropertyName 'driver_connected')
        ReadyPolicyEpoch = $readyPolicyEpoch
    }) | Out-Null
}

Write-Host ''
$results | Format-Table -AutoSize

Write-Host ''
Write-Success "Lifecycle stress validation completed. iterations=$Iterations baseline_policy_epoch=$baselinePolicyEpoch"
