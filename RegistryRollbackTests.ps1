param(
    [string]$HostGuardPath = '',
    [string]$RulesPath = '',
    [string]$EventPath = '',
    [int]$TimeoutSeconds = 30,
    [int]$PollIntervalMs = 500
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

function Get-RequiredString {
    param(
        [object]$Object,
        [string]$PropertyName
    )

    return [string](Get-JsonPropertyValue -Object $Object -PropertyName $PropertyName)
}

function Resolve-ActiveRulesPath {
    param(
        [string]$PreferredPath,
        [object]$StatusEnvelope
    )

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
        if (-not (Test-Path $PreferredPath)) {
            throw "Rules file not found: $PreferredPath"
        }

        return (Resolve-Path $PreferredPath).ProviderPath
    }

    $statusRulesPath = Get-RequiredString -Object $StatusEnvelope -PropertyName 'rules_path'
    if ([string]::IsNullOrWhiteSpace($statusRulesPath)) {
        throw 'HostGuard status --json did not return rules_path.'
    }

    if (-not (Test-Path $statusRulesPath)) {
        throw "Resolved rules_path does not exist: $statusRulesPath"
    }

    return (Resolve-Path $statusRulesPath).ProviderPath
}

function Resolve-EventLogPath {
    param([string]$PreferredPath)

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
        if (-not (Test-Path $PreferredPath)) {
            throw "Event log file not found: $PreferredPath"
        }

        return (Resolve-Path $PreferredPath).ProviderPath
    }

    $candidates = @(
        'C:\ProgramData\HostGuard\events.jsonl',
        'C:\ransomware\events.jsonl'
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).ProviderPath
        }
    }

    throw 'Unable to locate HostGuard events.jsonl. Pass -EventPath explicitly.'
}

function Read-JsonLines {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return @()
    }

    $events = New-Object System.Collections.Generic.List[object]
    foreach ($line in Get-Content $Path -ErrorAction SilentlyContinue) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $normalizedLine = $line
        if ($normalizedLine.Length -gt 0 -and $normalizedLine[0] -eq [char]0xFEFF) {
            $normalizedLine = $normalizedLine.Substring(1)
        }

        try {
            $events.Add(($normalizedLine | ConvertFrom-Json -ErrorAction Stop))
        }
        catch {
        }
    }

    return $events
}

function Get-AppendedEvents {
    param(
        [object[]]$Events,
        [int]$BaselineCount
    )

    if ($BaselineCount -lt 0) {
        $BaselineCount = 0
    }

    if ($null -eq $Events -or $Events.Count -le $BaselineCount) {
        return @()
    }

    return @($Events[$BaselineCount..($Events.Count - 1)])
}

function Find-ConfigEvent {
    param(
        [object[]]$Events,
        [string]$EventType,
        [string]$RulesPath,
        [hashtable]$ExpectedFields
    )

    foreach ($event in $Events) {
        if ($null -eq $event) {
            continue
        }

        if ([string]$event.event_type -ne $EventType) {
            continue
        }

        $eventRulesPath = [string]$event.rules_path
        if (-not [string]::IsNullOrWhiteSpace($RulesPath) -and
            -not $eventRulesPath.Equals($RulesPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $matched = $true
        foreach ($key in $ExpectedFields.Keys) {
            $property = $event.PSObject.Properties[$key]
            if ($null -eq $property) {
                $matched = $false
                break
            }

            $actualValue = [string]$property.Value
            $expectedValue = [string]$ExpectedFields[$key]
            if (-not $actualValue.Equals($expectedValue, [System.StringComparison]::OrdinalIgnoreCase)) {
                $matched = $false
                break
            }
        }

        if ($matched) {
            return $event
        }
    }

    return $null
}

function Wait-ForRollbackState {
    param(
        [string]$ResolvedHostGuardPath,
        [string]$ResolvedRulesPath,
        [string]$ResolvedEventPath,
        [UInt64]$ExpectedPolicyEpoch,
        [UInt64]$ExpectedBlockRuleCount,
        [UInt64]$ExpectedAllowRuleCount,
        [int]$BaselineEventCount,
        [int]$TimeoutSeconds,
        [int]$PollIntervalMs
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $statusEnvelope = Invoke-StatusJson -ResolvedHostGuardPath $ResolvedHostGuardPath
        $events = Read-JsonLines -Path $ResolvedEventPath
        $newEvents = Get-AppendedEvents -Events $events -BaselineCount $BaselineEventCount
        $rollbackEvent = Find-ConfigEvent -Events $newEvents -EventType 'config_reload_rollback' -RulesPath $ResolvedRulesPath -ExpectedFields @{
            action = 'reload'
            result = 'rollback_retained'
            reload_stage = 'parse'
        }

        $driverConnected = [bool](Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'driver_connected')
        $rulesLoaded = [bool](Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'rules_loaded')
        $driverStatus = Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'driver_status'
        $policyEpoch = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'policy_epoch'
        $blockRuleCount = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'registry_rule_count'
        $allowRuleCount = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'registry_allow_rule_count'

        if ($driverConnected -and
            -not $rulesLoaded -and
            $policyEpoch -eq $ExpectedPolicyEpoch -and
            $blockRuleCount -eq $ExpectedBlockRuleCount -and
            $allowRuleCount -eq $ExpectedAllowRuleCount -and
            $null -ne $rollbackEvent) {
            return [pscustomobject]@{
                StatusEnvelope = $statusEnvelope
                RollbackEvent = $rollbackEvent
                EventCount = $events.Count
            }
        }

        Start-Sleep -Milliseconds $PollIntervalMs
    }

    throw 'Timed out waiting for parse-failure rollback state.'
}

function Wait-ForRecoveryState {
    param(
        [string]$ResolvedHostGuardPath,
        [string]$ResolvedRulesPath,
        [string]$ResolvedEventPath,
        [UInt64]$ExpectedBlockRuleCount,
        [UInt64]$ExpectedAllowRuleCount,
        [int]$BaselineEventCount,
        [int]$TimeoutSeconds,
        [int]$PollIntervalMs
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $statusEnvelope = Invoke-StatusJson -ResolvedHostGuardPath $ResolvedHostGuardPath
        $events = Read-JsonLines -Path $ResolvedEventPath
        $newEvents = Get-AppendedEvents -Events $events -BaselineCount $BaselineEventCount
        $appliedEvent = Find-ConfigEvent -Events $newEvents -EventType 'config_applied' -RulesPath $ResolvedRulesPath -ExpectedFields @{
            action = 'reload'
            result = 'success'
            load_mode = 'hot_reload'
        }

        $driverConnected = [bool](Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'driver_connected')
        $rulesLoaded = [bool](Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'rules_loaded')
        $driverStatus = Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'driver_status'
        $blockRuleCount = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'registry_rule_count'
        $allowRuleCount = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'registry_allow_rule_count'

        if ($driverConnected -and
            $rulesLoaded -and
            $blockRuleCount -eq $ExpectedBlockRuleCount -and
            $allowRuleCount -eq $ExpectedAllowRuleCount -and
            $null -ne $appliedEvent) {
            return [pscustomobject]@{
                StatusEnvelope = $statusEnvelope
                AppliedEvent = $appliedEvent
            }
        }

        Start-Sleep -Milliseconds $PollIntervalMs
    }

    throw 'Timed out waiting for recovery after rollback test.'
}

$resolvedHostGuardPath = Resolve-HostGuardPath -PreferredPath $HostGuardPath
Write-Step "Using HostGuard binary: $resolvedHostGuardPath"

$baselineEnvelope = Invoke-StatusJson -ResolvedHostGuardPath $resolvedHostGuardPath
if (-not [bool](Get-JsonPropertyValue -Object $baselineEnvelope -PropertyName 'driver_connected')) {
    $driverErrorCode = 0
    try {
        $driverErrorCode = [int](Get-JsonPropertyValue -Object $baselineEnvelope -PropertyName 'driver_error_code')
    }
    catch {
        $driverErrorCode = 0
    }

    throw "Driver is not connected. Start HostGuard foreground/service first. driver_error_code=$driverErrorCode"
}

if (-not [bool](Get-JsonPropertyValue -Object $baselineEnvelope -PropertyName 'rules_loaded')) {
    throw 'Rollback regression requires a valid baseline rules.json before the test starts.'
}

$resolvedRulesPath = Resolve-ActiveRulesPath -PreferredPath $RulesPath -StatusEnvelope $baselineEnvelope
$resolvedEventPath = Resolve-EventLogPath -PreferredPath $EventPath

Write-Step "Using active rules file: $resolvedRulesPath"
Write-Step "Using event log path: $resolvedEventPath"

$baselineDriverStatus = Get-JsonPropertyValue -Object $baselineEnvelope -PropertyName 'driver_status'
$baselinePolicyEpoch = Get-RequiredUInt64 -Object $baselineDriverStatus -PropertyName 'policy_epoch'
$baselineBlockRuleCount = Get-RequiredUInt64 -Object $baselineDriverStatus -PropertyName 'registry_rule_count'
$baselineAllowRuleCount = Get-RequiredUInt64 -Object $baselineDriverStatus -PropertyName 'registry_allow_rule_count'
$baselineEvents = Read-JsonLines -Path $resolvedEventPath
$baselineEventCount = $baselineEvents.Count

$tempRoot = Join-Path $env:TEMP ('HostGuardRollback-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
$backupRulesPath = Join-Path $tempRoot 'rules.backup.json'
Copy-Item -LiteralPath $resolvedRulesPath -Destination $backupRulesPath -Force

$rollbackResult = $null
$recoveryResult = $null

try {
    $invalidJson = @'
{
  "config_version": "rollback-invalid",
  "profile_name": "rollback_invalid"
'@

    Set-Content -LiteralPath $resolvedRulesPath -Value $invalidJson -Encoding UTF8
    Write-Step "Wrote invalid rules file to trigger rollback: $resolvedRulesPath"

    $rollbackResult = Wait-ForRollbackState `
        -ResolvedHostGuardPath $resolvedHostGuardPath `
        -ResolvedRulesPath $resolvedRulesPath `
        -ResolvedEventPath $resolvedEventPath `
        -ExpectedPolicyEpoch $baselinePolicyEpoch `
        -ExpectedBlockRuleCount $baselineBlockRuleCount `
        -ExpectedAllowRuleCount $baselineAllowRuleCount `
        -BaselineEventCount $baselineEventCount `
        -TimeoutSeconds $TimeoutSeconds `
        -PollIntervalMs $PollIntervalMs

    Write-Step ('Rollback observed: policy_epoch={0} block={1} allow={2}' -f `
        $baselinePolicyEpoch,
        $baselineBlockRuleCount,
        $baselineAllowRuleCount)

    Copy-Item -LiteralPath $backupRulesPath -Destination $resolvedRulesPath -Force
    Write-Step "Restored valid rules file: $resolvedRulesPath"

    $recoveryResult = Wait-ForRecoveryState `
        -ResolvedHostGuardPath $resolvedHostGuardPath `
        -ResolvedRulesPath $resolvedRulesPath `
        -ResolvedEventPath $resolvedEventPath `
        -ExpectedBlockRuleCount $baselineBlockRuleCount `
        -ExpectedAllowRuleCount $baselineAllowRuleCount `
        -BaselineEventCount $rollbackResult.EventCount `
        -TimeoutSeconds $TimeoutSeconds `
        -PollIntervalMs $PollIntervalMs

    $recoveredDriverStatus = Get-JsonPropertyValue -Object $recoveryResult.StatusEnvelope -PropertyName 'driver_status'
    $recoveredPolicyEpoch = Get-RequiredUInt64 -Object $recoveredDriverStatus -PropertyName 'policy_epoch'

    Write-Host ''
    [pscustomobject]@{
        BaselinePolicyEpoch = $baselinePolicyEpoch
        RecoveredPolicyEpoch = $recoveredPolicyEpoch
        BaselineBlockRules = $baselineBlockRuleCount
        RecoveredBlockRules = Get-RequiredUInt64 -Object $recoveredDriverStatus -PropertyName 'registry_rule_count'
        BaselineAllowRules = $baselineAllowRuleCount
        RecoveredAllowRules = Get-RequiredUInt64 -Object $recoveredDriverStatus -PropertyName 'registry_allow_rule_count'
        RollbackStage = [string]$rollbackResult.RollbackEvent.reload_stage
        RollbackResult = [string]$rollbackResult.RollbackEvent.result
        RecoveryResult = [string]$recoveryResult.AppliedEvent.result
    } | Format-Table -AutoSize

    Write-Host ''
    Write-Success 'Registry rollback hot-reload validation completed.'
}
finally {
    if (Test-Path $backupRulesPath) {
        Copy-Item -LiteralPath $backupRulesPath -Destination $resolvedRulesPath -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
