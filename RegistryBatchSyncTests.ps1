param(
    [string]$HostGuardPath = '',
    [string]$RulesPath = '',
    [int]$BlockRuleCount = 24,
    [int]$AllowRuleCount = 6,
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

function New-RegistryRuleDefinition {
    param(
        [string]$Prefix,
        [int]$Index,
        [int]$Severity
    )

    $suffix = '{0:d4}' -f $Index
    return [ordered]@{
        id = "$Prefix-$suffix"
        threat_desc = "$Prefix regression rule $suffix"
        severity = $Severity
        operation = 'create_key'
        process_name = [ordered]@{
            match_type = 'exact'
            values = @('powershell.exe')
        }
        key_path = [ordered]@{
            match_type = 'exact'
            values = @("\\software\\hostguardbatchsync\\$Prefix\\$suffix")
        }
    }
}

function New-RulesDocument {
    param(
        [int]$BlockCount,
        [int]$AllowCount
    )

    $blockRules = New-Object System.Collections.Generic.List[object]
    for ($index = 1; $index -le $BlockCount; ++$index) {
        $blockRules.Add((New-RegistryRuleDefinition -Prefix 'batch-block' -Index $index -Severity 8))
    }

    $allowRules = New-Object System.Collections.Generic.List[object]
    for ($index = 1; $index -le $AllowCount; ++$index) {
        $allowRules.Add((New-RegistryRuleDefinition -Prefix 'batch-allow' -Index $index -Severity 1))
    }

    return [ordered]@{
        config_version = 'test-registry-batch-sync-' + (Get-Date -Format 'yyyy.MM.dd-HHmmssfff')
        profile_name = 'registry_batch_sync_test'
        generated_at = (Get-Date).ToString('o')
        process_rules = @()
        process_allow_rules = @()
        driver_blacklist = @()
        registry_rules = $blockRules
        registry_allow_rules = $allowRules
    }
}

function Wait-ForDriverRuleState {
    param(
        [string]$ResolvedHostGuardPath,
        [string]$ExpectedRulesPath,
        [UInt64]$ExpectedBlockRuleCount,
        [UInt64]$ExpectedAllowRuleCount,
        [UInt64]$MinimumPolicyEpoch,
        [int]$TimeoutSeconds,
        [int]$PollIntervalMs
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $statusEnvelope = Invoke-StatusJson -ResolvedHostGuardPath $ResolvedHostGuardPath
        $driverConnected = [bool](Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'driver_connected')
        $rulesLoaded = [bool](Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'rules_loaded')
        $currentRulesPath = Get-RequiredString -Object $statusEnvelope -PropertyName 'rules_path'

        if ($driverConnected -and $rulesLoaded -and
            $currentRulesPath.Equals($ExpectedRulesPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            $driverStatus = Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'driver_status'
            $blockRuleCount = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'registry_rule_count'
            $allowRuleCount = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'registry_allow_rule_count'
            $policyEpoch = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'policy_epoch'

            if ($blockRuleCount -eq $ExpectedBlockRuleCount -and
                $allowRuleCount -eq $ExpectedAllowRuleCount -and
                $policyEpoch -ge $MinimumPolicyEpoch) {
                return $statusEnvelope
            }
        }

        Start-Sleep -Milliseconds $PollIntervalMs
    }

    throw "Timed out waiting for registry batch sync state. expected_block=$ExpectedBlockRuleCount expected_allow=$ExpectedAllowRuleCount minimum_epoch=$MinimumPolicyEpoch"
}

if ($BlockRuleCount -lt 1) {
    throw 'BlockRuleCount must be at least 1.'
}

if ($AllowRuleCount -lt 0) {
    throw 'AllowRuleCount cannot be negative.'
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

$resolvedRulesPath = Resolve-ActiveRulesPath -PreferredPath $RulesPath -StatusEnvelope $baselineEnvelope
Write-Step "Using active rules file: $resolvedRulesPath"

$baselineDriverStatus = Get-JsonPropertyValue -Object $baselineEnvelope -PropertyName 'driver_status'
$baselinePolicyEpoch = Get-RequiredUInt64 -Object $baselineDriverStatus -PropertyName 'policy_epoch'
$baselineBlockRuleCount = Get-RequiredUInt64 -Object $baselineDriverStatus -PropertyName 'registry_rule_count'
$baselineAllowRuleCount = Get-RequiredUInt64 -Object $baselineDriverStatus -PropertyName 'registry_allow_rule_count'

Write-Host ''
Write-Step ('Baseline driver registry counts: block={0} allow={1} policy_epoch={2}' -f $baselineBlockRuleCount, $baselineAllowRuleCount, $baselinePolicyEpoch)

$tempRoot = Join-Path $env:TEMP ('HostGuardRegistryBatch-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$backupRulesPath = Join-Path $tempRoot 'rules.backup.json'
Copy-Item -LiteralPath $resolvedRulesPath -Destination $backupRulesPath -Force

$updatedEnvelope = $null
$restoredEnvelope = $null

try {
    $generatedRules = New-RulesDocument -BlockCount $BlockRuleCount -AllowCount $AllowRuleCount
    $generatedRules | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resolvedRulesPath -Encoding UTF8
    Write-Step "Wrote generated batch-sync rules to $resolvedRulesPath"

    $updatedEnvelope = Wait-ForDriverRuleState `
        -ResolvedHostGuardPath $resolvedHostGuardPath `
        -ExpectedRulesPath $resolvedRulesPath `
        -ExpectedBlockRuleCount ([UInt64]$BlockRuleCount) `
        -ExpectedAllowRuleCount ([UInt64]$AllowRuleCount) `
        -MinimumPolicyEpoch ($baselinePolicyEpoch + 1) `
        -TimeoutSeconds $TimeoutSeconds `
        -PollIntervalMs $PollIntervalMs

    $updatedDriverStatus = Get-JsonPropertyValue -Object $updatedEnvelope -PropertyName 'driver_status'
    $updatedPolicyEpoch = Get-RequiredUInt64 -Object $updatedDriverStatus -PropertyName 'policy_epoch'
    Write-Step ('Hot reload applied: block={0} allow={1} policy_epoch={2}' -f `
        (Get-RequiredUInt64 -Object $updatedDriverStatus -PropertyName 'registry_rule_count'),
        (Get-RequiredUInt64 -Object $updatedDriverStatus -PropertyName 'registry_allow_rule_count'),
        $updatedPolicyEpoch)

    Copy-Item -LiteralPath $backupRulesPath -Destination $resolvedRulesPath -Force
    Write-Step "Restored original rules file to $resolvedRulesPath"

    $restoredEnvelope = Wait-ForDriverRuleState `
        -ResolvedHostGuardPath $resolvedHostGuardPath `
        -ExpectedRulesPath $resolvedRulesPath `
        -ExpectedBlockRuleCount $baselineBlockRuleCount `
        -ExpectedAllowRuleCount $baselineAllowRuleCount `
        -MinimumPolicyEpoch ($updatedPolicyEpoch + 1) `
        -TimeoutSeconds $TimeoutSeconds `
        -PollIntervalMs $PollIntervalMs

    $restoredDriverStatus = Get-JsonPropertyValue -Object $restoredEnvelope -PropertyName 'driver_status'
    $restoredPolicyEpoch = Get-RequiredUInt64 -Object $restoredDriverStatus -PropertyName 'policy_epoch'

    Write-Host ''
    [pscustomobject]@{
        BaselinePolicyEpoch = $baselinePolicyEpoch
        UpdatedPolicyEpoch = $updatedPolicyEpoch
        RestoredPolicyEpoch = $restoredPolicyEpoch
        BaselineBlockRules = $baselineBlockRuleCount
        UpdatedBlockRules = Get-RequiredUInt64 -Object $updatedDriverStatus -PropertyName 'registry_rule_count'
        RestoredBlockRules = Get-RequiredUInt64 -Object $restoredDriverStatus -PropertyName 'registry_rule_count'
        BaselineAllowRules = $baselineAllowRuleCount
        UpdatedAllowRules = Get-RequiredUInt64 -Object $updatedDriverStatus -PropertyName 'registry_allow_rule_count'
        RestoredAllowRules = Get-RequiredUInt64 -Object $restoredDriverStatus -PropertyName 'registry_allow_rule_count'
    } | Format-Table -AutoSize

    Write-Host ''
    Write-Success 'Registry batch sync hot-reload validation completed.'
}
finally {
    if (Test-Path $backupRulesPath) {
        Copy-Item -LiteralPath $backupRulesPath -Destination $resolvedRulesPath -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
