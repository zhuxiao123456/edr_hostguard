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
        return $PreferredPath
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

    return $candidates[0]
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

function Get-CurrentUserSid {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User) {
        throw 'Unable to resolve current user SID.'
    }

    return $identity.User.Value
}

function Get-KernelRegistryPathForCurrentUser {
    param(
        [string]$UserSid,
        [string]$RelativePath
    )

    $normalizedPath = $RelativePath.TrimStart('\').Replace('/', '\')
    return "\REGISTRY\USER\$UserSid\$normalizedPath"
}

function New-RegistryRuleDefinition {
    param(
        [string]$Id,
        [string]$ThreatDesc,
        [int]$Severity,
        [string]$MatchType,
        [string]$KeyPathValue
    )

    return [ordered]@{
        id = $Id
        threat_desc = $ThreatDesc
        severity = $Severity
        operation = 'create_key'
        process_name = [ordered]@{
            match_type = 'exact'
            values = @('powershell.exe')
        }
        key_path = [ordered]@{
            match_type = $MatchType
            values = @($KeyPathValue)
        }
    }
}

function New-RegistryRuleOrderDocument {
    param([object[]]$Scenarios)

    $rules = New-Object System.Collections.Generic.List[object]
    foreach ($scenario in $Scenarios) {
        foreach ($rule in $scenario.Rules) {
            $rules.Add($rule)
        }
    }

    return [ordered]@{
        config_version = 'test-registry-rule-order-' + (Get-Date -Format 'yyyy.MM.dd-HHmmssfff')
        profile_name = 'registry_rule_order_test'
        generated_at = (Get-Date).ToString('o')
        process_rules = @()
        process_allow_rules = @()
        driver_blacklist = @()
        registry_rules = $rules
        registry_allow_rules = @()
    }
}

function Get-RuleClassSnapshot {
    param([object]$DriverStatus)

    $ruleClasses = Get-JsonPropertyValue -Object $DriverStatus -PropertyName 'registry_rule_classes'
    return [ordered]@{
        total = Get-RequiredUInt64 -Object $ruleClasses -PropertyName 'total'
        exact = Get-RequiredUInt64 -Object $ruleClasses -PropertyName 'exact'
        prefix = Get-RequiredUInt64 -Object $ruleClasses -PropertyName 'prefix'
        suffix = Get-RequiredUInt64 -Object $ruleClasses -PropertyName 'suffix'
        contains = Get-RequiredUInt64 -Object $ruleClasses -PropertyName 'contains'
    }
}

function Test-RuleClassSnapshot {
    param(
        [object]$Actual,
        [object]$Expected
    )

    foreach ($key in $Expected.Keys) {
        if (-not $Actual.Contains($key)) {
            return $false
        }

        if ([UInt64]$Actual[$key] -ne [UInt64]$Expected[$key]) {
            return $false
        }
    }

    return $true
}

function Wait-ForDriverRuleState {
    param(
        [string]$ResolvedHostGuardPath,
        [string]$ExpectedRulesPath,
        [UInt64]$ExpectedBlockRuleCount,
        [UInt64]$ExpectedAllowRuleCount,
        [object]$ExpectedRuleClasses,
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
            $ruleClasses = Get-RuleClassSnapshot -DriverStatus $driverStatus

            if ($blockRuleCount -eq $ExpectedBlockRuleCount -and
                $allowRuleCount -eq $ExpectedAllowRuleCount -and
                $policyEpoch -ge $MinimumPolicyEpoch -and
                (Test-RuleClassSnapshot -Actual $ruleClasses -Expected $ExpectedRuleClasses)) {
                return $statusEnvelope
            }
        }

        Start-Sleep -Milliseconds $PollIntervalMs
    }

    throw "Timed out waiting for registry order rule state. expected_block=$ExpectedBlockRuleCount expected_allow=$ExpectedAllowRuleCount minimum_epoch=$MinimumPolicyEpoch"
}

function Find-BlockedRegistryEvent {
    param(
        [object[]]$Events,
        [string]$ExpectedRuleId,
        [string]$ExpectedTargetPath
    )

    foreach ($event in $Events) {
        if ($null -eq $event) {
            continue
        }

        if ([string]$event.driver_event_name -ne 'blocked_registry_operation') {
            continue
        }

        if ([string]$event.registry_operation -ne 'create_key') {
            continue
        }

        if ([string]$event.rule_id -ne $ExpectedRuleId) {
            continue
        }

        if (-not ([string]$event.target_path).Equals($ExpectedTargetPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        return $event
    }

    return $null
}

function Wait-ForBlockedRegistryEvent {
    param(
        [string]$ResolvedEventPath,
        [int]$BaselineCount,
        [string]$ExpectedRuleId,
        [string]$ExpectedTargetPath,
        [int]$TimeoutSeconds,
        [int]$PollIntervalMs
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $events = Read-JsonLines -Path $ResolvedEventPath
        $appendedEvents = Get-AppendedEvents -Events $events -BaselineCount $BaselineCount
        $matchedEvent = Find-BlockedRegistryEvent `
            -Events $appendedEvents `
            -ExpectedRuleId $ExpectedRuleId `
            -ExpectedTargetPath $ExpectedTargetPath
        if ($null -ne $matchedEvent) {
            return $matchedEvent
        }

        Start-Sleep -Milliseconds $PollIntervalMs
    }

    throw "Timed out waiting for blocked registry event. expected_rule_id=$ExpectedRuleId target_path=$ExpectedTargetPath"
}

function Invoke-RegistryCreateAttempt {
    param([string]$RegistryProviderPath)

    try {
        New-Item -Path $RegistryProviderPath -Force -ErrorAction Stop | Out-Null
    }
    catch {
    }
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
$resolvedEventPath = Resolve-EventLogPath -PreferredPath $EventPath
Write-Step "Using active rules file: $resolvedRulesPath"
Write-Step "Using event log file: $resolvedEventPath"

$baselineDriverStatus = Get-JsonPropertyValue -Object $baselineEnvelope -PropertyName 'driver_status'
$baselinePolicyEpoch = Get-RequiredUInt64 -Object $baselineDriverStatus -PropertyName 'policy_epoch'
$baselineBlockRuleCount = Get-RequiredUInt64 -Object $baselineDriverStatus -PropertyName 'registry_rule_count'
$baselineAllowRuleCount = Get-RequiredUInt64 -Object $baselineDriverStatus -PropertyName 'registry_allow_rule_count'
$baselineRuleClasses = Get-RuleClassSnapshot -DriverStatus $baselineDriverStatus

$userSid = Get-CurrentUserSid
$scenarioBaseRelativePath = 'Software\HostGuardRuleOrder'
$scenarioBaseProviderPath = 'Registry::HKEY_CURRENT_USER\Software\HostGuardRuleOrder'
$scenarioBaseKernelPath = Get-KernelRegistryPathForCurrentUser -UserSid $userSid -RelativePath $scenarioBaseRelativePath

$scenarios = @(
    [pscustomobject]@{
        Name = 'prefix-before-exact'
        RegistryPath = "$scenarioBaseProviderPath\PrefixBeforeExact"
        KernelPath = "$scenarioBaseKernelPath\PrefixBeforeExact"
        ExpectedRuleId = 'order-a-prefix'
        Rules = @(
            (New-RegistryRuleDefinition -Id 'order-a-prefix' -ThreatDesc 'prefix should win before exact' -Severity 8 -MatchType 'prefix' -KeyPathValue "$scenarioBaseKernelPath\PrefixBefore"),
            (New-RegistryRuleDefinition -Id 'order-a-exact' -ThreatDesc 'exact should lose when ordered after prefix' -Severity 8 -MatchType 'exact' -KeyPathValue "$scenarioBaseKernelPath\PrefixBeforeExact"),
            (New-RegistryRuleDefinition -Id 'order-a-suffix' -ThreatDesc 'suffix fallback for prefix-before-exact' -Severity 8 -MatchType 'suffix' -KeyPathValue '\PrefixBeforeExact'),
            (New-RegistryRuleDefinition -Id 'order-a-contains' -ThreatDesc 'contains fallback for prefix-before-exact' -Severity 8 -MatchType 'contains' -KeyPathValue '\HostGuardRuleOrder\PrefixBeforeExact')
        )
    },
    [pscustomobject]@{
        Name = 'suffix-before-prefix'
        RegistryPath = "$scenarioBaseProviderPath\SuffixBeforePrefix"
        KernelPath = "$scenarioBaseKernelPath\SuffixBeforePrefix"
        ExpectedRuleId = 'order-b-suffix'
        Rules = @(
            (New-RegistryRuleDefinition -Id 'order-b-suffix' -ThreatDesc 'suffix should win before prefix' -Severity 8 -MatchType 'suffix' -KeyPathValue '\SuffixBeforePrefix'),
            (New-RegistryRuleDefinition -Id 'order-b-prefix' -ThreatDesc 'prefix should lose when ordered after suffix' -Severity 8 -MatchType 'prefix' -KeyPathValue "$scenarioBaseKernelPath\SuffixBefore"),
            (New-RegistryRuleDefinition -Id 'order-b-contains' -ThreatDesc 'contains fallback for suffix-before-prefix' -Severity 8 -MatchType 'contains' -KeyPathValue '\HostGuardRuleOrder\SuffixBeforePrefix')
        )
    },
    [pscustomobject]@{
        Name = 'contains-before-suffix'
        RegistryPath = "$scenarioBaseProviderPath\ContainsBeforeSuffix"
        KernelPath = "$scenarioBaseKernelPath\ContainsBeforeSuffix"
        ExpectedRuleId = 'order-c-contains'
        Rules = @(
            (New-RegistryRuleDefinition -Id 'order-c-contains' -ThreatDesc 'contains should win before suffix' -Severity 8 -MatchType 'contains' -KeyPathValue '\HostGuardRuleOrder\ContainsBeforeSuffix'),
            (New-RegistryRuleDefinition -Id 'order-c-suffix' -ThreatDesc 'suffix should lose when ordered after contains' -Severity 8 -MatchType 'suffix' -KeyPathValue '\ContainsBeforeSuffix')
        )
    }
)

$expectedRuleClasses = [ordered]@{
    total = 9
    exact = 1
    prefix = 2
    suffix = 3
    contains = 3
}

Write-Host ''
Write-Step ('Baseline driver registry counts: block={0} allow={1} policy_epoch={2}' -f $baselineBlockRuleCount, $baselineAllowRuleCount, $baselinePolicyEpoch)
Write-Step ('Baseline registry rule classes: total={0} exact={1} prefix={2} suffix={3} contains={4}' -f `
    $baselineRuleClasses.total, $baselineRuleClasses.exact, $baselineRuleClasses.prefix, $baselineRuleClasses.suffix, $baselineRuleClasses.contains)

$tempRoot = Join-Path $env:TEMP ('HostGuardRuleOrder-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$backupRulesPath = Join-Path $tempRoot 'rules.backup.json'
Copy-Item -LiteralPath $resolvedRulesPath -Destination $backupRulesPath -Force

$updatedEnvelope = $null
$restoredEnvelope = $null
$updatedPolicyEpoch = $baselinePolicyEpoch

try {
    $generatedRules = New-RegistryRuleOrderDocument -Scenarios $scenarios
    $generatedRules | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resolvedRulesPath -Encoding UTF8
    Write-Step "Wrote generated rule-order regression rules to $resolvedRulesPath"

    $updatedEnvelope = Wait-ForDriverRuleState `
        -ResolvedHostGuardPath $resolvedHostGuardPath `
        -ExpectedRulesPath $resolvedRulesPath `
        -ExpectedBlockRuleCount 9 `
        -ExpectedAllowRuleCount 0 `
        -ExpectedRuleClasses $expectedRuleClasses `
        -MinimumPolicyEpoch ($baselinePolicyEpoch + 1) `
        -TimeoutSeconds $TimeoutSeconds `
        -PollIntervalMs $PollIntervalMs

    $updatedDriverStatus = Get-JsonPropertyValue -Object $updatedEnvelope -PropertyName 'driver_status'
    $updatedPolicyEpoch = Get-RequiredUInt64 -Object $updatedDriverStatus -PropertyName 'policy_epoch'
    $updatedRuleClasses = Get-RuleClassSnapshot -DriverStatus $updatedDriverStatus
    Write-Step ('Rule-order reload applied: block={0} allow={1} policy_epoch={2}' -f `
        (Get-RequiredUInt64 -Object $updatedDriverStatus -PropertyName 'registry_rule_count'),
        (Get-RequiredUInt64 -Object $updatedDriverStatus -PropertyName 'registry_allow_rule_count'),
        $updatedPolicyEpoch)
    Write-Step ('Loaded registry_rule_classes: total={0} exact={1} prefix={2} suffix={3} contains={4}' -f `
        $updatedRuleClasses.total, $updatedRuleClasses.exact, $updatedRuleClasses.prefix, $updatedRuleClasses.suffix, $updatedRuleClasses.contains)

    foreach ($scenario in $scenarios) {
        Remove-Item -Path $scenario.RegistryPath -Recurse -Force -ErrorAction SilentlyContinue
        $baselineEventCount = (Read-JsonLines -Path $resolvedEventPath).Count
        Invoke-RegistryCreateAttempt -RegistryProviderPath $scenario.RegistryPath

        $matchedEvent = Wait-ForBlockedRegistryEvent `
            -ResolvedEventPath $resolvedEventPath `
            -BaselineCount $baselineEventCount `
            -ExpectedRuleId $scenario.ExpectedRuleId `
            -ExpectedTargetPath $scenario.KernelPath `
            -TimeoutSeconds $TimeoutSeconds `
            -PollIntervalMs $PollIntervalMs

        if (Test-Path $scenario.RegistryPath) {
            throw "Registry path was created even though the operation should have been blocked: $($scenario.RegistryPath)"
        }

        Write-Step ('Scenario {0}: matched rule_id={1} target_path={2}' -f `
            $scenario.Name,
            [string]$matchedEvent.rule_id,
            [string]$matchedEvent.target_path)
    }

    Copy-Item -LiteralPath $backupRulesPath -Destination $resolvedRulesPath -Force
    Write-Step "Restored original rules file to $resolvedRulesPath"

    $restoredEnvelope = Wait-ForDriverRuleState `
        -ResolvedHostGuardPath $resolvedHostGuardPath `
        -ExpectedRulesPath $resolvedRulesPath `
        -ExpectedBlockRuleCount $baselineBlockRuleCount `
        -ExpectedAllowRuleCount $baselineAllowRuleCount `
        -ExpectedRuleClasses $baselineRuleClasses `
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
        ExpectedExactRules = 1
        ExpectedPrefixRules = 2
        ExpectedSuffixRules = 3
        ExpectedContainsRules = 3
    } | Format-Table -AutoSize

    Write-Host ''
    Write-Success 'Registry rule order regression completed.'
}
finally {
    if (Test-Path $backupRulesPath) {
        Copy-Item -LiteralPath $backupRulesPath -Destination $resolvedRulesPath -Force -ErrorAction SilentlyContinue
    }

    foreach ($scenario in $scenarios) {
        Remove-Item -Path $scenario.RegistryPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
