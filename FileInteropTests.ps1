param(
    [string]$ProtectedDriverPath = 'C:\Windows\System32\drivers\DriverModule.sys',
    [string]$ScratchRoot = 'C:\Temp\HostGuardFileInterop',
    [string]$EventPath = '',
    [int]$TimeoutSeconds = 20,
    [int]$PollIntervalMs = 250
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
            return $candidate
        }
    }

    if (Test-Path 'C:\ProgramData\HostGuard') {
        return 'C:\ProgramData\HostGuard\events.jsonl'
    }

    return 'C:\ransomware\events.jsonl'
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

function Find-BlockedFileEvent {
    param(
        [object[]]$Events,
        [string]$ExpectedTargetPath,
        [string[]]$ExpectedInfoClasses = @()
    )

    $fallbackEvent = $null
    foreach ($event in $Events) {
        if ($null -eq $event) {
            continue
        }

        if ([string]$event.event_type -ne 'blocked_file_operation') {
            continue
        }

        if ([string]$event.driver_event_name -ne 'blocked_file_operation') {
            continue
        }

        if ([string]$event.rule_id -ne 'driver_self_protection') {
            continue
        }

        if (-not ([string]$event.target_path).Equals($ExpectedTargetPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $actualInfoClass = [string]$event.info_class
        if ($ExpectedInfoClasses.Count -eq 0) {
            return $event
        }

        foreach ($expectedInfoClass in $ExpectedInfoClasses) {
            if ($actualInfoClass.Equals($expectedInfoClass, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $event
            }
        }

        if ($null -eq $fallbackEvent) {
            $fallbackEvent = $event
        }
    }

    return $fallbackEvent
}

function Wait-BlockedFileEvent {
    param(
        [string]$ResolvedEventPath,
        [int]$BaselineCount,
        [string]$ExpectedTargetPath,
        [string[]]$ExpectedInfoClasses = @()
    )

    $matchedEvent = $null
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $allEvents = Read-JsonLines -Path $ResolvedEventPath
        $newEvents = if ($allEvents.Count -gt $BaselineCount) {
            @($allEvents | Select-Object -Skip $BaselineCount)
        }
        else {
            @()
        }

        $matchedEvent = Find-BlockedFileEvent `
            -Events $newEvents `
            -ExpectedTargetPath $ExpectedTargetPath `
            -ExpectedInfoClasses $ExpectedInfoClasses
        if ($null -ne $matchedEvent) {
            return $matchedEvent
        }

        Start-Sleep -Milliseconds $PollIntervalMs
    }

    return $null
}

function Invoke-BlockedMutationValidation {
    param(
        [string]$Name,
        [string]$ExpectedTargetPath,
        [scriptblock]$Action,
        [string[]]$ExpectedInfoClasses = @()
    )

    $baselineCount = (Read-JsonLines -Path $resolvedEventPath).Count
    $operationBlocked = $false
    $operationError = ''

    Write-Step "Attempting mutation: $Name"
    try {
        & $Action
    }
    catch {
        $operationBlocked = $true
        $operationError = $_.Exception.Message
    }

    if (-not $operationBlocked) {
        throw "Protected driver mutation unexpectedly succeeded: $Name"
    }

    $matchedEvent = Wait-BlockedFileEvent `
        -ResolvedEventPath $resolvedEventPath `
        -BaselineCount $baselineCount `
        -ExpectedTargetPath $ExpectedTargetPath `
        -ExpectedInfoClasses $ExpectedInfoClasses

    if ($null -eq $matchedEvent) {
        throw "Blocked file telemetry validation failed for mutation: $Name"
    }

    return [pscustomobject]@{
        Mutation = $Name
        Error = $operationError
        ProcessId = [int]$matchedEvent.process_id
        ProcessName = [string]$matchedEvent.process_name
        RuleId = [string]$matchedEvent.rule_id
        TargetPath = [string]$matchedEvent.target_path
        InfoClass = [string]$matchedEvent.info_class
    }
}

$resolvedEventPath = Resolve-EventLogPath -PreferredPath $EventPath
Write-Step "Using event log path: $resolvedEventPath"

if (-not (Test-Path -LiteralPath $ProtectedDriverPath)) {
    throw "Protected driver path not found: $ProtectedDriverPath"
}

New-Item -ItemType Directory -Force -Path $ScratchRoot | Out-Null
$scratchCopyPath = Join-Path $ScratchRoot 'DriverModule.copy.sys'
Remove-Item -LiteralPath $scratchCopyPath -Force -ErrorAction SilentlyContinue

Write-Step "Copying protected driver to scratch path: $scratchCopyPath"
Copy-Item -LiteralPath $ProtectedDriverPath -Destination $scratchCopyPath -Force

$renameTargetName = 'DriverModule.renamed-test.sys'
$results = @(
    Invoke-BlockedMutationValidation -Name 'overwrite_copy' -ExpectedTargetPath $ProtectedDriverPath -Action {
        Copy-Item -LiteralPath $scratchCopyPath -Destination $ProtectedDriverPath -Force -ErrorAction Stop
    }
    Invoke-BlockedMutationValidation -Name 'rename_item' -ExpectedTargetPath $ProtectedDriverPath -ExpectedInfoClasses @(
        'FileRenameInformation',
        'FileRenameInformationEx'
    ) -Action {
        Rename-Item -LiteralPath $ProtectedDriverPath -NewName $renameTargetName -ErrorAction Stop
    }
    Invoke-BlockedMutationValidation -Name 'delete_item' -ExpectedTargetPath $ProtectedDriverPath -ExpectedInfoClasses @(
        'FileDispositionInformation',
        'FileDispositionInformationEx'
    ) -Action {
        Remove-Item -LiteralPath $ProtectedDriverPath -Force -ErrorAction Stop
    }
)

if ($results.Count -lt 3) {
    $recentEvents = Read-JsonLines -Path $resolvedEventPath |
        Where-Object { [string]$_.driver_event_name -eq 'blocked_file_operation' } |
        Select-Object -Last 5

    if ($recentEvents.Count -gt 0) {
        Write-Host ''
        Write-Host '[*] Recent blocked_file_operation events:' -ForegroundColor Cyan
        $recentEvents |
            Select-Object time, process_id, process_name, rule_id, target_path |
            Format-Table -AutoSize
    }

    throw 'Blocked file telemetry validation failed.'
}

Write-Host ''
$results |
    Select-Object Mutation, ProcessId, ProcessName, RuleId, InfoClass, TargetPath, Error |
    Format-Table -AutoSize

Write-Host ''
Write-Success 'HostGuard file self-protection telemetry validated successfully.'
