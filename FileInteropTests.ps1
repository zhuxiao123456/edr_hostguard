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
        [string]$ExpectedTargetPath
    )

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

        return $event
    }

    return $null
}

$resolvedEventPath = Resolve-EventLogPath -PreferredPath $EventPath
Write-Step "Using event log path: $resolvedEventPath"

if (-not (Test-Path -LiteralPath $ProtectedDriverPath)) {
    throw "Protected driver path not found: $ProtectedDriverPath"
}

New-Item -ItemType Directory -Force -Path $ScratchRoot | Out-Null
$scratchCopyPath = Join-Path $ScratchRoot 'DriverModule.copy.sys'
Remove-Item -LiteralPath $scratchCopyPath -Force -ErrorAction SilentlyContinue

$baselineEvents = Read-JsonLines -Path $resolvedEventPath
$baselineCount = $baselineEvents.Count

Write-Step "Copying protected driver to scratch path: $scratchCopyPath"
Copy-Item -LiteralPath $ProtectedDriverPath -Destination $scratchCopyPath -Force

$overwriteBlocked = $false
$overwriteError = ''
Write-Step 'Attempting overwrite against the protected driver image'
try {
    Copy-Item -LiteralPath $scratchCopyPath -Destination $ProtectedDriverPath -Force -ErrorAction Stop
}
catch {
    $overwriteBlocked = $true
    $overwriteError = $_.Exception.Message
}

if (-not $overwriteBlocked) {
    throw 'Protected driver overwrite unexpectedly succeeded.'
}

$matchedEvent = $null
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
    $allEvents = Read-JsonLines -Path $resolvedEventPath
    $newEvents = if ($allEvents.Count -gt $baselineCount) {
        @($allEvents | Select-Object -Skip $baselineCount)
    }
    else {
        @()
    }

    $matchedEvent = Find-BlockedFileEvent -Events $newEvents -ExpectedTargetPath $ProtectedDriverPath
    if ($null -ne $matchedEvent) {
        break
    }

    Start-Sleep -Milliseconds $PollIntervalMs
}

if ($null -eq $matchedEvent) {
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
[pscustomobject]@{
    ProtectedDriverPath = $ProtectedDriverPath
    OverwriteError = $overwriteError
    ProcessId = [int]$matchedEvent.process_id
    ProcessName = [string]$matchedEvent.process_name
    RuleId = [string]$matchedEvent.rule_id
    TargetPath = [string]$matchedEvent.target_path
} | Format-Table -AutoSize

Write-Host ''
Write-Success 'HostGuard file self-protection telemetry validated successfully.'
