param(
    [string]$HostGuardPath = '',
    [string]$ProtectedDriverPath = 'C:\Windows\System32\drivers\DriverModule.sys',
    [string]$ScratchRoot = 'C:\Temp\HostGuardFileProtectionCounters',
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

function Get-DriverStatus {
    param([string]$ResolvedHostGuardPath)

    $statusEnvelope = Invoke-StatusJson -ResolvedHostGuardPath $ResolvedHostGuardPath
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

    return (Get-JsonPropertyValue -Object $statusEnvelope -PropertyName 'driver_status')
}

function Get-FileProtectionSnapshot {
    param([string]$ResolvedHostGuardPath)

    $driverStatus = Get-DriverStatus -ResolvedHostGuardPath $ResolvedHostGuardPath
    return [pscustomobject]@{
        BlockCount = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'file_protection_block_count'
        CreateBlockCount = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'file_protection_create_block_count'
        SetInformationBlockCount = Get-RequiredUInt64 -Object $driverStatus -PropertyName 'file_protection_set_information_block_count'
        LastInfoClass = [string](Get-JsonPropertyValue -Object $driverStatus -PropertyName 'last_file_protection_info_class')
    }
}

function Wait-FileProtectionSnapshot {
    param(
        [string]$ResolvedHostGuardPath,
        [object]$BaselineSnapshot,
        [UInt64]$MinimumBlockDelta,
        [UInt64]$MinimumCreateBlockDelta,
        [UInt64]$MinimumSetInformationBlockDelta,
        [string[]]$ExpectedInfoClasses
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $snapshot = Get-FileProtectionSnapshot -ResolvedHostGuardPath $ResolvedHostGuardPath
        $blockDelta = [UInt64]($snapshot.BlockCount - $BaselineSnapshot.BlockCount)
        $createDelta = [UInt64]($snapshot.CreateBlockCount - $BaselineSnapshot.CreateBlockCount)
        $setInformationDelta = [UInt64]($snapshot.SetInformationBlockCount - $BaselineSnapshot.SetInformationBlockCount)

        $matchesInfoClass = $ExpectedInfoClasses.Count -eq 0
        if (-not $matchesInfoClass) {
            foreach ($expectedInfoClass in $ExpectedInfoClasses) {
                if ($snapshot.LastInfoClass.Equals($expectedInfoClass, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $matchesInfoClass = $true
                    break
                }
            }
        }

        if ($blockDelta -ge $MinimumBlockDelta -and
            $createDelta -ge $MinimumCreateBlockDelta -and
            $setInformationDelta -ge $MinimumSetInformationBlockDelta -and
            $matchesInfoClass) {
            return [pscustomobject]@{
                Snapshot = $snapshot
                BlockDelta = $blockDelta
                CreateBlockDelta = $createDelta
                SetInformationBlockDelta = $setInformationDelta
            }
        }

        Start-Sleep -Milliseconds $PollIntervalMs
    }

    return $null
}

function Invoke-BlockedMutationStatusValidation {
    param(
        [string]$ResolvedHostGuardPath,
        [string]$Name,
        [UInt64]$MinimumBlockDelta,
        [UInt64]$MinimumCreateBlockDelta,
        [UInt64]$MinimumSetInformationBlockDelta,
        [string[]]$ExpectedInfoClasses,
        [scriptblock]$Action
    )

    $baselineSnapshot = Get-FileProtectionSnapshot -ResolvedHostGuardPath $ResolvedHostGuardPath
    $operationBlocked = $false
    $operationError = ''

    Write-Step "Attempting protected-file mutation for runtime counters: $Name"
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

    $deltaResult = Wait-FileProtectionSnapshot `
        -ResolvedHostGuardPath $ResolvedHostGuardPath `
        -BaselineSnapshot $baselineSnapshot `
        -MinimumBlockDelta $MinimumBlockDelta `
        -MinimumCreateBlockDelta $MinimumCreateBlockDelta `
        -MinimumSetInformationBlockDelta $MinimumSetInformationBlockDelta `
        -ExpectedInfoClasses $ExpectedInfoClasses

    if ($null -eq $deltaResult) {
        throw "File-protection runtime counter validation failed for mutation: $Name"
    }

    return [pscustomobject]@{
        Mutation = $Name
        LastInfoClass = [string]$deltaResult.Snapshot.LastInfoClass
        BlockDelta = [UInt64]$deltaResult.BlockDelta
        CreateBlockDelta = [UInt64]$deltaResult.CreateBlockDelta
        SetInformationBlockDelta = [UInt64]$deltaResult.SetInformationBlockDelta
        Error = $operationError
    }
}

$resolvedHostGuardPath = Resolve-HostGuardPath -PreferredPath $HostGuardPath
Write-Step "Using HostGuard binary: $resolvedHostGuardPath"

if (-not (Test-Path -LiteralPath $ProtectedDriverPath)) {
    throw "Protected driver path not found: $ProtectedDriverPath"
}

New-Item -ItemType Directory -Force -Path $ScratchRoot | Out-Null
$scratchCopyPath = Join-Path $ScratchRoot 'DriverModule.copy.sys'
Remove-Item -LiteralPath $scratchCopyPath -Force -ErrorAction SilentlyContinue

Write-Step "Copying protected driver to scratch path: $scratchCopyPath"
Copy-Item -LiteralPath $ProtectedDriverPath -Destination $scratchCopyPath -Force

$renameTargetName = 'DriverModule.renamed-status-test.sys'
$results = @(
    Invoke-BlockedMutationStatusValidation -ResolvedHostGuardPath $resolvedHostGuardPath `
        -Name 'overwrite_copy' `
        -MinimumBlockDelta 1 `
        -MinimumCreateBlockDelta 1 `
        -MinimumSetInformationBlockDelta 0 `
        -ExpectedInfoClasses @('IRP_MJ_CREATE') `
        -Action {
            Copy-Item -LiteralPath $scratchCopyPath -Destination $ProtectedDriverPath -Force -ErrorAction Stop
        }
    Invoke-BlockedMutationStatusValidation -ResolvedHostGuardPath $resolvedHostGuardPath `
        -Name 'rename_item' `
        -MinimumBlockDelta 1 `
        -MinimumCreateBlockDelta 0 `
        -MinimumSetInformationBlockDelta 1 `
        -ExpectedInfoClasses @('FileRenameInformation', 'FileRenameInformationEx') `
        -Action {
            Rename-Item -LiteralPath $ProtectedDriverPath -NewName $renameTargetName -ErrorAction Stop
        }
    Invoke-BlockedMutationStatusValidation -ResolvedHostGuardPath $resolvedHostGuardPath `
        -Name 'delete_item' `
        -MinimumBlockDelta 1 `
        -MinimumCreateBlockDelta 0 `
        -MinimumSetInformationBlockDelta 1 `
        -ExpectedInfoClasses @('FileDispositionInformation', 'FileDispositionInformationEx') `
        -Action {
            Remove-Item -LiteralPath $ProtectedDriverPath -Force -ErrorAction Stop
        }
)

Write-Host ''
$results |
    Select-Object Mutation, LastInfoClass, BlockDelta, CreateBlockDelta, SetInformationBlockDelta, Error |
    Format-Table -AutoSize

Write-Host ''
Write-Success 'File-protection runtime counters validated successfully.'
