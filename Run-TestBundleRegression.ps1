param(
    [string]$TargetRoot = 'C:\ransomware',
    [string]$ProgramDataRoot = 'C:\ProgramData\HostGuard',
    [string]$RuleFile = 'registry_interop_test_rules.json',
    [int]$ReadyTimeoutSeconds = 45,
    [int]$RepeatCount = 4,
    [switch]$SkipDeploy,
    [switch]$SkipCleanup,
    [switch]$SkipCertificateImport,
    [switch]$SkipProcessObserved,
    [switch]$SkipFileInterop,
    [switch]$SkipFileProtectionCounters,
    [switch]$SkipRuntimeCounters,
    [switch]$SkipRegistryBatchSync,
    [switch]$SkipRegistryRuleScale,
    [switch]$SkipRegistryRuleOrder,
    [switch]$SkipRegistryRollback,
    [switch]$SkipRegistryInterop,
    [switch]$SkipLifecycleStress,
    [switch]$LeaveInstalled,
    [switch]$PlanOnly
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

function Write-Warn {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-RegressionResultMap {
    $results = [ordered]@{}
    foreach ($name in @(
        'ProcessObservedTests.ps1',
        'FileInteropTests.ps1',
        'FileProtectionRuntimeCountersTests.ps1',
        'StatusRuntimeCountersTests.ps1',
        'RegistryBatchSyncTests.ps1',
        'RegistryRuleScaleTests.ps1',
        'RegistryRuleOrderTests.ps1',
        'RegistryRollbackTests.ps1',
        'RegistryInteropTests.ps1',
        'LifecycleStressTests.ps1'
    )) {
        $results[$name] = [pscustomobject]@{
            Status = 'SKIP'
            Detail = 'Not executed.'
        }
    }

    return $results
}

function Set-RegressionResult {
    param(
        [System.Collections.IDictionary]$Results,
        [string]$Name,
        [string]$Status,
        [string]$Detail
    )

    if (-not $Results.Contains($Name)) {
        $Results[$Name] = [pscustomobject]@{
            Status = $Status
            Detail = $Detail
        }
        return
    }

    $Results[$Name] = [pscustomobject]@{
        Status = $Status
        Detail = $Detail
    }
}

function Write-RegressionSummary {
    param([System.Collections.IDictionary]$Results)

    Write-Host ''
    Write-Host 'Regression summary:' -ForegroundColor Cyan
    Get-RegressionSummaryRows -Results $Results |
        Format-Table -AutoSize
}

function Get-RegressionSummaryRows {
    param([System.Collections.IDictionary]$Results)

    return @(
        $Results.GetEnumerator() |
            ForEach-Object {
                [pscustomobject]@{
                    Test = $_.Key
                    Status = [string]$_.Value.Status
                    Detail = [string]$_.Value.Detail
                }
            }
    )
}

function Write-RegressionSummaryFiles {
    param(
        [System.Collections.IDictionary]$Results,
        [string]$TargetRootPath,
        [string]$ProgramDataRootPath,
        [string]$RuleFileName,
        [bool]$Succeeded,
        [string]$FailureDetail,
        [object]$FinalDriverStatus
    )

    $summaryRows = Get-RegressionSummaryRows -Results $Results
    $txtPath = Join-Path $TargetRootPath 'bundle-regression-summary.txt'
    $jsonPath = Join-Path $TargetRootPath 'bundle-regression-summary.json'

    New-Item -ItemType Directory -Force -Path $TargetRootPath | Out-Null

    $txtLines = [System.Collections.Generic.List[string]]::new()
    $txtLines.Add('HostGuard bundle regression summary')
    $txtLines.Add("GeneratedAt: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $txtLines.Add("TargetRoot: $TargetRootPath")
    $txtLines.Add("ProgramDataRoot: $ProgramDataRootPath")
    $txtLines.Add("RuleFile: $RuleFileName")
    $txtLines.Add("Succeeded: $Succeeded")
    if (-not [string]::IsNullOrWhiteSpace($FailureDetail)) {
        $txtLines.Add("FailureDetail: $FailureDetail")
    }
    $txtLines.Add('')
    $txtLines.Add('Regression summary:')
    $txtLines.Add(($summaryRows | Format-Table -AutoSize | Out-String).TrimEnd())

    if ($null -ne $FinalDriverStatus) {
        $txtLines.Add('')
        $txtLines.Add('Final driver status:')
        $txtLines.Add(($FinalDriverStatus | Format-List * | Out-String).TrimEnd())
    }

    Set-Content -Path $txtPath -Value $txtLines -Encoding UTF8

    $summaryPayload = [ordered]@{
        generated_at = (Get-Date).ToString('s')
        target_root = $TargetRootPath
        program_data_root = $ProgramDataRootPath
        rule_file = $RuleFileName
        succeeded = $Succeeded
        failure_detail = $FailureDetail
        tests = @($summaryRows)
        final_driver_status = $FinalDriverStatus
    }

    $summaryPayload | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8

    Write-Step "Wrote regression summary files: $txtPath , $jsonPath"
}

function Invoke-Tool {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$Description
    )

    Write-Step $Description
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

function Invoke-PowerShellFile {
    param(
        [string]$ScriptPath,
        [string[]]$Arguments,
        [string]$Description
    )

    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $invokeArgs = @('-ExecutionPolicy', 'Bypass', '-File', $ScriptPath) + $Arguments
    Invoke-Tool -FilePath $psExe -Arguments $invokeArgs -Description $Description
}

function Invoke-ScActionSilently {
    param(
        [string]$Action,
        [string]$ServiceName
    )

    try {
        & sc.exe $Action $ServiceName | Out-Null
    }
    catch {
    }
}

function Import-TestCertificate {
    param([string]$CertificatePath)

    Write-Step "Importing test certificate: $CertificatePath"
    Import-Certificate -FilePath $CertificatePath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Import-Certificate -FilePath $CertificatePath -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
}

function Invoke-HostGuardStatusJson {
    param([string]$HostGuardExePath)

    $output = & $HostGuardExePath status --json 2>&1
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

function Wait-HostGuardReady {
    param(
        [string]$HostGuardExePath,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $statusEnvelope = Invoke-HostGuardStatusJson -HostGuardExePath $HostGuardExePath
            if ($statusEnvelope.driver_connected) {
                $driverStatus = $statusEnvelope.driver_status
                if ($null -eq $driverStatus) {
                    return $statusEnvelope
                }

                $protectionMode = [string]$driverStatus.protection_mode
                if ($protectionMode -eq 'monitor_only') {
                    return $statusEnvelope
                }

                if ($driverStatus.process_callback_registered -and $driverStatus.process_port_connected) {
                    return $statusEnvelope
                }
            }
        }
        catch {
        }

        Start-Sleep -Seconds 1
    }

    throw "HostGuard did not reach ready state within $TimeoutSeconds seconds."
}

function Remove-PreviousRuntimeArtifacts {
    param(
        [string]$TargetRootPath,
        [string]$ProgramDataRootPath
    )

    Write-Step 'Cleaning previous HostGuard/PebMonitor state'
    Invoke-ScActionSilently -Action 'stop' -ServiceName 'PebMonitor'
    Invoke-ScActionSilently -Action 'delete' -ServiceName 'PebMonitor'
    Invoke-ScActionSilently -Action 'stop' -ServiceName 'HostGuard'
    Invoke-ScActionSilently -Action 'delete' -ServiceName 'HostGuard'

    $pathsToRemove = @(
        (Join-Path $TargetRootPath 'hostguard-foreground.log'),
        (Join-Path $TargetRootPath 'events.jsonl'),
        (Join-Path $ProgramDataRootPath 'events.jsonl'),
        'C:\Windows\System32\drivers\DriverModule.sys'
    )

    foreach ($path in $pathsToRemove) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function Stop-AndRemoveHostGuardService {
    param([string]$HostGuardExePath)

    if (Test-Path $HostGuardExePath) {
        try {
            & $HostGuardExePath stop | Out-Null
        }
        catch {
        }

        try {
            & $HostGuardExePath uninstall | Out-Null
        }
        catch {
        }
    }

    Invoke-ScActionSilently -Action 'stop' -ServiceName 'PebMonitor'
    Invoke-ScActionSilently -Action 'delete' -ServiceName 'PebMonitor'
    Invoke-ScActionSilently -Action 'stop' -ServiceName 'HostGuard'
    Invoke-ScActionSilently -Action 'delete' -ServiceName 'HostGuard'
}

$bundleRoot = $PSScriptRoot
$deployScriptPath = Join-Path $bundleRoot 'Deploy-TestBundle.ps1'
$targetHostGuardExe = Join-Path $TargetRoot 'HostGuard.exe'
$targetCertPath = Join-Path $TargetRoot 'DriverModule.cer'
$targetProcessObservedScript = Join-Path $TargetRoot 'ProcessObservedTests.ps1'
$targetFileInteropScript = Join-Path $TargetRoot 'FileInteropTests.ps1'
$targetFileProtectionCounterScript = Join-Path $TargetRoot 'FileProtectionRuntimeCountersTests.ps1'
$targetRuntimeCountersScript = Join-Path $TargetRoot 'StatusRuntimeCountersTests.ps1'
$targetRegistryBatchSyncScript = Join-Path $TargetRoot 'RegistryBatchSyncTests.ps1'
$targetRegistryRuleScaleScript = Join-Path $TargetRoot 'RegistryRuleScaleTests.ps1'
$targetRegistryRuleOrderScript = Join-Path $TargetRoot 'RegistryRuleOrderTests.ps1'
$targetRegistryRollbackScript = Join-Path $TargetRoot 'RegistryRollbackTests.ps1'
$targetRegistryInteropScript = Join-Path $TargetRoot 'RegistryInteropTests.ps1'
$targetLifecycleStressScript = Join-Path $TargetRoot 'LifecycleStressTests.ps1'
$regressionResults = Initialize-RegressionResultMap
$finalDriverStatusSnapshot = $null

Write-Step "Bundle root: $bundleRoot"
Write-Step "Target root: $TargetRoot"
Write-Step "ProgramData root: $ProgramDataRoot"
Write-Step "Active rule file: $RuleFile"

if ($PlanOnly) {
    Write-Step 'PlanOnly enabled. The script will not make any system changes.'
    Write-Host ''
    Write-Host 'Planned steps:' -ForegroundColor Cyan
    Write-Host '1. Optional cleanup of old HostGuard/PebMonitor services and previous logs'
    Write-Host '2. Optional Deploy-TestBundle.ps1 execution'
    Write-Host '3. Optional test certificate import'
    Write-Host '4. HostGuard service install/start'
    Write-Host '5. Wait for status --json ready state'
    Write-Host '6. Optional ProcessObservedTests.ps1'
    Write-Host '7. Optional FileInteropTests.ps1'
    Write-Host '8. Optional FileProtectionRuntimeCountersTests.ps1'
    Write-Host '9. Optional StatusRuntimeCountersTests.ps1'
    Write-Host '10. Optional RegistryBatchSyncTests.ps1'
    Write-Host '11. Optional RegistryRuleScaleTests.ps1'
    Write-Host '12. Optional RegistryRuleOrderTests.ps1'
    Write-Host '13. Optional RegistryRollbackTests.ps1'
    Write-Host '14. Optional RegistryInteropTests.ps1'
    Write-Host '15. Optional LifecycleStressTests.ps1'
    Write-Host '16. Optional stop/uninstall cleanup'
    return
}

if (-not $SkipCleanup) {
    Remove-PreviousRuntimeArtifacts -TargetRootPath $TargetRoot -ProgramDataRootPath $ProgramDataRoot
}

if (-not $SkipDeploy) {
    if (-not (Test-Path $deployScriptPath)) {
        throw "Deploy-TestBundle.ps1 not found in $bundleRoot. Run from the bundle directory or pass -SkipDeploy."
    }

    Invoke-PowerShellFile -ScriptPath $deployScriptPath -Arguments @(
        '-TargetRoot', $TargetRoot,
        '-ProgramDataRoot', $ProgramDataRoot,
        '-RuleFile', $RuleFile
    ) -Description 'Deploying test bundle to target root'
}

if (-not (Test-Path $targetHostGuardExe)) {
    throw "HostGuard.exe not found at target path: $targetHostGuardExe"
}

if (-not $SkipCertificateImport) {
    if (-not (Test-Path $targetCertPath)) {
        throw "DriverModule.cer not found at target path: $targetCertPath"
    }

    Import-TestCertificate -CertificatePath $targetCertPath
}

Invoke-Tool -FilePath $targetHostGuardExe -Arguments @('install') -Description 'Installing HostGuard service'
Invoke-Tool -FilePath $targetHostGuardExe -Arguments @('start') -Description 'Starting HostGuard service'

$readyStatus = $null
$runSucceeded = $false
$failureMessage = ''
try {
    $readyStatus = Wait-HostGuardReady -HostGuardExePath $targetHostGuardExe -TimeoutSeconds $ReadyTimeoutSeconds
    Write-Success 'HostGuard status --json reported ready state.'

    if (-not $SkipProcessObserved) {
        if (-not (Test-Path $targetProcessObservedScript)) {
            throw "ProcessObservedTests.ps1 not found at target path: $targetProcessObservedScript"
        }

        Invoke-PowerShellFile -ScriptPath $targetProcessObservedScript -Arguments @() -Description 'Running observed process telemetry regression'
        Set-RegressionResult -Results $regressionResults -Name 'ProcessObservedTests.ps1' -Status 'PASS' -Detail 'Executed successfully.'
    }
    else {
        Set-RegressionResult -Results $regressionResults -Name 'ProcessObservedTests.ps1' -Status 'SKIP' -Detail 'Skipped by -SkipProcessObserved.'
    }

    if (-not $SkipFileInterop) {
        if (-not (Test-Path $targetFileInteropScript)) {
            throw "FileInteropTests.ps1 not found at target path: $targetFileInteropScript"
        }

        Invoke-PowerShellFile -ScriptPath $targetFileInteropScript -Arguments @() -Description 'Running protected-file interop regression'
        Set-RegressionResult -Results $regressionResults -Name 'FileInteropTests.ps1' -Status 'PASS' -Detail 'Executed successfully.'
    }
    else {
        Set-RegressionResult -Results $regressionResults -Name 'FileInteropTests.ps1' -Status 'SKIP' -Detail 'Skipped by -SkipFileInterop.'
    }

    if (-not $SkipFileProtectionCounters) {
        if (-not (Test-Path $targetFileProtectionCounterScript)) {
            throw "FileProtectionRuntimeCountersTests.ps1 not found at target path: $targetFileProtectionCounterScript"
        }

        Invoke-PowerShellFile -ScriptPath $targetFileProtectionCounterScript -Arguments @(
            '-HostGuardPath', $targetHostGuardExe
        ) -Description 'Running file-protection runtime counter regression'
        Set-RegressionResult -Results $regressionResults -Name 'FileProtectionRuntimeCountersTests.ps1' -Status 'PASS' -Detail 'Executed successfully.'
    }
    else {
        Set-RegressionResult -Results $regressionResults -Name 'FileProtectionRuntimeCountersTests.ps1' -Status 'SKIP' -Detail 'Skipped by -SkipFileProtectionCounters.'
    }

    if (-not $SkipRuntimeCounters) {
        if (-not (Test-Path $targetRuntimeCountersScript)) {
            throw "StatusRuntimeCountersTests.ps1 not found at target path: $targetRuntimeCountersScript"
        }

        Invoke-PowerShellFile -ScriptPath $targetRuntimeCountersScript -Arguments @(
            '-HostGuardPath', $targetHostGuardExe,
            '-RepeatCount', $RepeatCount
        ) -Description 'Running runtime counter regression'
        Set-RegressionResult -Results $regressionResults -Name 'StatusRuntimeCountersTests.ps1' -Status 'PASS' -Detail 'Executed successfully.'
    }
    else {
        Set-RegressionResult -Results $regressionResults -Name 'StatusRuntimeCountersTests.ps1' -Status 'SKIP' -Detail 'Skipped by -SkipRuntimeCounters.'
    }

    if (-not $SkipRegistryBatchSync) {
        if (-not (Test-Path $targetRegistryBatchSyncScript)) {
            throw "RegistryBatchSyncTests.ps1 not found at target path: $targetRegistryBatchSyncScript"
        }

        Invoke-PowerShellFile -ScriptPath $targetRegistryBatchSyncScript -Arguments @(
            '-HostGuardPath', $targetHostGuardExe
        ) -Description 'Running registry batch-sync hot reload regression'
        Set-RegressionResult -Results $regressionResults -Name 'RegistryBatchSyncTests.ps1' -Status 'PASS' -Detail 'Executed successfully.'
    }
    else {
        Set-RegressionResult -Results $regressionResults -Name 'RegistryBatchSyncTests.ps1' -Status 'SKIP' -Detail 'Skipped by -SkipRegistryBatchSync.'
    }

    if (-not $SkipRegistryRuleScale) {
        if (-not (Test-Path $targetRegistryRuleScaleScript)) {
            throw "RegistryRuleScaleTests.ps1 not found at target path: $targetRegistryRuleScaleScript"
        }

        Invoke-PowerShellFile -ScriptPath $targetRegistryRuleScaleScript -Arguments @(
            '-HostGuardPath', $targetHostGuardExe
        ) -Description 'Running registry dynamic-scale hot reload regression'
        Set-RegressionResult -Results $regressionResults -Name 'RegistryRuleScaleTests.ps1' -Status 'PASS' -Detail 'Executed successfully.'
    }
    else {
        Set-RegressionResult -Results $regressionResults -Name 'RegistryRuleScaleTests.ps1' -Status 'SKIP' -Detail 'Skipped by -SkipRegistryRuleScale.'
    }

    if (-not $SkipRegistryRuleOrder) {
        if (-not (Test-Path $targetRegistryRuleOrderScript)) {
            throw "RegistryRuleOrderTests.ps1 not found at target path: $targetRegistryRuleOrderScript"
        }

        Invoke-PowerShellFile -ScriptPath $targetRegistryRuleOrderScript -Arguments @(
            '-HostGuardPath', $targetHostGuardExe
        ) -Description 'Running registry rule order regression'
        Set-RegressionResult -Results $regressionResults -Name 'RegistryRuleOrderTests.ps1' -Status 'PASS' -Detail 'Executed successfully.'
    }
    else {
        Set-RegressionResult -Results $regressionResults -Name 'RegistryRuleOrderTests.ps1' -Status 'SKIP' -Detail 'Skipped by -SkipRegistryRuleOrder.'
    }

    if (-not $SkipRegistryRollback) {
        if (-not (Test-Path $targetRegistryRollbackScript)) {
            throw "RegistryRollbackTests.ps1 not found at target path: $targetRegistryRollbackScript"
        }

        Invoke-PowerShellFile -ScriptPath $targetRegistryRollbackScript -Arguments @(
            '-HostGuardPath', $targetHostGuardExe
        ) -Description 'Running registry rollback hot reload regression'
        Set-RegressionResult -Results $regressionResults -Name 'RegistryRollbackTests.ps1' -Status 'PASS' -Detail 'Executed successfully.'
    }
    else {
        Set-RegressionResult -Results $regressionResults -Name 'RegistryRollbackTests.ps1' -Status 'SKIP' -Detail 'Skipped by -SkipRegistryRollback.'
    }

    if (-not $SkipRegistryInterop) {
        if (-not (Test-Path $targetRegistryInteropScript)) {
            throw "RegistryInteropTests.ps1 not found at target path: $targetRegistryInteropScript"
        }

        Invoke-PowerShellFile -ScriptPath $targetRegistryInteropScript -Arguments @() -Description 'Running registry interop regression'
        Set-RegressionResult -Results $regressionResults -Name 'RegistryInteropTests.ps1' -Status 'PASS' -Detail 'Executed successfully.'
    }
    else {
        Set-RegressionResult -Results $regressionResults -Name 'RegistryInteropTests.ps1' -Status 'SKIP' -Detail 'Skipped by -SkipRegistryInterop.'
    }

    if (-not $SkipLifecycleStress) {
        if (-not (Test-Path $targetLifecycleStressScript)) {
            throw "LifecycleStressTests.ps1 not found at target path: $targetLifecycleStressScript"
        }

        Invoke-PowerShellFile -ScriptPath $targetLifecycleStressScript -Arguments @(
            '-HostGuardPath', $targetHostGuardExe
        ) -Description 'Running HostGuard lifecycle stress regression'
        Set-RegressionResult -Results $regressionResults -Name 'LifecycleStressTests.ps1' -Status 'PASS' -Detail 'Executed successfully.'
    }
    else {
        Set-RegressionResult -Results $regressionResults -Name 'LifecycleStressTests.ps1' -Status 'SKIP' -Detail 'Skipped by -SkipLifecycleStress.'
    }

    $finalStatus = Invoke-HostGuardStatusJson -HostGuardExePath $targetHostGuardExe
    if ($finalStatus.driver_connected -and $null -ne $finalStatus.driver_status) {
        $driverStatus = $finalStatus.driver_status
        $finalDriverStatusSnapshot = [pscustomobject]@{
            ProtectionMode = [string]$driverStatus.protection_mode
            PolicyEpoch = [UInt64]$driverStatus.policy_epoch
            Requests = [UInt64]$driverStatus.process_verdict_request_count
            FastPathHits = [UInt64]$driverStatus.fast_path_hit_count
            CacheHits = [UInt64]$driverStatus.cache_hit_count
            CacheMisses = [UInt64]$driverStatus.cache_miss_count
            CacheFlushes = [UInt64]$driverStatus.cache_flush_count
            SlowPath = [UInt64]$driverStatus.slow_path_count
            FileProtectionBlocks = if ($null -ne $driverStatus.PSObject.Properties['file_protection_block_count']) { [UInt64]$driverStatus.file_protection_block_count } else { [UInt64]0 }
            FileProtectionCreateBlocks = if ($null -ne $driverStatus.PSObject.Properties['file_protection_create_block_count']) { [UInt64]$driverStatus.file_protection_create_block_count } else { [UInt64]0 }
            FileProtectionSetInfoBlocks = if ($null -ne $driverStatus.PSObject.Properties['file_protection_set_information_block_count']) { [UInt64]$driverStatus.file_protection_set_information_block_count } else { [UInt64]0 }
            LastFileProtectionInfoClass = if ($null -ne $driverStatus.PSObject.Properties['last_file_protection_info_class']) { [string]$driverStatus.last_file_protection_info_class } else { '' }
        }
        Write-Host ''
        $finalDriverStatusSnapshot | Format-Table -AutoSize
    }

    $runSucceeded = $true
}
catch {
    $failureMessage = $_.Exception.Message

    foreach ($entry in $regressionResults.GetEnumerator()) {
        if ([string]$entry.Value.Status -eq 'SKIP' -and [string]$entry.Value.Detail -eq 'Not executed.') {
            Set-RegressionResult -Results $regressionResults -Name $entry.Key -Status 'SKIP' -Detail 'Not reached because the run stopped earlier.'
        }
    }

    $failedTestName = $null
    if ($failureMessage -match '([A-Za-z0-9_-]+Tests\.ps1)') {
        $failedTestName = $Matches[1]
    }
    elseif ($failureMessage -match '([A-Za-z0-9_-]+\.ps1)') {
        $failedTestName = $Matches[1]
    }

    if (-not [string]::IsNullOrWhiteSpace($failedTestName) -and $regressionResults.Contains($failedTestName)) {
        Set-RegressionResult -Results $regressionResults -Name $failedTestName -Status 'FAIL' -Detail $failureMessage
    }

    throw
}
finally {
    Write-RegressionSummary -Results $regressionResults
    Write-RegressionSummaryFiles `
        -Results $regressionResults `
        -TargetRootPath $TargetRoot `
        -ProgramDataRootPath $ProgramDataRoot `
        -RuleFileName $RuleFile `
        -Succeeded $runSucceeded `
        -FailureDetail $failureMessage `
        -FinalDriverStatus $finalDriverStatusSnapshot

    if (-not $LeaveInstalled) {
        Stop-AndRemoveHostGuardService -HostGuardExePath $targetHostGuardExe
    }
}

if ($runSucceeded) {
    Write-Host ''
    Write-Success 'Bundle deployment and regression validation completed.'
}
