#-------------------------------------------------------------------------------
# SCCMReinstall.ps1
#-------------------------------------------------------------------------------
# Autor: Alan Kordel
# Data: 2025-09-10
# Descrição: Script para reinstalação do agente SCCM/MECM (ccmsetup) com etapas de
#            limpeza prévia, download do pacote, instalação e validação.
# Observações: Personalize parâmetros no topo do script (MP, SiteCode, paths) conforme
#              ambiente antes de executar. Execute como Administrador.
# Licença: MIT (SPDX: MIT)
#-------------------------------------------------------------------------------


#Step 1 Logs and Paths
$ErrorActionPreference = "Stop"
$delayedRegistryCleanup = $true

$downloadPath = "C:\Temp\SCCMReinstall.zip"
$extractPath = "C:\Temp\SCCMReinstall"
$logPath = "$extractPath\SCCMClientInstall.log"
$innerFolder = Join-Path $extractPath "SCCM Reinstall"
$ccmSetupPath = Join-Path $innerFolder "ccmsetup.exe"



function Write-Log($message) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logDir = Split-Path $logPath
    if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

    $formattedMessage = "$timestamp`t$message"
    
    # Show in console
    Write-Output $formattedMessage

    # Save to file
    $formattedMessage | Out-File -Append -FilePath $logPath
}

# Add the required type to call SetThreadExecutionState
Add-Type -Namespace WinAPI -Name Power -MemberDefinition @'
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SetThreadExecutionState(uint esFlags);
'@ -Language CSharp -ErrorAction SilentlyContinue

# Use [Convert] to avoid casting issues
$ES_CONTINUOUS        = [Convert]::ToUInt32("0x80000000", 16)
$ES_SYSTEM_REQUIRED   = [Convert]::ToUInt32("0x00000001", 16)
$ES_AWAYMODE_REQUIRED = [Convert]::ToUInt32("0x00000040", 16)

# Combine flags to keep system fully awake
$flags = $ES_CONTINUOUS -bor $ES_SYSTEM_REQUIRED -bor $ES_AWAYMODE_REQUIRED
$result = [WinAPI.Power]::SetThreadExecutionState($flags)

# Log result
if ($result -ne 0) {
    Write-Log "Sleep prevention enabled. System will stay awake during execution."
} else {
    Write-Log "Failed to set execution state. Sleep may occur if power policy overrides it."
}

function Restore-SCCMSecurityKey {
    $securityPath = "HKLM:\SOFTWARE\Microsoft\CCM\Security"

    Write-Log "Checking for missing CCM\Security registry key structure..."

    if (-not (Test-Path $securityPath)) {
        Write-Log "Creating missing CCM\Security key..."
        New-Item -Path $securityPath -Force | Out-Null
    }

    # Restore essential keys
    Set-ItemProperty -Path $securityPath -Name "ClientAlwaysOnInternet" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $securityPath -Name "UseDefaultMP" -Value 0 -Type DWord -Force

    Write-Log "Restored essential registry values under CCM\Security"
}


function Check-OrphanedSCCMMsi {
    Write-Log "Checking for orphaned SCCM MSI installations..."
    try {
        $orphans = Get-WmiObject Win32_Product | Where-Object { $_.Name -like "*Configuration Manager*" }

        if ($orphans.Count -eq 0) {
            Write-Log "No orphaned SCCM MSI installations found."
        } else {
            foreach ($entry in $orphans) {
                Write-Log "Found orphaned product: $($entry.Name) [$($entry.IdentifyingNumber)]"
                Write-Log "Attempting silent removal..."
                Start-Process -FilePath "msiexec.exe" -ArgumentList "/x", "$($entry.IdentifyingNumber)", "/qn" -Wait
                Write-Log "Successfully removed orphaned product."
            }
        }
    } catch {
        Write-Log "Error checking or removing orphaned MSI: $($_.Exception.Message)"
    }
}




function Remove-OrphanedSCCMInstallations {
    Write-Log "Scanning hidden installer DB for orphaned SCCM products..."

    $keys = Get-ChildItem "HKLM:\SOFTWARE\Classes\Installer\Products" -ErrorAction SilentlyContinue
    foreach ($key in $keys) {
        try {
            $props = Get-ItemProperty -Path $key.PSPath
            if ($props.ProductName -like "*Configuration Manager*") {
                Write-Log "Found leftover installer entry: $($props.ProductName). Attempting forced removal..."
                Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Successfully removed $($props.ProductName) from installer DB."
            }
        } catch {
            Write-Log "Failed to process key: $($key.Name): $($_.Exception.Message)"
        }
    }
}


function Remove-ConfigMgrMSI {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.DisplayName -like "*Configuration Manager*") {
                $uninstallCmd = $_.UninstallString
                if ($uninstallCmd -and $uninstallCmd -like "msiexec*") {
                    Write-Log "Uninstalling leftover SCCM client from: $($_.DisplayName)"
                    try {
                        # Ensure silent uninstall
                        $silentCmd = $uninstallCmd -replace "/I", "/X"
                        if ($silentCmd -notmatch "/quiet") {
                            $silentCmd += " /qn"
                        }

                        Start-Process -FilePath "cmd.exe" -ArgumentList "/c $silentCmd" -Wait -WindowStyle Hidden
                        Write-Log "Uninstall command executed: $silentCmd"
                    } catch {
                        Write-Log "Failed to uninstall $($_.DisplayName): $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}

function Remove-ConflictingVCRedists {
    Write-Log "Checking for conflicting VC++ Redistributables before SCCM install..."

    $vcNames = @(
        "Microsoft Visual C++ 2008",
        "Microsoft Visual C++ 2010",
        "Microsoft Visual C++ 2012",
        "Microsoft Visual C++ 2013",
        "Microsoft Visual C++ 2015",
        "Microsoft Visual C++ 2017",
        "Microsoft Visual C++ 2019",
        "Microsoft Visual C++ 2022"
    )

    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $foundVCs = @()
    foreach ($path in $uninstallPaths) {
        $foundVCs += Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath
            if ($vcNames | Where-Object { $props.DisplayName -like "$_*" }) {
                $props
            }
        }
    }

    Write-Log "Found $($foundVCs.Count) VC++ redist(s) to remove"

    foreach ($vc in $foundVCs) {
        try {
            Write-Log "Uninstalling: $($vc.DisplayName)"
            $uninstallString = $vc.UninstallString

            if ($uninstallString) {
                if ($uninstallString -match '^\{[\w\d\-]+\}$') {
                    $uninstallString = "msiexec.exe /x $uninstallString /quiet /norestart"
                }
                elseif ($uninstallString -match 'msiexec\.exe') {
                    if ($uninstallString -notmatch "/quiet") {
                        $uninstallString += " /quiet /norestart"
                    }
                }
                elseif ($uninstallString -match '\.exe.+/uninstall') {
                    $uninstallString = "`"$uninstallString`" /quiet /norestart"
                }
                else {
                    Write-Log "Unrecognized uninstall format: $uninstallString - skipping"
                    continue
                }

                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $uninstallString" -WindowStyle Hidden -Wait
            } else {
                Write-Log "No uninstall string found for $($vc.DisplayName)"
            }
        }
        catch {
            Write-Log "Failed to uninstall $($vc.DisplayName): $_"
        }
    }

    # Wait for msiexec.exe to finish
    $perUninstallTimeout = 300
    $totalTimeout = $perUninstallTimeout * $foundVCs.Count
    $elapsed = 0

    Write-Log "Waiting for lingering msiexec.exe processes (timeout: $($totalTimeout / 60) minutes)..."
    while (Get-Process msiexec -ErrorAction SilentlyContinue) {
        if ($elapsed -ge $totalTimeout) {
            Write-Log "msiexec.exe still running after $elapsed seconds - continuing anyway."
            break
        }
        Write-Log "msiexec.exe still running... waiting 60 seconds"
        Write-Log "Elapsed: $elapsed sec / $totalTimeout sec"
        Start-Sleep -Seconds 60
        $elapsed += 60
    }

    Write-Log "msiexec.exe has exited or timeout reached."
}


# Software Center Client Health Check
function Test-SCCMClientHealth {
    Write-Log "Running strict health check on SCCM client..."

    # Initialize containers for errors and warnings
    $errors = @()
    $warnings = @()

    try {
        # 1. Check if CcmExec service exists and is running
        $svc = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Log "CcmExec service is completely missing."
            return $false
        }
        if ($svc.Status -ne 'Running') {
            Write-Log "CcmExec service exists but is not running."
            return $false
        }

        # 2. Check critical folders
        $requiredFolders = @("C:\Windows\CCM", "C:\Windows\CCMSetup", "C:\Windows\ccmcache")
        foreach ($folder in $requiredFolders) {
            if (-not (Test-Path $folder)) {
                Write-Log "Missing folder: $folder"
                return $false
            }
        }

        # 3. Check registry key
        if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\CCM")) {
            Write-Log "CCM registry key is missing"
            return $false
        }

        # 4. Check if WMI namespace exists
        try {
            Get-CimInstance -Namespace "root\ccm" -ClassName "__Namespace" -ErrorAction Stop
        } catch {
            Write-Log "WMI namespace root\\ccm is missing or broken: $($_.Exception.Message)"
            return $false
        }

        # 5. Query client WMI class
        try {
            $client = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction Stop
        } catch {
            Write-Log "SMS_Client WMI class not found: $($_.Exception.Message)"
            return $false
        }

        if (-not $client) {
            Write-Log "SMS_Client WMI object is null."
            return $false
        }

        # 6. Validate version and site code
        $version = $client.ClientVersion
        $assignedSite = $client.AssignedSiteCode

        if (-not $version -or $version -eq "0.0.0.0" -or $version.Length -lt 5) {
            Write-Log "Invalid SCCM client version: $version"
            return $false
        }

        if ($null -ne $assignedSite -and $assignedSite.Length -gt 1 -and $assignedSite -ne "000") {
            Write-Log "Valid site code: $assignedSite"
        } else {
            Write-Log "Site code is missing or not set yet - waiting for client to finish registration."
        }

        Write-Log "Detected version: $version, site code: $assignedSite"

        # 7. Optional MP info
        try {
            $mp = Get-WmiObject -Namespace "root\ccm" -Class "CCM_ManagementPoint" -ErrorAction Stop
            if ($mp) {
                Write-Log "Detected MP assignment: $($mp.ServerName)"
            }
        } catch {
            Write-Log "MP assignment info not found in WMI - skipping, this is not a health failure."
        }

        # 8. Check for known setup errors
        $ccmLogPath = "C:\Windows\ccmsetup\Logs\ccmsetup.log"
        if (Test-Path $ccmLogPath) {
            $failures = Select-String -Path $ccmLogPath -Pattern "CcmSetup failed with error code" -SimpleMatch -ErrorAction SilentlyContinue
            if ($failures) {
                Write-Log "ccmsetup.log shows failed install"
                return $false
            }

            $mpMissing = Select-String -Path $ccmLogPath -Pattern "No valid source or MP locations" -SimpleMatch -ErrorAction SilentlyContinue
            if ($mpMissing) {
                Write-Log "ccmsetup.log reports no MP found"
                return $false
            }
        }

        # 9. Check Client GUID from WMI
        $client = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction SilentlyContinue
        $clientId = $null
        
        if ($client -and $client.PSObject.Properties.Match("ClientGUID").Count -gt 0) {
            $clientId = $client.ClientGUID
        }
        
        if (-not $clientId) {
            Write-Log "Warning: Client GUID is missing. Likely still initializing."
            $warnings += "Missing Client GUID (WMI SMS_Client)"
        } else {
            Write-Log "Client GUID: $clientId"
        }
        
        

        # 10. Policy check
        try {
            $policy = Get-CimInstance -Namespace "root\ccm\Policy\Machine\RequestedConfig" -ClassName "CCM_Scheduler_History" -ErrorAction Stop
            $policyCount = $policy.Count
            Write-Log "Client has $policyCount policies available."
            if ($policyCount -lt 3) {
                Write-Log "Too few policy actions available. Client not fully initialized."
                $errors += "Too few policy actions ($policyCount)"
            }
        } catch {
            Write-Log "Warning: Policy WMI query failed - likely still initializing: $($_.Exception.Message)"
            $warnings += "Policy WMI class not ready"
        }
        

        # --- FINAL HEALTH DECISION ---
        if ($errors.Count -eq 0) {
            if ($warnings.Count -gt 0) {
                Write-Log "SCCM Client Health Passed (with warnings):"
                $warnings | ForEach-Object { Write-Log "$_" }
            } else {
                Write-Log "SCCM Client Health Passed (fully healthy)"
            }
            return $true
        } else {
            Write-Log "SCCM Client Health Check Failed:"
            $errors | ForEach-Object { Write-Log "$_" }
            return $false
        }

    } catch {
        Write-Log "Health check threw exception: $($_.Exception.Message)"
        return $false
    }
}


function Test-IntranetConnectivity {
    $knownIntranetMP = "SEGOTN19802.vcn.ds.volvo.net"
    try {
        $ping = Test-Connection -ComputerName $knownIntranetMP -Count 1 -Quiet -TimeoutSeconds 3
        return $ping
    } catch {
        return $false
    }
}



$secPath = "HKLM:\SOFTWARE\Microsoft\CCM\Security"
$backupFile = "C:\Temp\Backup_CCM_Security.reg"

if (Test-Path $secPath) {
    Write-Log "Backing up CCM\Security registry key..."
    reg export "HKLM\SOFTWARE\Microsoft\CCM\Security" $backupFile /y | Out-Null
    Write-Log "Security key exported to $backupFile"
} else {
    Write-Log "Security key not found. Skipping export."
}


function Get-BestMPAndSiteCode {
    $mpList = @(
        "AUBNEN024.VCN.DS.VOLVO.NET",
        "AUSYDN032.VCN.DS.VOLVO.NET",
        "BRCTAN334.VCN.DS.VOLVO.NET",
        "BRCTAN510.VCN.DS.VOLVO.NET",
        "FRLYONN423.VCN.DS.VOLVO.NET",
        "FRLYONN698.VCN.DS.VOLVO.NET",
        "JPSAITN101.VCN.DS.VOLVO.NET",
        "JPSAITN251.VCN.DS.VOLVO.NET",
        "JPSAITN760.VCN.DS.VOLVO.NET",
        "SEGOTN12255.VCN.DS.VOLVO.NET",
        "SEGOTN12424.VCN.DS.VOLVO.NET",
        "SEGOTN12527.VCN.DS.VOLVO.NET",
        "SEGOTN15657.VCN.DS.VOLVO.NET",
        "SEGOTN19802.VCN.DS.VOLVO.NET",
        "SEGOTN19804.VCN.DS.VOLVO.NET",
        "SEGOTN19806.VCN.DS.VOLVO.NET",
        "SEGOTN19807.VCN.DS.VOLVO.NET",
        "SEGOTN19808.VCN.DS.VOLVO.NET",
        "SEGOTN19809.VCN.DS.VOLVO.NET",
        "USGSON10122.VCN.DS.VOLVO.NET",
        "USGSON10213.VCN.DS.VOLVO.NET",
        "USGSON10450.VCN.DS.VOLVO.NET",
        "USGSON2162.VCN.DS.VOLVO.NET",
        "ZAMIDRN002.VCN.DS.VOLVO.NET"
    )

    $siteMapping = @{
        "SE" = "PAP"
        "IN" = "PAP"
        "FR" = "PBP"
        "BR" = "PGP"
        "ZA" = "PFP"
        "AU" = "PEP"
        "JP" = "PDP"
        "US" = "PCP"
    }

    $result = @()
    foreach ($mp in $mpList) {
        $ping = Test-Connection -ComputerName $mp -Count 1 -Quiet -ErrorAction SilentlyContinue
        $latency = $null
        if ($ping) {
            $latency = (Test-Connection -ComputerName $mp -Count 1 -ErrorAction SilentlyContinue).ResponseTime
        }

        $https = Test-NetConnection -ComputerName $mp -Port 443 -WarningAction SilentlyContinue

        $result += [PSCustomObject]@{
            Hostname    = $mp
            PingSuccess = $ping
            LatencyMS   = $latency
            HttpsOpen   = $https.TcpTestSucceeded
            IPAddress   = $https.RemoteAddress
        }
    }

    $bestMP = $result | Where-Object { $_.PingSuccess -and $_.HttpsOpen } | Sort-Object LatencyMS | Select-Object -First 1

    if ($bestMP) {
        $countryCode = ($bestMP.Hostname -split '\.')[0].Substring(0,2)
        $siteCode = $siteMapping[$countryCode]
        return [PSCustomObject]@{
            BestMP   = "https://$($bestMP.Hostname)"
            SiteCode = $siteCode
        }
    }

    return $null
}

function Uninstall-StuckSCCMMSI {
    Write-Log "Checking for stuck SCCM MSI registrations..."
    $found = $false

    $installerPaths = @(
        "HKLM:\SOFTWARE\Classes\Installer\Products",                       # 64-bit view
        "Registry::HKLM\SOFTWARE\WOW6432Node\Classes\Installer\Products"  # 32-bit view
    )

    foreach ($installerKey in $installerPaths) {
        if (Test-Path $installerKey) {
            Get-ChildItem $installerKey | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($props.ProductName -like "*Configuration Manager*") {
                    $productCode = $_.PSChildName
                    $guid = $productCode -replace '(.{8})(.{4})(.{4})(.{2})(.{2})(.*)', '{$1-$2-$3-$4$5-$6}'
                    Write-Log "Found stuck SCCM MSI: $($props.ProductName) - $guid"
                    $args = "/x $guid /qn"
                    try {
                        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
                        Write-Log "Uninstall exit code: $($proc.ExitCode)"
                        $found = $true
                    } catch {
                        $errMsg = $_.Exception.Message
                        Write-Log "Failed to uninstall MSI GUID $($guid): $($errMsg)"
                    }                                   
                }
            }
        } else {
            Write-Log "Installer registry path not found: $installerKey. Skipping..."
        }
    }

    if (-not $found) {
        Write-Log "No stuck SCCM MSI registrations found."
    }
}



# Pre-Check: Check if the computer certificate is valid
Write-Log "Starting Pre-Check: Verifying computer certificate validity"
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Issuer -like "*Volvo Group Class2 Issuing CA3*" }

if ($cert) {
    Write-Log "Certificate is valid and issued by Volvo Group Class2 Issuing CA3."
} else {
    Write-Log "Certificate is not valid or not issued by Volvo Group Class2 Issuing CA3. Attempting to request and install the certificate."

    # Automatically trigger the enrollment of the certificate
    $certEnrollCmd = "certutil -pulse"
    Write-Log "Running certutil to enroll the certificate"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $certEnrollCmd" -Wait

    # Verify again after enrollment
    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Issuer -like "*Volvo Group Class2 Issuing CA3*" }
    if ($cert) {
        Write-Log "Volvo_Computer_Certificate successfully installed."
    } else {
        Write-Log "Failed to install the Volvo_Computer_Certificate."
        Exit
    }
}


# Deep health check and decision
Write-Log "Running initial deep SCCM health check before proceeding..."
$initialHealth = Test-SCCMClientHealth

if ($initialHealth -eq $true) {
    Write-Log "SCCM client is healthy. Skipping reinstall and proceeding with safe repair actions."

    # 1. Ensure CcmExec is running
    Write-Log "Ensuring CcmExec service is running..."
    $ccmExecService = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue
    if ($ccmExecService -and $ccmExecService.Status -ne 'Running') {
        Start-Service -Name "CcmExec" -ErrorAction SilentlyContinue
        Write-Log "CcmExec service started."
        Start-Sleep -Seconds 10
    } elseif (-not $ccmExecService) {
        Write-Log "CcmExec service not found, cannot trigger policy schedules."
        exit 1
    } else {
        Write-Log "CcmExec service is already running."
    }

    # Optional site code reassignment if current is outdated
    try {
        $client = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction Stop
        $currentSiteCode = $client.AssignedSiteCode
        $best = Get-BestMPAndSiteCode

        if ($best -and $best.SiteCode -and $currentSiteCode -ne $best.SiteCode) {
            Write-Log "Current site code is $currentSiteCode, reassigning to $($best.SiteCode)..."
            Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "SetAssignedSite" -ArgumentList $best.SiteCode | Out-Null
            Write-Log "Site reassignment requested successfully."
        } else {
            Write-Log "Site code is already correct or reassignment not required."
        }
    } catch {
        Write-Log "Failed to evaluate or reassign site code: $($_.Exception.Message)"
    }


    # 2. Rebuild SCCM cache folder if empty or corrupted
    Write-Log "Checking if CCMCache needs to be fixed"
    $cachePath = "C:\Windows\ccmcache"
    if ((Test-Path $cachePath) -and ((Get-ChildItem $cachePath -ErrorAction SilentlyContinue).Count -eq 0)) {
        Write-Log "CCMCache folder exists but is empty. Rebuilding cache folder..."
        try {
            Remove-Item -Path $cachePath -Recurse -Force -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Path $cachePath | Out-Null
            Write-Log "Rebuilt CCMCache folder."
        } catch {
            Write-Log "Failed to rebuild CCMCache: $($_.Exception.Message)"
        }
    }

    # 3. Clean up legacy retry or upgrade tasks if they exist
    try {
        schtasks /Delete /TN "Microsoft\Microsoft\Configuration Manager\Configuration Manager Client Retry Task" /F 2>$null | Out-Null
        Write-Log "Removed Retry Task if it existed."
    } catch {
        Write-Log "Retry Task cleanup failed or not found: $($_.Exception.Message)"
    }

    try {
        schtasks /Delete /TN "Microsoft\Microsoft\Configuration Manager\Configuration Manager Client Upgrade Task" /F 2>$null | Out-Null
        Write-Log "Removed Upgrade Task if it existed."
    } catch {
        Write-Log "Upgrade Task cleanup failed or not found: $($_.Exception.Message)"
    }


    # remediation polish - only if not already running
    $remediateExe = "C:\Windows\ccmsetup\cache\ccmsetup.exe"
    $remediateRunning = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'ccmsetup.exe'" | Where-Object {
        $_.CommandLine -like "*remediate:client*"
    }

    if ((Test-Path $remediateExe) -and (-not $remediateRunning)) {
        Write-Log "Triggering final SCCM client remediation using /remediate:client"
        try {
            Start-Process -FilePath $remediateExe -ArgumentList "/remediate:client" -WindowStyle Hidden
        } catch {
            Write-Log "Failed to start SCCM client remediation: $($_.Exception.Message)"
        }
    } elseif ($remediateRunning) {
        Write-Log "Remediation already in progress. Skipping manual /remediate:client trigger."
    } else {
        Write-Log "Remediation skipped - ccmsetup.exe not found in cache."
    }

    Write-Log "Waiting for ccmsetup or msiexec to finish (client installation in progress)..."

    $maxWaitTime = 1800  # 30 minutes
    $interval = 60
    $elapsed = 0
    
    while ($elapsed -lt $maxWaitTime) {
        $installersRunning = Get-Process -Name "ccmsetup", "msiexec" -ErrorAction SilentlyContinue
        if (-not $installersRunning) {
            Write-Log "Installation processes have exited. Proceeding with next steps..."
            break
        }
    
        Write-Log "Installer still running... waiting $interval seconds..."
        Start-Sleep -Seconds $interval
        $elapsed += $interval
    }
    
    if ($elapsed -ge $maxWaitTime) {
        Write-Log "Timeout: ccmsetup or msiexec still running after $maxWaitTime seconds."
    }

    # 4. Trigger policy + MP refresh
    Write-Log "Triggering policy and MP discovery schedules..."
    $scheduleIds = @(
        "{00000000-0000-0000-0000-000000000121}",  # MP Location Refresh
        "{00000000-0000-0000-0000-000000000022}",  # Machine Policy Retrieval
        "{00000000-0000-0000-0000-000000000040}"   # Evaluate Policies
    )

    foreach ($id in $scheduleIds) {
        try {
            Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList $id | Out-Null
            Write-Log "Triggered schedule ID: $id"
        } catch {
            Write-Log "Failed to trigger schedule ID ${id}: $($_.Exception.Message)"
        }
    }

    # 5. Refresh Group Policy
    Write-Log "Running gpupdate /force to refresh Group Policy"
    Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -WindowStyle Hidden
    Start-Sleep -Seconds 5

    # 6. Optional: Confirm MP assignment is active
    try {
        $mp = Get-WmiObject -Namespace "root\ccm" -Class "CCM_ManagementPoint" -ErrorAction Stop
        if ($mp) {
            Write-Log "MP assignment confirmed: $($mp.ServerName)"
        }
    } catch {
        Write-Log "WMI class CCM_ManagementPoint is not yet available. This may be normal during early post-install phase."
    }

    Write-Log "Healthy client handled with safe refresh and cleanup actions. Exiting script."
    exit 0
}



# Else: unhealthy
Write-Log "SCCM client is not healthy - continuing with full cleanup and reinstall."

# Step 3 Download and prepare installation package
# Clear extract folder if it already exists to prevent file conflicts
if (Test-Path $extractPath) {
    Write-Log "Extract folder already exists. Deleting it..."
    Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Log "Creating fresh extraction folder"
New-Item -ItemType Directory -Path $extractPath -Force | Out-Null

Write-Log "Downloading zip package"
Copy-Item -Path "\\vcn.ds.volvo.net\it-blr\ITPROJ01\030012\SDLogsDump\SCCMClientSetup\SCCM Reinstall.zip" -Destination $downloadPath -Force

Write-Log "Extracting zip package"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($downloadPath, $extractPath)




# Step 4 Cleanup
Write-Log "Pre-cleanup: Stopping any ongoing CCMSetup or repair processes..."

# Stop services
Stop-Service CcmExec -Force -ErrorAction SilentlyContinue

# Kill any running setup or repair processes
$processesToKill = @("ccmsetup", "smsexec", "msiexec")
foreach ($proc in $processesToKill) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Write-Log "Killing process: $($_.ProcessName) (PID: $($_.Id))"
            $_ | Stop-Process -Force
        } catch {
            $errorMessage = $_.Exception.Message
            Write-Log ("Failed to kill process ${proc}: $errorMessage")
        }
    }
}


# Remove the retry task that sometimes runs after failed installs
try {
    schtasks /Delete /TN "Microsoft\Microsoft\Configuration Manager\Configuration Manager Client Retry Task" /F | Out-Null
    Write-Log "Removed Configuration Manager Client Retry Task if it existed."
} catch {
    Write-Log "Could not remove retry task (may not exist): $($_.Exception.Message)"
}

Write-Log "Attempting clean uninstall with ccmsetup.exe /uninstall from local source..."

$ccmUninstall = $ccmSetupPath
if (Test-Path $ccmUninstall) {
    try {
        # Start uninstall
        Write-Log "Triggering uninstall with ccmsetup.exe /uninstall..."
        Start-Process -FilePath $ccmUninstall -ArgumentList "/uninstall" -WindowStyle Hidden
        Start-Sleep -Seconds 5  # allow process to initialize

        # Wait for uninstall or MSI to complete
        $timeout = 600  # 10 minutes total wait
        $elapsed = 0
        $interval = 60

        while ($elapsed -lt $timeout) {
            $ccmStillRunning = Get-Process -Name "ccmsetup" -ErrorAction SilentlyContinue
            $msiStillRunning = Get-CimInstance Win32_Process | Where-Object {
                $_.Name -eq "msiexec.exe" -and $_.CommandLine -match "ccmsetup|Configuration Manager|client.msi"
            }
            
            if (-not $ccmStillRunning -and -not $msiStillRunning) {
                Write-Log "ccmsetup and related msiexec processes have exited. Uninstall likely completed."
                break
            }

            Write-Log "Uninstall still running... sleeping $interval seconds"
            Start-Sleep -Seconds $interval
            $elapsed += $interval
        }

        if ($elapsed -ge $timeout) {
            Write-Log "Timeout: Uninstall still running after $timeout seconds. Forcing cleanup..."
        }
    } catch {
        Write-Log "ccmsetup.exe /uninstall failed to start: $($_.Exception.Message)"
    }
} else {
    Write-Log "ccmsetup.exe not found for uninstall step, skipping..."
}



Write-Log "Starting deep cleanup and reset..."

# WMI cleanup attempt
try {
    Write-Log "Attempting to remove CCM WMI namespace manually..."
    $namespace = Get-WmiObject -Namespace "ROOT" -Class "__Namespace" -Filter "Name='ccm'" -ErrorAction SilentlyContinue
    if ($namespace) {
        $namespace.Delete()
        Write-Log "ROOT\ccm namespace manually removed."
    } else {
        Write-Log "ROOT\ccm namespace was not found or already removed."
    }
} catch {
    Write-Log "Failed to manually remove ROOT\ccm: $($_.Exception.Message)"
}


# Stop services and kill related processes
Stop-Service CcmExec -Force -ErrorAction SilentlyContinue
taskkill /F /IM ccmsetup.exe /T | Out-Null
taskkill /F /IM smsexec.exe /T | Out-Null

# Ensure the CcmExec service is removed
sc.exe delete CcmExec | Out-Null

Write-Log "Checking for stuck MSI-based SCCM client installs..."
Uninstall-StuckSCCMMSI

# Remove folders
Remove-Item -Recurse -Force "C:\Windows\CCM" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "C:\Windows\CCMSetup" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "C:\Windows\ccmcache" -ErrorAction SilentlyContinue

# Manual step: Rename specific files if they exist
Write-Log "Removing smscfg.ini and .mif files..."
$cfgPaths = @(
    "C:\Windows\SMSCFG.ini",
    "C:\Windows\System32\CCM\Inventory\SMSAdvancedClient*.mif"
)

foreach ($path in $cfgPaths) {
    try {
        $matchedFiles = Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue
        if ($matchedFiles) {
            foreach ($file in $matchedFiles) {
                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                Write-Log "Removed file: $($file.FullName)"
            }
        } else {
            Write-Log "No matching files found for path: $path"
        }
    } catch {
        Write-Log ("Failed to remove from path {0}: {1}" -f $path, $_.Exception.Message)
    }
}

$orphanedKeysPath = "HKLM:\SOFTWARE\Classes\Installer\Products"
if (Test-Path $orphanedKeysPath) {
    Get-ItemProperty -Path "$orphanedKeysPath\*" |
        Where-Object { $_.ProductName -like "*Configuration Manager*" } |
        ForEach-Object {
            Write-Log "Force-removing orphaned product: $($_.ProductName)"
            Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
} else {
    Write-Log "No orphaned installer keys found under $orphanedKeysPath"
}


Write-Log "Removing any leftover Configuration Manager MSI installations..."
Remove-ConfigMgrMSI

Write-Log "Checking for leftover WMI CCM namespace to forcibly remove..."
try {
    if (Get-WmiObject -Namespace "ROOT" -Class "__Namespace" | Where-Object { $_.Name -eq "ccm" }) {
        Write-Log "ROOT\ccm namespace still exists, attempting manual deletion..."

        # Enumerate and remove if accessible
        Remove-WmiObject -Namespace "ROOT" -Class "__Namespace" -Filter "Name='ccm'" -ErrorAction SilentlyContinue
        Write-Log "ROOT\ccm namespace deletion attempted."
    } else {
        Write-Log "ROOT\ccm namespace already gone."
    }
} catch {
    Write-Log "WMI cleanup failed or not required: $($_.Exception.Message)"
}


# Ensure AlwaysOnInternet is set early
New-Item -Path "HKLM:\SOFTWARE\Microsoft\CCM\Security" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Security" -Name "ClientAlwaysOnInternet" -Value 1 -Type DWord

# Reset BITS
Set-Service BITS -StartupType Automatic
Start-Service BITS
bitsadmin /reset

Write-Log "Pre-cleanup complete"


# Rebuild WMI repository safely if inconsistent
Write-Log "Checking WMI repository health before reinstall..."

$wmiCheck = & winmgmt /verifyrepository
if ($wmiCheck -match "inconsistent") {
    Write-Log "WMI repository is inconsistent. Attempting salvage repair using winmgmt..."
    & winmgmt /salvagerepository | Out-Null
    Write-Log "WMI repository salvage attempt completed."
} else {
    Write-Log "WMI repository is consistent."
}


# Sanity check: Ensure WMI root\ccm namespace is gone or not healthy before reinstall
try {
    Get-CimInstance -Namespace "ROOT\ccm" -ClassName "SMS_Client" -ErrorAction Stop | Out-Null
    Write-Log "Warning: ROOT\ccm namespace already exists. WMI may still be corrupted. Consider rebooting after cleanup."
} catch {
    Write-Log "ROOT\ccm namespace not found - expected for clean install."
}

Start-Sleep -Seconds 10


# Remove vcredist prereqs to avoid 1638 install failure
Write-Log "Removing leftover vcredist files to avoid installer retry and exit code 1638..."
$vcFiles = @("vcredist_x86.exe", "vcredist_x64.exe")
foreach ($file in $vcFiles) {
    $vcPath = Join-Path -Path "C:\Windows\ccmsetup" -ChildPath $file
    if (Test-Path $vcPath) {
        Write-Log "Deleting: $vcPath"
        Remove-Item -Path $vcPath -Force -ErrorAction SilentlyContinue
    }
}
# Also remove any MSI prereq files if present
$msiFiles = @("MicrosoftPolicyPlatformSetup.msi", "WindowsFirewallConfigurationProvider.msi")
foreach ($file in $msiFiles) {
    $path = Join-Path -Path "C:\Windows\ccmsetup" -ChildPath $file
    if (Test-Path $path) {
        Write-Log "Deleting leftover prereq MSI: $file"
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
    }
}

# Clean manifest files too if needed
Get-ChildItem "C:\Windows\ccmsetup\*.manifest" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Start-Sleep -Seconds 10

# Step 5 Installation
# Compile core SCCM MOF files to fix WMI registration
$ccmPath = Join-Path $innerFolder "x64"
Write-Log "Scanning for MOF files to compile in: $ccmPath"

$mofFiles = Get-ChildItem -Path $ccmPath -Filter *.mof -File

if ($mofFiles.Count -eq 0) {
    Write-Log "No MOF files found to compile."
} else {
    foreach ($mof in $mofFiles) {
        try {
            Write-Log "Compiling MOF: $($mof.Name)"
            mofcomp.exe $mof.FullName | Out-Null
        } catch {
            Write-Log "Failed to compile MOF: $($mof.Name) - $_"
        }
    }
}



# Stop the main service again just in case
Stop-Service -Name "CcmExec" -Force -ErrorAction SilentlyContinue

# Kill any lingering processes that might have restarted
$processesToKill = @("ccmsetup", "smsexec", "msiexec")
foreach ($proc in $processesToKill) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Write-Log "Killing process: $($_.ProcessName) (PID: $($_.Id))"
            $_ | Stop-Process -Force
        } catch {
            Write-Log "Failed to kill process ${proc}: $($_.Exception.Message)"
        }
    }
}

# Wipe the retry task again just in case it respawned
try {
    schtasks /Delete /TN "Microsoft\Microsoft\Configuration Manager\Configuration Manager Client Retry Task" /F | Out-Null
    Write-Log "Removed retry task again before reinstall"
} catch {
    Write-Log "Retry task not found or could not be deleted again: $($_.Exception.Message)"
}

# Optionally delete the CcmExec service again to ensure it's not reattaching
sc.exe delete CcmExec | Out-Null

# Step 5.5 – Copy ccmsetup.exe to expected location to avoid remediation failure
$expectedPath = "C:\Windows\ccmsetup"
if (!(Test-Path $expectedPath)) {
    New-Item -Path $expectedPath -ItemType Directory -Force | Out-Null
}
Copy-Item -Path $ccmSetupPath -Destination "$expectedPath\ccmsetup.exe" -Force
Write-Log "Ensured ccmsetup.exe is in $expectedPath to avoid remediation failure."

Write-Log "Attempting to remove WMI namespace ROOT\\ccm safely..."

try {
    $locator = New-Object -ComObject WbemScripting.SWbemLocator
    $service = $locator.ConnectServer(".", "root")

    # Check if the 'ccm' namespace exists
    $ccmNamespace = $service.Get("__namespace.Name='ccm'")
    if ($ccmNamespace) {
        $ccmNamespace.Delete_()
        Write-Log "Successfully removed ROOT\\ccm namespace"
    } else {
        Write-Log "ROOT\\ccm namespace not found, skipping deletion"
    }

    [GC]::Collect()
    Start-Sleep -Seconds 5
} catch {
    Write-Log "Failed to delete ROOT\\ccm namespace (may not exist or access denied): $_"
}

Write-Log "Starting SCCM setup process"
if (Test-Path $ccmSetupPath) {
Write-Log "Selecting best MP and site code dynamically..."
    $mpInfo = Get-BestMPAndSiteCode

    if (-not $mpInfo) {
        Write-Log "No responsive MP found. Aborting install."
        exit 1
    }

    $mp = $mpInfo.BestMP
    $siteCode = $mpInfo.SiteCode
    
    Write-Log "Selected MP: $mp, SiteCode: $siteCode"
    
    Write-Log "Pre-setting selected Management Point in registry to avoid fallback to CMG"
    
    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\CCM")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\CCM" -Force | Out-Null
    }
    
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM" -Name "AllowedMPs" -Value $mp -Type String
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM" -Name "RequestMPToken" -Value 1 -Type DWord

    # Step: Kill any existing install attempts
    Write-Log "Stopping any leftover ccmsetup/ccmrepair processes..."
    Get-Process -Name "ccmsetup", "ccmrepair" -ErrorAction SilentlyContinue | Stop-Process -Force

    # Step: Delete retry task to avoid auto-launching old BITS jobs
    Write-Log "Removing existing retry task if present..."
    schtasks /Delete /TN "Configuration Manager Client Retry Task" /F | Out-Null

    # Step: Clear leftover BITS jobs (must be after stopping tasks/processes)
    Write-Log "Checking and fixing BITS before SCCM install"
    Set-Service -Name BITS -StartupType Automatic
    Restart-Service -Name BITS -Force
    bitsadmin /reset

    Write-Log "Cleaning up C:\Windows\ccmsetup to ensure no downloaded prereqs linger..."
    Remove-Item "C:\Windows\ccmsetup\*" -Force -Recurse -ErrorAction SilentlyContinue
    
    $useAlwaysInternet = $false
    if (-not (Test-IntranetConnectivity)) {
        Write-Host "Intranet MP not reachable - enabling AlwaysInternet mode."
        $useAlwaysInternet = $true
    } else {
        Write-Host "Intranet MP is reachable - using Intranet mode."
    }


    # Step: Build SCCM install arguments
    # Now build your SCCM install arguments. For example:
    $installArgs = @(
        "/mp:$mp",
        "SMSMP=$($mp -replace '^https://')",
        "SMSSITECODE=$siteCode",
        "CCMFIRSTCERT=1",
        "/UsePKICert",
        "/noCRLCheck",
        "RESETKEYINFORMATION=TRUE",
        "/logon",
        "/forceinstall",
        "/debug:all",
        "/noservice",
        "/source:`"$innerFolder`"",
        "CCMALWAYSINF=0",
        "/skipprereq:silverlight.exe"
    )

    # Adjust properties based on the connectivity state.
    if ($useAlwaysInternet) {
        $installArgs += "CCMHTTPSSTATE=448"
        Write-Log "Adding AlwaysInternet parameter to install args."
    } else {
        $installArgs += "CCMHTTPSSTATE=63"
        Write-Log "Adding intranet-only parameter to install args."
    }

    # Log the final install arguments:
    Write-Log "Using install arguments:`n$($installArgs -join "`n")"


    
    Write-Log "Forcing registry cleanup to ensure proper reinstall"
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\CCM" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\CCMSetup" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\SMS" -Recurse -Force -ErrorAction SilentlyContinue
    

    # Kill any leftover ccmsetup processes before reinstall
    Write-Log "Ensuring no leftover ccmsetup processes are running..."
    Get-Process -Name "ccmsetup" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5

    Write-Log "Ensuring MSI leftovers are cleared..."
    Remove-Item -Path "C:\Windows\ccmsetup\*.download" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\ccmsetup\ccmsetup.xml" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\ccmsetup\client.msi" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5

    Write-Log "Extra cleanup: Removing leftover Installer rollback keys (if accessible)..."

    $rollbackKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\Rollback",
        "HKLM:\Software\Classes\Installer\Products",
        "HKLM:\Software\Classes\Installer\Features",
        "HKLM:\Software\Classes\Installer\UpgradeCodes"
    )

    foreach ($rk in $rollbackKeys) {
        try {
            Remove-Item -Path $rk -Recurse -Force -ErrorAction Stop
            Write-Log "Removed: $rk"
        } catch {
            Write-Log "Warning: Could not remove $rk - $($_.Exception.Message)"
        }
    }



    Write-Log "Waiting for WMI root namespace to be healthy before install..."

    $maxWait = 600
    $interval = 10
    $elapsed = 0
    while ($elapsed -lt $maxWait) {
        try {
            Get-CimInstance -Namespace "ROOT\CIMV2" -ClassName "Win32_OperatingSystem" -ErrorAction Stop | Out-Null
            Write-Log "WMI is responsive. Proceeding with install."
            break
        } catch {
            Write-Log "WMI still unresponsive. Sleeping $interval seconds..."
            Start-Sleep -Seconds $interval
            $elapsed += $interval
        }
    }


    # Wait up to 60s for ROOT\ccm to be *created* (initial WMI registration)
    Write-Log "Waiting up to 60 seconds for ROOT\\ccm namespace to appear before launching SCCM setup..."
    $elapsed = 0
    while ($elapsed -lt 60) {
        try {
            Get-CimInstance -Namespace "ROOT\ccm" -ClassName "__Namespace" -ErrorAction Stop | Out-Null
            Write-Log "ROOT\\ccm namespace has been created. Proceeding..."
            break
        } catch {
            Write-Log "ROOT\\ccm not yet created. Sleeping 20 seconds..."
            Start-Sleep -Seconds 20
            $elapsed += 20
        }
    }



    try {
        schtasks /Delete /TN "Microsoft\Microsoft\Configuration Manager\Configuration Manager Client Retry Task" /F | Out-Null
        Write-Log "Removed Configuration Manager Client Retry Task if it existed."
    } catch {
        Write-Log "Could not remove retry task (may not exist): $($_.Exception.Message)"
    }

Write-Log "Creating dummy retry task to block re-creation..."

$taskPath = "Microsoft\Microsoft\Configuration Manager"
$taskName = "Configuration Manager Client Retry Task"
$fullTask = "$taskPath\$taskName"

$dummyXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>SCCM</Author>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
      <UserId>S-1-5-18</UserId>
      <LogonType>S4U</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>false</Enabled>
    <StartWhenAvailable>false</StartWhenAvailable>
    <AllowHardTerminate>false</AllowHardTerminate>
    <Hidden>true</Hidden>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions>
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c exit</Arguments>
    </Exec>
  </Actions>
</Task>
"@





    # Ensure the CCM\Security key exists before modifying AlwaysOnInternet
    # Ensure CCM and Security keys exist
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\CCM\Security" -Force | Out-Null

    # Temporarily disable AlwaysOnInternet to avoid install errors
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Security" -Name "ClientAlwaysOnInternet" -Value 0 -Type DWord -Force
    Write-Log "Pre-created CCM\Security and disabled AlwaysOnInternet before install"

    $taskXmlPath = "$env:TEMP\dummy_retry_task.xml"
    $dummyXml | Out-File -FilePath $taskXmlPath -Encoding unicode -Force

    try {
        schtasks /Create /TN $fullTask /XML $taskXmlPath /F | Out-Null
        Write-Log "Created disabled dummy retry task to prevent re-creation."
    } catch {
        Write-Log "Failed to create dummy retry task: $($_.Exception.Message)"
    }

    Check-OrphanedSCCMMsi

    # Extra: Detect hidden MSI entries (if WMI is broken or client stuck in installer DB)
    try {
        $wmicProduct = wmic product where "Name like '%%Configuration Manager%%'" get IdentifyingNumber /format:csv | Out-String
        $productGuids = ($wmicProduct -split "`n") | Where-Object { $_ -match "\{.*\}" } | ForEach-Object { ($_ -split ",")[-1].Trim() }
    
        foreach ($guid in $productGuids) {
            Write-Log "Found hidden MSI entry for SCCM with GUID: $guid. Forcing uninstall..."
            Start-Process "msiexec.exe" -ArgumentList "/x $guid /qn" -Wait
            Write-Log "Uninstall completed for $guid"
        }
    } catch {
        Write-Log "Failed to query or uninstall hidden SCCM MSI products: $($_.Exception.Message)"
    }
    
    # Clear safe reboot flags to prevent MSI 1603 errors
    Write-Log "Checking and clearing common pending reboot flags..."
    
    $regPendingFile = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    if ((Get-ItemProperty -Path $regPendingFile -ErrorAction SilentlyContinue).PendingFileRenameOperations) {
        try {
            Remove-ItemProperty -Path $regPendingFile -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
            Write-Log "Cleared PendingFileRenameOperations from Session Manager."
        } catch {
            Write-Log "Failed to clear PendingFileRenameOperations: $($_.Exception.Message)"
        }
    }
    
    $regWU = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    if (Test-Path $regWU) {
        try {
            Remove-Item -Path $regWU -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed Windows Update pending reboot key."
        } catch {
            Write-Log "Failed to remove Windows Update pending reboot key: $($_.Exception.Message)"
        }
    }
    
    $regCBS = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    if (Test-Path $regCBS) {
        try {
            Remove-Item -Path $regCBS -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed CBS reboot pending key."
        } catch {
            Write-Log "Failed to remove CBS reboot pending key: $($_.Exception.Message)"
        }
    }
    
    $regComputerName = "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"
    if ((Get-ItemProperty -Path $regComputerName -ErrorAction SilentlyContinue).ComputerName -ne `
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue).Hostname) {
        Write-Log "System rename is pending. This may cause install issues but will not be forcibly cleared."
    }
    
    Write-Log "Finished checking for pending reboot indicators."
    
    # Final optional check - warn if anything's still pending
    function Test-PendingReboot {
        $rebootKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
        )
        foreach ($key in $rebootKeys) {
            if (Test-Path $key) {
                Write-Log "Still pending reboot: $key"
                return $true
            }
        }
        return $false
    }
    
    if (Test-PendingReboot) {
        Write-Log "Warning: One or more reboot flags still present. SCCM install may fail. Consider reboot."
    } else {
        Write-Log "No active reboot flags detected."
    }
    
    # Preinstall cleanup (ccmsetup/msiexec)
    Write-Log "Killing lingering ccmsetup/msiexec processes..."
    Get-Process -Name "ccmsetup", "msiexec" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log "Killing lingering process: $($_.Name) (PID: $($_.Id))"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 5


    # Additional cleanup: brute force broken installer references that cause 0x80070666
    Write-Log "Scanning registry for lingering SCCM installer product keys..."

    $installerKeys = Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\Installer\Products" -ErrorAction SilentlyContinue
    foreach ($key in $installerKeys) {
        try {
            $props = Get-ItemProperty -Path $key.PSPath
            if ($props.ProductName -like "*Configuration Manager*") {
                Write-Log "Found lingering SCCM installer key: $($props.ProductName) [$($key.PSChildName)] - removing..."
                Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log "Failed to inspect/remove key: $($key.PSPath) - $($_.Exception.Message)"
        }
    }

    # Extra: Also clear any uninstall info (just in case)
    $uninstallKeys = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue
    foreach ($key in $uninstallKeys) {
        try {
            $props = Get-ItemProperty -Path $key.PSPath
            if ($props.DisplayName -like "*Configuration Manager*") {
                Write-Log "Found lingering Uninstall entry: $($props.DisplayName) - removing..."
                Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log "Failed to remove uninstall key: $($_.Exception.Message)"
        }
    }

    Remove-OrphanedSCCMInstallations

    # Kill any lingering ccmsetup processes to ensure clean start
    Get-Process ccmsetup -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log "Killing lingering ccmsetup process (PID: $($_.Id))"
        $_.Kill()
        $_.WaitForExit()
    }


    # INSTALLATION PART / installation part / install
    $securityKey = "HKLM:\SOFTWARE\Microsoft\CCM\Security"
    $alwaysInternetWasEnabled = $false
    
    try {
        $currentValue = Get-ItemPropertyValue -Path $securityKey -Name "ClientAlwaysOnInternet" -ErrorAction SilentlyContinue
        if ($currentValue -eq 1) {
            $alwaysInternetWasEnabled = $true
        }
    } catch {
        # Key doesn't exist - create it to ensure clean install
        New-Item -Path $securityKey -Force | Out-Null
    }
    
    # Now set it to 0 temporarily if needed
    if (-not $useAlwaysInternet) {
        Write-Log "Temporarily disabling ClientAlwaysOnInternet for intranet mode install"
        Set-ItemProperty -Path $securityKey -Name "ClientAlwaysOnInternet" -Value 0 -Force
    }
    
    Write-Log "ClientAlwaysOnInternet value just before install: $(Get-ItemPropertyValue -Path $securityKey -Name 'ClientAlwaysOnInternet' -ErrorAction SilentlyContinue)"
    Set-ItemProperty -Path $securityKey -Name "ClientAlwaysOnInternet" -Value 0 -Force
    Start-Sleep -Seconds 5

    Write-Log "Starting SCCM setup and watching for early exit..."

    $joinedArgs = $installArgs -join " "
    $ccmProcess = Start-Process -FilePath $ccmSetupPath -ArgumentList $joinedArgs -PassThru -WindowStyle Hidden

    Start-Sleep -Seconds 20

    if ($ccmProcess.HasExited) {
        Write-Log "ccmsetup.exe exited too quickly. Suspecting file lock or error. Retrying after 30 seconds..."
        Start-Sleep -Seconds 30
        $ccmProcess = Start-Process -FilePath $ccmSetupPath -ArgumentList $joinedArgs -PassThru -WindowStyle Hidden
        $ccmProcess.WaitForExit()
    } else {
        $ccmProcess.WaitForExit()
    }

    $ccmLog = "C:\Windows\ccmsetup\Logs\ccmsetup.log"
    $installFailed = $false

    if (Test-Path $ccmLog) {
        $errorMatch = Select-String -Path $ccmLog -Pattern "CcmSetup failed with error code" -SimpleMatch -ErrorAction SilentlyContinue
        if ($errorMatch) {
            Write-Log "Detected failure in ccmsetup.log: $($errorMatch.Line)"
            Write-Log "ccmsetup.exe exit code: $($ccmProcess.ExitCode)"
    
            # Check for known VC++ redist conflict
            $vcConflict = Get-Content $ccmLog -ErrorAction SilentlyContinue | Select-String -SimpleMatch "0x80070666"
            if ($vcConflict) {
                Write-Log "Detected 0x80070666 error (VC++ redist conflict). Initiating VC++ redist cleanup and retrying SCCM install."
                Remove-ConflictingVCRedists
    
                Write-Log "Waiting 60 seconds after VC++ cleanup to ensure system readiness..."
                Start-Sleep -Seconds 60
    
                Write-Log "Checking for lingering msiexec.exe processes after VC++ cleanup..."
                Get-Process msiexec -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Log "Killing lingering process: msiexec (PID: $($_.Id))"
                    $_ | Stop-Process -Force
                }
    
                Write-Log "Retrying SCCM setup after redist cleanup..."
                $ccmProcess = Start-Process -FilePath $ccmSetupPath -ArgumentList $joinedArgs -PassThru -WindowStyle Hidden -Wait
    
                if ($ccmProcess.ExitCode -eq 0 -or $ccmProcess.ExitCode -eq 7) {
                    Write-Log "SCCM setup retry exited successfully with code $($ccmProcess.ExitCode)."
                    $installFailed = $false
                } else {
                    $installFailed = $true
                    Write-Log "Retry failed. ccmsetup.exe exit code: $($ccmProcess.ExitCode)"
                }
            } else {
                # No VC++ conflict, but we saw a failure line in the log
                if ($ccmProcess.ExitCode -eq 0 -or $ccmProcess.ExitCode -eq 7) {
                    Write-Log "ccmsetup.exe exited successfully despite log error. Ignoring non-fatal log entry."
                    $installFailed = $false
                } else {
                    $installFailed = $true
                    Write-Log "SCCM install failed with exit code $($ccmProcess.ExitCode)."
                }
            }
        } else {
            Write-Log "No fatal error string found in ccmsetup.log."
            if ($ccmProcess.ExitCode -eq 0 -or $ccmProcess.ExitCode -eq 7) {
                $installFailed = $false
                Write-Log "ccmsetup.exe exit code indicates success."
            } else {
                $installFailed = $true
                Write-Log "ccmsetup.exe exit code $($ccmProcess.ExitCode) indicates failure."
            }
        }
    }
    
    # Final decision
    if ($installFailed) {
        Write-Log "Skipping to client.msi install due to SCCM setup failure."
    } else {
        Write-Log "SCCM install appears successful. Proceeding with client health validation..."
    }
    

    if ($installFailed -or -not (Get-Service -Name CcmExec -ErrorAction SilentlyContinue)) {
        Write-Log "CcmExec service missing or install failed. Attempting fallback install with client.msi..."

        if ($delayedRegistryCleanup) {
            Write-Log "Performing delayed registry cleanup..."
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\CCM" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\CCMSetup" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\SMS" -Recurse -Force -ErrorAction SilentlyContinue
            $delayedRegistryCleanup = $false
        }

        $clientMsi = Join-Path $ccmPath "client.msi"
        if (Test-Path $clientMsi) {
            $securityKey = "HKLM:\SOFTWARE\Microsoft\CCM\Security"
            if (-not (Test-Path $securityKey)) {
                New-Item -Path $securityKey -Force | Out-Null
                Write-Log "Re-created CCM\Security key before disabling AlwaysOnInternet"
            }
            
            Write-Log "Temporarily disabling AlwaysOnInternet mode to allow local install"
            Set-ItemProperty -Path $securityKey -Name "ClientAlwaysOnInternet" -Value 0 -Force
            
            Start-Process -FilePath "msiexec.exe" -ArgumentList @(
                "/i", "`"$clientMsi`"",
                "SMSSITECODE=$siteCode",
                "CCMFIRSTCERT=1",
                "RESETKEYINFORMATION=TRUE",
                "REINSTALL=ALL", "REINSTALLMODE=amus",
                "/qn",
                "/l*v", "`"C:\Temp\SCCMClientManual.log`""
            ) -Wait            
            Start-Sleep -Seconds 10
            Restore-SCCMSecurityKey
            if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\CCM\Security")) {
                if (Test-Path $backupFile) {
                    Write-Log "Security registry key missing. Importing backup from $backupFile..."
                    try {
                        Start-Process -FilePath "$env:SystemRoot\System32\reg.exe" -ArgumentList "import", "`"$backupFile`"" -Wait
                        Write-Log "Security key imported successfully from backup."
                    } catch {
                        Write-Log "Failed to import Security key: $_"
                    }
                } else {
                    Write-Log "Backup file not found. Could not restore CCM\Security from .reg export."
                }
            }

        } else {
            Write-Log "client.msi not found at $clientMsi"
        }
    } else {
        Write-Log "CcmExec service found. Attempting to start..."
        Start-Service CcmExec -ErrorAction SilentlyContinue
    }


    Write-Log "Waiting for ccmsetup or msiexec to finish (client installation in progress)..."

    $maxWaitTime = 1800  # 30 minutes
    $interval = 60
    $elapsed = 0
    
    while ($elapsed -lt $maxWaitTime) {
        $installersRunning = Get-Process -Name "ccmsetup", "msiexec" -ErrorAction SilentlyContinue
        if (-not $installersRunning) {
            Write-Log "Installation processes have exited. Proceeding with next steps..."
            break
        }
    
        Write-Log "Installer still running... waiting $interval seconds..."
        Start-Sleep -Seconds $interval
        $elapsed += $interval
    }
    
    if ($elapsed -ge $maxWaitTime) {
        Write-Log "Timeout: ccmsetup or msiexec still running after $maxWaitTime seconds."
    }
    
    
    

    if ($alwaysInternetWasEnabled) {
        try {
            Write-Log "Restoring ClientAlwaysOnInternet=1 after install"
            Set-ItemProperty -Path $securityKey -Name "ClientAlwaysOnInternet" -Value 1 -Force
        } catch {
            Write-Log "Failed to restore ClientAlwaysOnInternet=1: $_"
        }
    }
    


# Wait for SMS_Client WMI class to become available before proceeding
$maxWaitTime = 300  # 10 Minutes
$interval = 60       # Check every 60 seconds
$elapsed = 0
$wmiReady = $false

Write-Log "Waiting for SMS_Client WMI class to become available (max 5 minutes)..."

while ($elapsed -lt $maxWaitTime) {
    try {
        Get-CimInstance -Namespace "ROOT\ccm" -ClassName "SMS_Client" -ErrorAction Stop | Out-Null
        $wmiReady = $true
        break
    } catch {
        Write-Log "WMI class SMS_Client not yet available. Waiting $interval seconds..."
        Start-Sleep -Seconds $interval
        $elapsed += $interval
    }
}

if (-not $wmiReady) {
    Write-Log "Timeout: WMI class SMS_Client still unavailable after $maxWaitTime seconds."
} else {
    Write-Log "WMI class SMS_Client is now available!"
}

# Step 6 Check WMI Health and Repair if needed
    # Optional WMI class confirmation
    Write-Log "Checking if SMS_Client WMI class is now available..."
    try {
        Get-CimInstance -Namespace "ROOT\ccm" -ClassName "SMS_Client" -ErrorAction Stop | Out-Null
        Write-Log "WMI class SMS_Client is now available."
    } catch {
        Write-Log "WMI class still not available."
    }
} else {
    Write-Log "ERROR: ccmsetup.exe not found at $ccmSetupPath"
}

# Optional: Try WMI repair as a last resort
Write-Log "Attempting WMI repository repair..."
$wmiResult = & winmgmt /verifyrepository
if ($wmiResult -match "inconsistent") {
    & winmgmt /salvagerepository | Out-Null
    Write-Log "WMI repository salvaged (was inconsistent)."
} else {
    Write-Log "WMI repository was consistent."
}

Write-Log "Waiting 60 seconds to let CCM exec settle before registration..."
Start-Sleep -Seconds 60

Write-Log "Making Sure AlwaysOnInternet is Enabled..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM" -Name "ClientAlwaysOnInternet" -Value 1 -Force

try {
    schtasks /Delete /TN "Microsoft\Microsoft\Configuration Manager\Configuration Manager Client Retry Task" /F | Out-Null
    Write-Log "Removed Configuration Manager Client Retry Task if it existed."
} catch {
    Write-Log "Could not remove retry task (may not exist): $($_.Exception.Message)"
}
Start-Sleep -Seconds 5

Write-Log "Restarting CcmExec to stabilize services and registration"
$ccmService = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue
if ($ccmService) {
    Restart-Service -Name "CcmExec" -Force
    Write-Log "CcmExec restarted successfully"
} else {
    Write-Log "CcmExec service not found, skipping restart"
}

Write-Log "Waiting 60 seconds to let CCM exec start up..."
Start-Sleep -Seconds 60

Write-Log "Triggering actions."
Start-Sleep -Seconds 5
try {
    $scheduleIds = @(
        "{00000000-0000-0000-0000-000000000121}",  # MP Location Refresh
        "{00000000-0000-0000-0000-000000000022}",  # Machine Policy Retrieval
        "{00000000-0000-0000-0000-000000000040}"   # Evaluate Policies (optional but good)
    )

    foreach ($id in $scheduleIds) {
        try {
            Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList $id | Out-Null
            Write-Log "Successfully triggered schedule ID: $id"
        } catch {
            Write-Log ("Failed to trigger schedule ID {0}: {1}" -f $id, $_.Exception.Message)
        }
    }
} catch {
    Write-Log "Unexpected failure during schedule triggers: $($_.Exception.Message)"
}

Write-Log "Running gpupdate /force to refresh Group Policy"
Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -WindowStyle Hidden
Start-Sleep -Seconds 30

# Final remediation polish - only if not already running
$remediateExe = "C:\Windows\ccmsetup\cache\ccmsetup.exe"
$remediateSource = "cache"
$rebootRequired = $false  # Track if reboot is needed later

# Fallback to extracted location if cache path doesn't exist
if (-not (Test-Path $remediateExe)) {
    $remediateExe = Join-Path $innerFolder "ccmsetup.exe"
    $remediateSource = "extracted"
}

# Check if remediation is already running
try {
    $remediateRunning = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'ccmsetup.exe'" | Where-Object {
        $_.CommandLine -like "*remediate:client*"
    }
} catch {
    $remediateRunning = $null
    Write-Log "Failed to check remediation process status: $($_.Exception.Message)"
}

# Trigger remediation if needed
if ((Test-Path $remediateExe) -and (-not $remediateRunning)) {
    Write-Log "Triggering final SCCM client remediation from $remediateSource path using /remediate:client"
    try {
        Start-Process -FilePath $remediateExe -ArgumentList "/remediate:client" -WindowStyle Hidden
    } catch {
        Write-Log "Failed to start SCCM client remediation: $($_.Exception.Message)"
    }
} elseif ($remediateRunning) {
    Write-Log "Remediation already in progress. Skipping manual /remediate:client trigger."
} else {
    Write-Log "Remediation skipped - ccmsetup.exe not found in cache or extracted path."
}

# Wait for remediation process to complete
Write-Log "Waiting up to 60 minutes for remediation process to complete..."
$maxRemediateWait = 3600
$interval = 60
$elapsed = 0
while ($elapsed -lt $maxRemediateWait) {
    $remediateRunning = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'ccmsetup.exe'" | Where-Object {
        $_.CommandLine -like "*remediate:client*"
    }
    if (-not $remediateRunning) {
        Write-Log "Remediation process has finished."
        break
    } else {
        Write-Log "Remediation still running... waiting $interval seconds..."
        Start-Sleep -Seconds $interval
        $elapsed += $interval
    }
}

# Check if remediation requested a reboot (exit code 7)
$ccmLogPath = "$env:windir\ccmsetup\Logs\ccmsetup.log"
if (Test-Path $ccmLogPath) {
    try {
        $exitCodeLine = Get-Content $ccmLogPath -Tail 50 | Where-Object { $_ -match "CcmSetup is exiting with return code" }
        if ($exitCodeLine -and $exitCodeLine -match "return code (\d+)") {
            $ccmExitCode = [int]$matches[1]
            Write-Log "CcmSetup exited with return code $ccmExitCode"
            if ($ccmExitCode -eq 7) {
                Write-Log "CcmSetup requested a reboot (exit code 7). Some features may not work until the next restart."
                $rebootRequired = $true
            }
        } else {
            Write-Log "CcmSetup log checked, but no recognizable exit code was found in last 50 lines."
        }
    } catch {
        Write-Log "Failed to read ccmsetup.log for exit code: $($_.Exception.Message)"
    }
} else {
    Write-Log "CcmSetup log not found at expected path: $ccmLogPath"
}


Write-Log "Waiting additional 60 seconds for CcmExec to settle..."
Start-Sleep -Seconds 60

# Ensure CcmExec is running
$ccmExec = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue
if ($ccmExec -and $ccmExec.Status -ne "Running") {
    try {
        Write-Log "CcmExec is not running. Attempting to start..."
        Start-Service -Name "CcmExec"
        Write-Log "CcmExec started successfully."
        Start-Sleep -Seconds 15  # Give it time to settle
    } catch {
        Write-Log "Failed to start CcmExec: $($_.Exception.Message)"
    }
} elseif (-not $ccmExec) {
    Write-Log "CcmExec service not found. This may indicate a failed client install."
} else {
    Write-Log "CcmExec is already running."
}

# Reapply AlwaysOnInternet after remediation
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM" -Name "ClientAlwaysOnInternet" -Value 1 -Force
    Write-Log "Re-applied ClientAlwaysOnInternet = 1 after remediation."
} catch {
    Write-Log "Failed to re-apply ClientAlwaysOnInternet: $($_.Exception.Message)"
}

# Triggering all available client actions dynamically
Write-Log "Triggering all available SCCM client actions after remediation..."
try {
    $availableSchedules = Get-WmiObject -Namespace "root\ccm\scheduler" -Class "CCM_Scheduler_History" | Select-Object -ExpandProperty ScheduleID -Unique
    foreach ($id in $availableSchedules) {
        try {
            Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList $id | Out-Null
            Write-Log "Successfully triggered schedule ID: $id"
        } catch {
            Write-Log ("Failed to trigger schedule ID {0}: {1}" -f $id, $_.Exception.Message)
        }
    }
} catch {
    Write-Log "Failed to retrieve available schedule IDs: $($_.Exception.Message)"
}
Write-Log "Waiting additional 120 seconds for actions to settle..."
Start-Sleep -Seconds 120

# Report installed client version
try {
    $version = (Get-WmiObject -Namespace "ROOT\ccm" -Class SMS_Client -ErrorAction Stop).ClientVersion
    Write-Log "Client version: $version"
} catch {
    Write-Log "Could not retrieve client version: $($_.Exception.Message)"
}


Write-Log "Final cleanup of downloaded SCCM reinstall files..."

# Clean up extract folder
if (Test-Path $extractPath) {
    try {
        Remove-Item -Path $extractPath -Recurse -Force -ErrorAction Stop
        Write-Log "Removed extract folder: $extractPath"
    } catch {
        Write-Log "Failed to remove extract folder: $($_.Exception.Message)"
    }
} else {
    Write-Log "Extract folder not found: $extractPath (already cleaned?)"
}

# Clean up downloaded ZIP
if (Test-Path $downloadPath) {
    try {
        Remove-Item -Path $downloadPath -Force -ErrorAction Stop
        Write-Log "Removed ZIP package: $downloadPath"
    } catch {
        Write-Log "Failed to remove ZIP package: $($_.Exception.Message)"
    }
} else {
    Write-Log "ZIP package not found: $downloadPath (already cleaned?)"
}

# Restore normal sleep behavior
$ES_CONTINUOUS = [Convert]::ToUInt32("0x80000000", 16)
$result = [WinAPI.Power]::SetThreadExecutionState($ES_CONTINUOUS)

if ($result -ne 0) {
    Write-Log "Sleep behavior restored to default."
} else {
    Write-Log "Failed to restore sleep behavior. Manual intervention may be needed."
}


Write-Log "SCCM reinstall process completed. Kindly wait 15 minutes then restart PC."