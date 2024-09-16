# Get Listening Ports and Associated Processes
Write-Output "`nListening Ports:"
try {
    Get-NetTCPConnection -State Listen | 
        Select-Object LocalAddress, LocalPort, 
            @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}},
            @{Name="ProcessPath";Expression={(Get-Process -Id $_.OwningProcess).Path}} | 
        Format-Table -AutoSize -Wrap
} catch {
    Write-Output "Error retrieving listening ports and associated processes: $_"
}

# Get Installed Drivers (with more details)
Write-Output "`nInstalled Drivers:"
try {
    Get-WmiObject Win32_PnPSignedDriver | 
        Select-Object DeviceName, DriverVersion, Manufacturer, DriverProviderName, 
            DriverDate, InfName, IsSigned, IsDigitallySigned, SignerName, ClassGuid, 
            DeviceClass, DeviceID | Format-Table -AutoSize -Wrap
} catch {
    Write-Output "Error retrieving installed drivers: $_"
}

# Get Installed Printers
Write-Output "`nInstalled Printers:"
try {
    Get-WmiObject -Class Win32_Printer | 
        Select-Object Name, DriverName, PortName, Shared, Published, Local, Network | 
        Format-Table -AutoSize -Wrap
} catch {
    Write-Output "Error retrieving installed printers: $_"
}

# Get Installed Software
Write-Output "`nInstalled Software:"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize -Wrap

# Get Detailed Event Logs
Write-Output "`nDetailed Event Logs:"
$logNames = "Application", "System", "Security"
$logEntries = @()
foreach ($log in $logNames) {
    try {
        $entries = Get-WinEvent -LogName $log -MaxEvents 100 | 
            Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message
        $logEntries += $entries
    } catch {
        Write-Output "Error retrieving log entries for ${log}: $_"
    }
}
$logEntries | Sort-Object TimeCreated -Descending | Format-Table -AutoSize -Wrap

# Get AppLocker Policy
Write-Output "`nAppLocker Policy:"
try {
    Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
} catch {
    Write-Output "Error retrieving AppLocker policy: $_"
}

# Get Account Lockout Settings
Write-Output "`nAccount Lockout Settings:"
Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutDuration, LockoutThreshold | Format-Table -AutoSize -Wrap

# Get BitLocker Status
Write-Output "`nBitLocker Status:"
try {
    $bitlockerVolumes = Get-BitLockerVolume
    $bitlockerVolumes | Select-Object MountPoint, VolumeType, ProtectionStatus, EncryptionPercentage, KeyProtector | Format-Table -AutoSize -Wrap
} catch {
    Write-Output "Error retrieving BitLocker status: $_"
}

# Get Detailed LAPS (Local Administrator Password Solution) Configuration
Write-Output "`nLAPS Configuration:"
$lapsConfig = @(
    "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled",
    "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordComplexity",
    "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordLength",
    "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays",
    "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd\BackupDirectory",
    "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd\PwdExpirationProtectionEnabled",
    "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdAuditing",
    "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdminAccountName",
    "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordEncryptionEnabled",
    "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordEncryptionPrincipal"
)

$lapsConfig | ForEach-Object {
    $key, $valueName = $_ -split '\\', 2
    $value = (Get-ItemProperty -Path $key -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($value) {
        Write-Output "${valueName}: $value"
    } else {
        Write-Output "${valueName}: Not Configured"
    }
}

# Get PowerShell Transcription and Logging Settings
Write-Output "`nPowerShell Transcription and Logging Settings:"
$psSettings = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
)

foreach ($path in $psSettings) {
    if (Test-Path $path) {
        try {
            Write-Output "`nRegistry Path: $path"
            Get-ItemProperty -Path $path | Format-List
        } catch {
            Write-Output "Error retrieving properties from $path{} $_"
        }
    } else {
        Write-Output "Registry path does not exist: $path"
    }
}

# Get Windows Defender Settings
Write-Output "`nWindows Defender Settings:"
try {
    Get-MpComputerStatus | Select-Object AntivirusEnabled, AntispywareEnabled, RealTimeProtectionEnabled, 
        BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled | Format-List
    Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, 
        DisableBlockAtFirstSeen, DisableIOAVProtection, DisablePrivacyMode, 
        SignatureDisableUpdateOnStartupWithoutEngine, DisableArchiveScanning, 
        DisableIntrusionPreventionSystem, DisableScriptScanning | Format-List
} catch {
    Write-Output "Error retrieving Windows Defender settings: $_"
}