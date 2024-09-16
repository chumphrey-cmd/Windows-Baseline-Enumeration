# Prompt for directory path and file name
$directoryPath = Read-Host "Please enter the folder path to save the output"

# Remove any double quotes if they exist in the folder path
$directoryPath = $directoryPath -replace '"', ''

# Check if the folder path exists
if (-Not (Test-Path -Path $directoryPath)) {
    Write-Output "The folder path you entered does not exist. Please verify the path."
    exit
}

# Prompt for file name
$fileName = Read-Host "Please enter a descriptive file name for the output (without extension)"

# Remove any double quotes from file name
$fileName = $fileName -replace '"', ''

# Combine folder path and file name, appending the .txt extension
$outputFilePath = Join-Path $directoryPath "$fileName.txt"

# Start capturing output to the specified file
Start-Transcript -Path $outputFilePath -Append

# Ensure user is running as administrator

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if the script is running as admin
if (-not (Test-IsAdmin)) {
    Write-Output "This script requires administrative privileges. Please run PowerShell as an administrator."
    exit
}

# Get system information
$systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$biosInfo = Get-CimInstance -ClassName Win32_BIOS

Write-Output "System Information:"
Write-Output "Hostname: $($systemInfo.Name)" 
Write-Output "Manufacturer: $($systemInfo.Manufacturer)"
Write-Output "Model: $($systemInfo.Model)"
Write-Output "OS: $($osInfo.Caption) $($osInfo.OSArchitecture)"
Write-Output "BIOS Version: $($biosInfo.SMBIOSBIOSVersion)"

# Get list of running processes
Write-Output "`nRunning Processes:"

Get-Process | Select-Object ProcessName, Id, Path, StartTime, @{Name="UserName";Expression={$_.GetOwner().User}} -ErrorAction SilentlyContinue | Format-Table -AutoSize -Wrap

# Get list of installed applications
'''
Retrieves and displays a list of installed applications on a Windows system, including both 32-bit and 64-bit applications.
'''
Write-Output "`nInstalled Applications:"
$apps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
$apps += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
$apps | Where-Object {$_.DisplayName -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName} | 
    
    Select-Object DisplayName, DisplayVersion, Publisher, @{Name="InstallDate";Expression={[datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null)}}, InstallLocation, UninstallString | 
    Sort-Object DisplayName | Format-Table -AutoSize -Wrap

# Get list of enabled Windows features
Write-Output "`nEnabled Windows Features:"
Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} | 
    Select-Object FeatureName, Description | Format-Table -AutoSize -Wrap

# Get list of installed Windows updates
Write-Output "`nInstalled Windows Updates:"

Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID, Description, InstalledBy, InstalledOn | Format-Table -AutoSize -Wrap

# Get list of startup programs from registry Run keys
Write-Output "`nStartup Programs (Registry):"
$regStartupLocations = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

Get-ItemProperty -Path $regStartupLocations | ForEach-Object {
    $key = $_.PSPath -replace 'Microsoft.PowerShell.Core\\Registry::', ''
    $_ | Get-Member -MemberType NoteProperty | Where-Object {$_.Name -ne '(Default)'} | ForEach-Object {
        $name = $_.Name
        $path = $_.$name
        Write-Output "$key\$name -> $path"
    }
} | Format-List

# Get Windows Defender Exploit Guard Settings
Write-Output "`nWindows Defender Exploit Guard Settings:"
try {
    Get-MpPreference | Select-Object -Property AttackSurfaceReductionRules_Actions, ControlledFolderAccess, ExploitProtectionSettings | Format-List
} catch {
    Write-Output "Error retrieving Windows Defender Exploit Guard settings: $_"
}

# Get Audit Policy
Write-Output "`nAudit Policy:"
auditpol /get /category:* | Format-Table -AutoSize -Wrap

# Get Windows Error Reporting Settings
Write-Output "`nWindows Error Reporting Settings:"
try {
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" | Format-List
} catch {
    Write-Output "Error retrieving Windows Error Reporting settings: $_"
}

# Get Service Recovery Configuration
Write-Output "`nService Recovery Settings for Security-Critical Services:"
foreach ($service in $securityServices) {
    Set-Content qc $service | Select-String "FAILURE_ACTIONS" -Context 0,3
}

# Get Data Execution Prevention (DEP) Settings
Write-Output "`nData Execution Prevention (DEP) Settings:"
Get-ProcessMitigation -System | Format-List

# Get list of startup programs from startup folders
Write-Output "`nStartup Programs (Startup Folders):"
$startupFolders = @(
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
Get-ChildItem -Path $startupFolders -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output $_.FullName
} | Format-List

# Get list of scheduled tasks
Write-Output "`nScheduled Tasks:"

Get-ScheduledTask | Where-Object {$_.State -eq "Ready" -and $_.Principal.UserId -eq 'SYSTEM'} | 
    Select-Object TaskName, TaskPath, Description, Author, Date, Triggers, Actions | Format-Table -AutoSize -Wrap

# Get list of WMI event subscriptions
Write-Output "`nWMI Event Subscriptions:"
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | ForEach-Object {
    Write-Output "Filter: $($_.Name)"
    Write-Output "Query: $($_.Query)"
    Write-Output "---"
} | Format-List

# Retrieve WMI Event Consumers for a complete WMI baseline
Write-Output "`nWMI Event Consumers:"
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | ForEach-Object {
    Write-Output "Consumer: $($_.Name)"
    Write-Output "Type: $($_.PSClass)"
    Write-Output "---"
} | Format-List

# Get list of network adapters and IP configuration
Write-Output "`nNetwork Configuration:"

Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, 
    @{Name="IPAddress";Expression={Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress}},
    @{Name="DNSServers";Expression={Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses}} | 
    Format-Table -AutoSize -Wrap

# Get Windows event forwarding status
Write-Output "`nWindows Event Forwarding Status:"
try {
    wecutil es | Format-List
} catch {
    Write-Output "Error retrieving WEF status: $_"
}

# Get list of local users and groups
Write-Output "`nLocal Users:"
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, PasswordExpires, UserMayChangePassword | Format-Table -AutoSize -Wrap

Write-Output "`nLocal Groups:" 
Get-LocalGroup | Select-Object Name, Description, @{Name="Members";Expression={$_.Members() | Select-Object -ExpandProperty Name}} | Format-Table -AutoSize -Wrap

# Get important registry settings
Write-Output "`nRegistry Settings:" 
# Added check for registry path existence before reading properties
$regSettings = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
)
foreach ($regPath in $regSettings) {
    if (Test-Path $regPath) {
        Get-ItemProperty -Path $regPath | Format-List
    } else {
        Write-Output "Path $regPath does not exist."
    }
}

# Get CPU Usage
Write-Output "`nCPU Usage:"
# Added CPU Time history (Optional)
$cpuTime = Get-Counter '\Processor(_Total)\% Processor Time'
Write-Output "CPU Time History: $($cpuTime.CounterSamples[0].CookedValue)%"
Get-CimInstance -ClassName Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, LoadPercentage | Format-Table -AutoSize -Wrap

# Get Memory Usage
Write-Output "`nMemory Usage:"
$mem = Get-CimInstance -ClassName Win32_OperatingSystem
$freeMem = [math]::round(($mem.FreePhysicalMemory / 1MB), 2)
$totalMem = [math]::round(($mem.TotalVisibleMemorySize / 1MB), 2)
$usedMem = $totalMem - $freeMem
Write-Output "Total Memory: $totalMem MB, Used Memory: $usedMem MB, Free Memory: $freeMem MB"

# Get Disk Usage
Write-Output "`nDisk Usage:"
Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | 
    Select-Object DeviceID, VolumeName, FileSystem, @{Name='UsedSpace(GB)'; Expression={[math]::round(($_.Size - $_.FreeSpace) / 1GB, 2)}}, @{Name='FreeSpace(GB)'; Expression={[math]::round($_.FreeSpace / 1GB, 2)}}, @{Name='TotalSpace(GB)'; Expression={[math]::round($_.Size / 1GB, 2)}}, @{Name='PercentFree'; Expression={[math]::round(($_.FreeSpace / $_.Size) * 100, 2)}} | 
    Format-Table -AutoSize -Wrap

# Get Firewall Rules
Write-Output "`nFirewall Rules:"
# Filtered inbound rules for enhanced security focus
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'} | 
    Select-Object DisplayName, Description, LocalAddress, RemoteAddress, Protocol, LocalPort, RemotePort, Action | Format-Table -AutoSize -Wrap

# Get Security Settings
Write-Output "`nSecurity Settings:"

$secpolPath = Join-Path $env:TEMP "secpol.cfg"
secedit /export /cfg $secpolPath
Get-Content $secpolPath
Remove-Item $secpolPath -Force

# List of high-privilege and security-related services
$securityServices = @(
    'WinDefend',   # Windows Defender
    'MpsSvc',      # Windows Firewall
    'EventLog',    # Windows Event Log
    'SamSs',       # Security Accounts Manager
    'WinRM',       # Windows Remote Management
    'VaultSvc',    # Credential Manager
    'gpsvc',       # Group Policy Client
    'PolicyAgent', # IPsec Policy Agent
    'wuauserv',    # Windows Update
    'wscsvc',      # Security Center
    'TermService', # Remote Desktop Services
    'W32Time',     # Windows Time
    'CryptSvc',    # Cryptographic Services
    'BDESVC'       # BitLocker Drive Encryption
)

# Filter for high-privilege services running as SYSTEM, NT AUTHORITY, or LocalService
Write-Output "`nSecurity-Critical High-Privilege Services:"
Get-WmiObject win32_service | Where-Object { 
    ($securityServices -contains $_.Name) -and 
    ($_.StartName -match "LocalSystem|NT AUTHORITY|LocalService|NetworkService")
} | 
Select-Object Name, DisplayName, StartMode, State, PathName, StartName, Description | 
Format-Table -AutoSize -Wrap

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
        Select-Object @{Name='DeviceName';Expression={$_.DeviceName}}, 
                      @{Name='DriverVersion';Expression={$_.DriverVersion}},
                      @{Name='Manufacturer';Expression={$_.Manufacturer}},
                      @{Name='DriverProviderName';Expression={$_.DriverProviderName}},
                      @{Name='DriverDate';Expression={[datetime]::Parse($_.DriverDate).ToString("yyyy-MM-dd")}},
                      @{Name='InfName';Expression={$_.InfName}},
                      @{Name='IsSigned';Expression={$_.IsSigned}},
                      @{Name='IsDigitallySigned';Expression={$_.IsDigitallySigned}},
                      @{Name='SignerName';Expression={$_.SignerName}},
                      @{Name='ClassGuid';Expression={$_.ClassGuid}},
                      @{Name='DeviceClass';Expression={$_.DeviceClass}},
                      @{Name='DeviceID';Expression={$_.DeviceID}} |
        Format-Table -Property DeviceName, DriverVersion, Manufacturer, DriverProviderName, DriverDate, InfName, 
                      @{Name='IsSigned';Expression={if ($_.IsSigned) { "Yes" } else { "No" }}}, 
                      @{Name='IsDigitallySigned';Expression={if ($_.IsDigitallySigned) { "Yes" } else { "No" }}},
                      SignerName, ClassGuid, DeviceClass, DeviceID -AutoSize
} catch {
    Write-Output "Error retrieving installed drivers: $_"
}

# Get Installed Printers
Write-Output "`nInstalled Printers:"
try {
    Get-WmiObject -Class Win32_Printer | 
        Select-Object Name, DriverName, PortName, Shared, Published, Local, Network | 
        Format-Table
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

# Get Windows Update Settings
Write-Output "`nWindows Update Settings:"
$updateSettings = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", 
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
)

foreach ($path in $updateSettings) {
    if (Test-Path $path) {
        try {
            Get-ItemProperty -Path $path | Format-List
        } catch {
            Write-Output "Error retrieving Windows Update settings for $path{} $_"
        }
    } else {
        Write-Output "Registry path $path does not exist."
    }
}

# Get Backup and Restoration Status
Write-Output "`nBackup and Restoration Status:"
try {
    vssadmin list shadows | Format-List
    wbadmin get versions | Format-List
} catch {
    Write-Output "Error retrieving backup status: $_"
}

# Get User Rights Assignment
Write-Output "`nUser Rights Assignment:"
$userRights = @(
    "SeTrustedCredManAccessPrivilege", "SeNetworkLogonRight", "SeTcbPrivilege", 
    "SeMachineAccountPrivilege", "SeIncreaseQuotaPrivilege", "SeInteractiveLogonRight", 
    "SeRemoteInteractiveLogonRight", "SeBackupPrivilege", "SeChangeNotifyPrivilege", 
    "SeSystemtimePrivilege", "SeTimeZonePrivilege", "SeCreatePagefilePrivilege", 
    "SeCreateTokenPrivilege", "SeCreateGlobalPrivilege", "SeCreatePermanentPrivilege", 
    "SeCreateSymbolicLinkPrivilege", "SeDebugPrivilege", "SeDenyNetworkLogonRight", 
    "SeDenyBatchLogonRight", "SeDenyServiceLogonRight", "SeDenyInteractiveLogonRight", 
    "SeDenyRemoteInteractiveLogonRight", "SeEnableDelegationPrivilege", "SeRemoteShutdownPrivilege", 
    "SeAuditPrivilege", "SeImpersonatePrivilege", "SeIncreaseWorkingSetPrivilege", 
    "SeIncreaseBasePriorityPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", 
    "SeBatchLogonRight", "SeServiceLogonRight", "SeSecurityPrivilege", "SeRelabelPrivilege", 
    "SeSystemEnvironmentPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", 
    "SeSystemProfilePrivilege", "SeUndockPrivilege", "SeAssignPrimaryTokenPrivilege", 
    "SeRestorePrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeTakeOwnershipPrivilege"
)

foreach ($right in $userRights) {
    try {
        $identity = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name $right -ErrorAction SilentlyContinue).$right
        if ($identity) {
            if ($identity -is [Array]) {
                $identity | ForEach-Object { Write-Output "$right : $_" }
            } else {
                Write-Output "$right : $identity"
            }
        } else {
            Write-Output "$right : Not Assigned"
        }
    } catch {
        Write-Output "Error retrieving User Rights Assignment for $right{} $_"
    }
}

# Check PowerShell Remoting Status
Write-Output "`nPowerShell Remoting Status:"
try {
    $psRemoting = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableRemoteManagement" -ErrorAction SilentlyContinue
    if ($psRemoting.EnableRemoteManagement -eq 1) {
        Write-Output "PowerShell Remoting: Enabled"
    } else {
        Write-Output "PowerShell Remoting: Disabled"
    }
} catch {
    Write-Output "Error retrieving PowerShell remoting status: $_"
}

# Get Removable Media Security Settings
Write-Output "`nRemovable Media Security Settings:"

$removableMediaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"

if (Test-Path $removableMediaPath) {
    try {
        Get-ItemProperty -Path $removableMediaPath | Format-List
    } catch {
        Write-Output "Error retrieving Removable Media Security settings: $_"
    }
} else {
    Write-Output "Registry path $removableMediaPath does not exist."
}

# Stop capturing output
Stop-Transcript