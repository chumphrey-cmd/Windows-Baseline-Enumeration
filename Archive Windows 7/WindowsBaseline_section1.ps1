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
    sc qc $service | Select-String "FAILURE_ACTIONS" -Context 0,3
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
