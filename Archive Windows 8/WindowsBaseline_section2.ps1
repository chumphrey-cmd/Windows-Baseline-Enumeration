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