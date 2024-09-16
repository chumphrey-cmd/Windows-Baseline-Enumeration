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

# Get MFA Status for Accounts
Write-Output "`nMFA Status for User Accounts:"
Get-MsolUser | Select-Object DisplayName, UserPrincipalName, StrongAuthenticationMethods | Format-Table -AutoSize -Wrap

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

# Get Removeable Media Status
Write-Output "`nRemovable Media Security Settings:"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" | Format-List -AutoSize