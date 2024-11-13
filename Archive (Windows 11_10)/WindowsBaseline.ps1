#$drive = "\\COMPUTERNAME\NETWORK_SHARE_NAME\"
$drive = "C:\"


Write-Output "SYSTEMINFO" > "$($drive)$($env:COMPUTERNAME)Baseline.txt"
systeminfo.exe >> "$($drive)$($env:COMPUTERNAME)Baseline.txt"
Write-Output "Get-Service" >> "$($drive)$($env:COMPUTERNAME)Baseline.txt"
Get-Service|Sort-Object -Property Status|ft -Wrap |out-file -Append "$($drive)$($env:COMPUTERNAME)Baseline.txt"
Write-Output "Get-NetTCPConnection" >> "$($drive)$($env:COMPUTERNAME)Baseline.txt"
Get-NetTCPConnection|Sort-Object -Property State|out-file -Append "$($drive)$($env:COMPUTERNAME)Baseline.txt"
Write-Output "Get-LocalUser" >> "$($drive)$($env:COMPUTERNAME)Baseline.txt"
Get-LocalUser|Select-Object -Property *| out-file -Append "$($drive)$($env:COMPUTERNAME)Baseline.txt"
Write-Output "Get-LocalGroup" >> "$($drive)$($env:COMPUTERNAME)Baseline.txt"
Get-LocalGroup|Select-Object -Property Name,SID,PrincipalSource,ObjectClass | out-file -Append "$($drive)$($env:COMPUTERNAME)Baseline.txt"
Write-Output "Processes PID & PPID" >> "$($drive)$($env:COMPUTERNAME)Baseline.txt"
Get-CimInstance -Class Win32_Process|Select-Object -Property ProcessName,Path,Description,Name,CreationDate,CommandLine,ExecutablePath,ProcessId,ParentProcessId|Sort-Object -Property ProcessId | out-file -Append "$($drive)$($env:COMPUTERNAME)Baseline.txt"





&"$($drive)autorunsc.exe" -accepteula -a bklnst * > "$($drive)$($env:COMPUTERNAME)_autoruns.txt"
&"$($drive)tcpvcon.exe" -accepteula -nobanner -n |Set-Content "$($drive)$($env:COMPUTERNAME)_tcpvcon.txt"