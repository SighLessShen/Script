$FormatEnumerationLimit=-1
Start-Transcript -path C:\Windows\temp\output.txt -append
$Agent = Read-Host -Prompt 'Agent Name'
$Date = (Get-Date).ToString('MM.dd.yyyy.HH:mm')

$Title = 'System Inventory Report' 
 
$AgentHeading = "Created by $Agent"

$DateHeading = "Date Created: $Date"

$Srvc = Get-Service | Sort-Object -Property Status, DisplayName | Format-Table @{L='Display Name';E={$_.DisplayName}}, Status #| Out-File -FilePath E:\Process-ServicesInventory-$Date.txt -Append
$Prcs = tasklist -V 
$hstnme = (Get-WmiObject Win32_OperatingSystem).CSName
$hstos = (Get-WmiObject Win32_OperatingSystem).Caption 
$hstarc = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
$hstosversion = (Get-WmiObject Win32_OperatingSystem).Version
$instSoft = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object Publisher, DisplayName, DisplayVersion, InstallDate | Format-Table –AutoSize 
$localusr = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select PSComputername, Name, Status, Disabled, AccountType, Lockout, PasswordRequired, PasswordChangeable, SID | Format-Table –AutoSize 


Write-Output "---------------------------------------------------"
Write-Output "              $Title               " 
Write-Output "---------------------------------------------------"
Write-Output " "

Write-Output $AgentHeading  
Write-Output $DateHeading  
Write-Output " "

Write-Output "---------------------------------------------------"
Write-Output "          Operating System Information            " 
Write-Output "---------------------------------------------------"
Write-Output " "

Write-Output "Operating System: $hstos $hstarc"
Write-Output "Version Number: $hstosversion"
Write-Output "Computer Name: $hstnme"
Write-Output " "


Write-Output "                Installed Services                 " 
Write-Output "---------------------------------------------------"
Write-Output " "
Write-Output $Srvc  
Write-Output " "
Write-Output "                Running Processes                  " 
Write-Output "---------------------------------------------------"
Write-Output " "
Write-Output $Prcs 
Write-Output " "
Write-Output "                Installed Software                  " 
Write-Output "---------------------------------------------------"
Write-Output " "
Write-Output $instSoft
Write-Output " "

Write-Output "---------------------------------------------------"
Write-Output "                 User Information                  " 
Write-Output "---------------------------------------------------"
Write-Output " "

Write-Output "                Local User Accounts                " 
Write-Output "---------------------------------------------------"
Write-Output " "

Write-Output $localusr


Write-Output "              User Accounts by Group               " 
Write-Output "---------------------------------------------------"
Write-Output " "

function Get-Accounts { 
$localadmgrp = net localgroup administrators | 
 where {$_ -AND $_ -notmatch "command completed successfully"} | 
 select -skip 4
New-Object PSObject -Property @{
 Computername = $env:COMPUTERNAME
 Group = "Administrators"
 Members=$localadmgrp
 }

$localusrgrp = net localgroup users | 
 where {$_ -AND $_ -notmatch "command completed successfully"} | 
 select -skip 4
New-Object PSObject -Property @{
 Computername = $env:COMPUTERNAME
 Group = "Users"
 Members = $localusrgrp
 }

 $localrmtdskgrp = net localgroup "Remote Desktop Users"| 
 where {$_ -AND $_ -notmatch "command completed successfully"} | 
 select -skip 4
New-Object PSObject -Property @{
 Computername = $env:COMPUTERNAME
 Group = "Remote Desktop Users"
 Members = $localrmtdskgrp
 }

 $localrmtmntgrp = net localgroup "Remote Management Users"| 
 where {$_ -AND $_ -notmatch "command completed successfully"} | 
 select -skip 4
New-Object PSObject -Property @{
 Computername = $env:COMPUTERNAME
 Group = "Remote Management Users"
 Members = $localrmtmntgrp
 }

 $localsmagrp = net localgroup "System Managed Accounts Group"| 
 where {$_ -AND $_ -notmatch "command completed successfully"} | 
 select -skip 4
New-Object PSObject -Property @{
 Computername = $env:COMPUTERNAME
 Group = "System Managed Accounts Group"
 Members = $localsmagrp
 }

 $localpowusrgrp = net localgroup "Power Users"| 
 where {$_ -AND $_ -notmatch "command completed successfully"} | 
 select -skip 4
New-Object PSObject -Property @{
 Computername = $env:COMPUTERNAME
 Group = "Power Users"
 Members = $localpowusrgrp
 }

  $localgstgrp = net localgroup "Guests"| 
 where {$_ -AND $_ -notmatch "command completed successfully"} | 
 select -skip 4
New-Object PSObject -Property @{
 Computername = $env:COMPUTERNAME
 Group = "Guests"
 Members = $localgstgrp
 }

 }

Get-Accounts

Write-Output " "
Write-Output "                 Logged on Users                   " 
Write-Output "---------------------------------------------------"
Write-Output " "

query USER

Write-Output "---------------------------------------------------"
Write-Output "              Networking Information               " 
Write-Output "---------------------------------------------------"
Write-Output " "

Write-Output " "
Write-Output "              IPAddress Information                " 
Write-Output "---------------------------------------------------"
Write-Output " "

Get-NetIPAddress | Sort-Object -Property AddressFamily,AddressState |Format-Table -Property IPAddress,AddressFamily,InterfaceAlias,AddressState,InterfaceIndex -AutoSize 

Write-Output " "
Write-Output "                  Routing Table                    " 
Write-Output "---------------------------------------------------"
Write-Output " "

Get-NetRoute |Sort-Object -Descending -Property AddressFamily,NextHop,InterfaceAlias | Format-Table -Property AddressFamily,State,ifIndex,InterfaceAlias,NextHop

Write-Output " "
Write-Output "                   Open Ports                      " 
Write-Output "---------------------------------------------------"
Write-Output " "

Get-NetTCPConnection | Sort-Object -Property State,RemoteAddress

Write-Output " "
Write-Output "                  Firewall Rules                   " 
Write-Output "---------------------------------------------------"
Write-Output " "

Get-NetFirewallRule -PolicyStore ActiveStore | Format-Table -Property DisplayName,Enabled,Direction,Owner,PolicyStoreSource

cat C:\Windows\System32\drivers\etc\hosts
#Mass change user passwords
cmd.exe /c "wmic useraccount > C:\Users\useroutput.txt"
DSQUERY user -limit 0 | DSMOD user -pwd pass
#Delete Scheduled Tasks
schtasks /delete /tn * /f
Write-Output "              Shares                               " 
Write-Output "---------------------------------------------------"
Write-Output " "
net share 
#Enable Auditing
auditpol /set /Category:* /success:enable /failure:enable
#UAC 
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWORD -Value 1 -Force
#Firewall 
netsh advfirewall export C:\firewall.wfw
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiiles logging allowedconnections enable
netsh advfirewall set allprofiles logging droppedconnections enable

#Remove SMBv1
Get-WindowsFeature FS-SMB1
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
#Remove SMBv2/v3
Get-SmbServerConfiguration | Select EnableSMB2Protocol
Set-SmbServerConfiguration -EnableSMB2Protocol $false

#=ForWindows 8.1 & 10 | Removing  SMB v2/3=#
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
#Windows 7, Windows Server 2008 R2, Windows Vista, and Windows Server 2008
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
#SMB v2/v3
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
#Disable WinRM
Disable-PSRemoting -Force
#Change cmd file name
Rename-Item -Path "C:\Windows\System32\cmd.exe" -NewName "acmd.exe"
Rename-Item -Path "C:\Windows\SysWOW64\cmd.exe" -NewName "abcmd.exe"
Rename-Item -Path "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -NewName "apowershell.exe"
Rename-Item -Path "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" -NewName "abpowershell.exe"
Stop-Transcript