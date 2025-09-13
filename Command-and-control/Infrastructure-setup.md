## under development
[back to blog](../blog.md)

Disclaimer: This blog is for educational purposes only. The author does not condone or support illegal activity, use the information responsibly and only in environments you own or have explicit written permission to test. 

All examples shown here are drawn from the author’s self-study for red-teaming certifications and from technical blogs; environments demonstrated are owned by the author and hosted in virtual machines locally. The author accepts no responsibility or liability for any actions taken by readers that violate applicable laws, regulations, or terms of service.

The main purpose of this blog is to share knowledge about Havoc C2 and it's setup.

![alt text](../images/hollow-knight-mine.gif)

* Infrastructure setup
  * VPN config
  * [Redirector](redirector.md)
  * Beacon/agent profile config


The blog contains setup that will utilize the services of

* Cloudflare - to buy domain and get a certificate (if you want to test purely locally you must have a lot of VM opened/computer and have a powerdns)
* VPS for HTTP/HTTPS redirector
* 1 more Redirector - still checking if AWS, DO or azure serverless. 
* Another VPS but an OpenVPN for C2 server and client.
* 1 VM with C2 server hosted locally (should be isolated)
* 1 VM for C2 operator
* 1 Target machine hosted locally but ideally it would be great if it's on a different computer with VM, or AWS / azure windows VM (but the thing about those 2 you need to get a permission if you will test something related to that)

![https://tenor.com/view/silksong-hollow-knight-hollow-night-silksong-faridulasimanet-sherma-silksong-gif-171830693794769624](../images/silksong-hollow-knight.gif)

[back to blog](../blog.md)

