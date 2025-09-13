## under development
[back to blog](../blog.md)

![alt text](../images/hollow-knight-mine.gif)

Disclaimer: This blog is for educational purposes only. The author does not condone or support illegal activity, use the information responsibly and only in environments you own or have explicit written permission to test. 

All examples shown here are drawn from the author’s self-study for red-teaming certifications and from technical blogs; environments demonstrated are owned by the author and hosted in virtual machines locally. The author accepts no responsibility or liability for any actions taken by readers that violate applicable laws, regulations, or terms of service.

The main purpose of this blog is to share knowledge about Havoc C2 and it's setup.

* [Infrastructure setup](#setup)
* [Domain](#domain)
* [VPS config](#vps-config)
  * OpenVPN
  * Linux vm
* [Redirector](redirector.md)
* Beacon/agent profile config
* FW rule
* Automating deployment via terraform

# setup

The blog contains setup that will use the following.

* Cloudflare for purchasing the domain and obtaining a certificate. (If you want to test purely locally, you’ll need multiple VMs or machines and a DNS solution such as PowerDNS.)
* VPS for HTTP/HTTPS redirector
* 1 more Redirector - still checking if AWS, DO or azure serverless. 
* VPS for OpenVPN to connect the C2 server and operator access.
* 1 VM C2 server hosted locally.
* 1 VM for C2 operator.
* 1 Target machine hosted locally, ideally on a separate physical machine or a cloud VM (AWS/Azure). Note that testing on cloud VMs may require prior permission see AWS penetration testing guidelines for details: [AWS pentest guidelines](https://aws.amazon.com/security/penetration-testing/) check the simulated events.

Why am I sharing this notes ? well it's to help other pentester/red teamer or people doing certs related to red teaming. I’m still learning, so some OPSEC trade-offs or imperfect practices may appear.

# Domain

When purchasing a domain for red teaming infrastructure, there are several important considerations to weigh to improve operational reliability, reduce detection risk, and avoid rapid takedowns.


| Title                          | Description |
|--------------------------------|-------------|
| Domain fronting                | Domain fronting is a technique that attempts to hide the true destination of network traffic by making the connection appear to go to a trusted, well-known hostname (such as a major CDN), while the request is internally forwarded to a different backend hostname. It’s used to blend malicious or sensitive traffic into normal-looking traffic, evade simple host-based blocking, or bypass censorship. [Domain fronting](https://bigb0ss.medium.com/redteam-c2-redirector-domain-fronting-setup-azure-adbedbd28305), [Domain fronting 2](https://www.zscaler.com/blogs/security-research/analysis-domain-fronting-technique-abuse-and-hiding-cdns). |
| Domain aging                   | Older, legitimately aged domains generally have better reputations and are less likely to be blocked immediately. Check historical usage (archive.org, passive DNS) before buying. |
| Domain categorization          | Security vendors and web filters categorize domains (example: malware, news, gambling). Verify category/reputation with reputation services to avoid instant blocking. [Domain categeroziation](https://tools.zvelo.com/). |
| Registrar blocking / takedown risk | Some registrars respond quickly to abuse complaints. Choose a reputable registrar, read their abuse/TOS policies, and plan backups in case of suspension. Another thing to note here, these registrars search for keywords or phrases that are commonly used for phishing or used by malwares or bots. |
| TLD choice                     | Some TLD are closely monitored or commonly abused. Use mainstream or context-appropriate TLD (.com, .org, regional TLDs) for better blend in the network. |
| DNS reputation & hosting       | Where you host DNS affects credibility. Reputable DNS providers (Cloudflare, Route53, etc.) look more legitimate than obscure/cheap providers associated with abuse. |
| SSL / TLS certificate          | Use certificates from trusted CAs (Let’s Encrypt, commercial CAs) to avoid TLS errors and reduce suspicion. Self-signed certs are more likely to be flagged. |
| WHOIS privacy                  | Privacy protection hides registrant details but can sometimes raise suspicion. Balance anonymity with perceived legitimacy depending on the engagement. |
| Cost & burn rate               | Expect some domains to "burn" quickly. Budget for replacements, consider domain lifecycle, and plan redundancy (multiple domains/hosts). |


Since this will be just an example, I will not wait for a long time to have a domain aging or categorization.

The example will use cloudflare because, I find it easy to manage the domains here and it gives other features such as domain privacy and stuffs.

# VPS config

## Resources
https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki

![https://tenor.com/view/silksong-hollow-knight-hollow-night-silksong-faridulasimanet-sherma-silksong-gif-171830693794769624](../images/silksong-hollow-knight.gif)

[back to blog](../blog.md)

