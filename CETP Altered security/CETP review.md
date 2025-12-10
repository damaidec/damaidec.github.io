[back to blog](../blog.md)

# Certified Evasion Techniques Professional (CETP) 

This blog will contain what is the course about, my opinion about the course, how is it compared to other evasion courses and the exam preparation.

## What is the course about ?

The course focus on reverse engineering, kernel exploitation and heavily utilizes the Bring Your Own Vulnerable Driver (BYOVD) technique to terminate AV/EDR or downgrade their tokens, resulting in effective evasion. The course also teaches how to bypass several hardening mechanisms applied on servers, such as kernel protections, PPL and ASR. In addition, it covers how to backdoor a ClickOnce application for initial access, bypass static detection, and much more.

As shown on their website https://www.alteredsecurity.com/evasionlab, the course environment includes Microsoft Defender for Endpoint (MDE) and Elastic EDR installed in the lab and exam machines. You are also given access to the dashboard, allowing you to observe what gets detected.
![alt text](image-1.png)

The course is explained very well, enabling students with or without prior experience to understand how the kernel works, how AV/EDR works (not at an extremely deep level just enough for beginners), and how to bypass these protections at the kernel level. They also provide you the code and it's also have comments, sometimes instructions allowing students without knowledge in coding on C to follow what was happening on certain functions.

## Exam preparation tips

I created this blog because there aren’t many resources available for CETP, since it’s a relatively new course at the time of writing.

So how did I prepare for my exam?

* Similar to their other courses, what they teach you in the modules is kinda similar to what appears in the exam. So **always complete the labs they provide**. The labs give you a clear understanding of how everything is configured, how the defenses are applied, and you also get to test different attacks and techniques. Practice makes perfect.

* If you have your own home lab environment, you can try using a trial subscription or the freemium version of the target AV/EDR and test your payloads there. (This is what I did first because the modules were still incomplete at the time.)

* This is probably the most important part: **You must have your payloads/executables ready and ensure they work and can evade AV/EDR both static and dynamic detection.**

* Since the exam has no limitations on commands or what you can execute, it’s helpful to have knowledge of other tools, and TTPs, such as using LOLBAS for enumeration, privilege escalation, or post-exploitation.

* Because the course revolves around terminating AV/EDR, staying updated on the latest tools that do the same thing can be beneficial.

* This is optional and just my opinion: If you find a 0 day or created a PoC for an N day, you can use it, since there are no restrictions. However, be careful using a 0 day or N day, this can result into burning the tool quickly. Make sure to explain that in your report if you choose to use one, and ensure you redact sensitive details.

* As usual, always perform heavy enumeration. The more information you gather, the better your understanding and the larger your attack surface. Always perform situational awareness recon.

* This is just my preference, but in your reporting, always explain everything in detail. I even included explanations of how the exploit works, the code, etc. Just like in a regular pentest, always structure your report properly.

* After the exam, I got some free time and vibecoded an enumtool that does multiple thing for enumeration. https://github.com/damaidec/enumlochost. It's up to you how you would bypass the detection for the app and use what you learn on CETP.

## My opinion

There was a time when my LinkedIn feed was always related to EDR killer and lots in the community was posting about BYOVD techniques used to terminate AV/EDR for evasion. I’m not sure if it was a coincidence or not, but when the course was released, there seemed to be an increase in BYOVD content related to AV/EDR evasion. 

* https://www.crowdstrike.com/en-us/blog/falcon-prevents-vulnerable-driver-attacks-real-world-intrusion/
* https://www.eset.com/blog/en/business-topics/threat-landscape/stop-edr-killers/
* https://www.broadcom.com/support/security-center/protection-bulletin/protection-highlight-impairing-defense-using-av-edr-killers

My thoughts after finishing the course are mixed. On one hand, it was very cool because I learned how to exploit Windows kernel drivers and other techniques. On the other hand, I would be hesitant to use these attacks during a pentest or red team projects. There are many considerations to keep in mind for example, using this during a pentest could easily burn the resource. Another factor is the constant risk or fear of causing a denial of service (since you are at a kernel level and it's very sensitive). While the techniques are powerful and can help you achieve your objective, they require rigorous testing on different versions and environment to ensure they work properly and do not cause any disruption to the client’s machines.

One thing I did not like, probably, is the idea of terminating the AV/EDR. While it is considered evasion, obtaining the required permissions or user privileges to load a kernel driver is difficult. At the very least, you need either an administrator account or SeLoadDriverPrivilege, along with permission to create a service in order to conduct the attack. However, if a vulnerable driver is already loaded and running, then it’s fine you can simply upload and run the exploit application.

I understand that red teaming has different stages, but to use this technique effectively, you would typically need to complete the initial access, privilege escalation, and be in the post exploitation phase because this technique has high requirements, so it can only realistically be used at that point in my opinion.

On the other hand the course was amazing and I really took a liking to windows kernel reversing and exploitation. Hopefully altered security would consider adding a course specifically focused on windows kernel exploitation vulnerabilities such as, User After Free, Buffer/Heap overflows and etc. to achieve privilege escalation or RCE.

## Compared to other evasion courses

On this section, I will only use the courses that I bought for comparing, but some of them may be different because those courses are focused on red teaming and includes a way for AV/EDR evasion for the whole red team process. 

Honestly, I don’t like comparing courses because each one has its own strengths, focus, and specialties. Every course teaches you different techniques and provides knowledge that others might not cover.

| Course | Description | CETP comparison
| -------- | -------- | -------- 
| Maldev academy - Malware development course| Maldev Academy is a very good course to get you started in malware development and to help you understand how endpoint security solutions work. They constantly update their courses and add new techniques that can potentially evade AV/EDR. Of course, it’s up to the developer to apply these techniques properly in order to evade AV/EDR successfully.<br><br>Note that Maldev Academy does not offer a certification it is only a course as of the time of writing. However, when you finish the course, you do receive a certificate of completion.| Maldev also touched on the BYOVD concept, and both courses did a good job explaining how it works. The difference I see is this: in CETP, the code is explained through video and comments are added on the code as well. CETP also covers BYOVD deeply. Maldev provides written explanations of how the code works, the Windows API structures, and more.<br><br>In conclusion, if you want to learn additional techniques such as different process injections, various AMSI/ETW bypass methods, NTDLL unhooking, and other techniques, then Maldev would be a great choice.
| Offensive Development Practitioner Certification (ODPC) from whiteknight labs| ODPC is certainly more advanced compared to CETP. This course and certification are very thorough it teaches you everything from the basics of coding to evading different EDRs like Sophos, MDE, Elastic, CrowdStrike, and more, all without killing or terminating the process. It also provides a set of tasks that challenge you to evade specific EDR vendors, such as using a particular process injection technique to bypass a specific EDR.<br><br>Another thing that CETP probably lacks is the use of C2 frameworks and OPSEC. In ODPC, you are taught how to use C2 frameworks and how to apply proper OPSEC. |I haven’t checked yet if ODPC have released any updates, but in their other courses they also used BYOVD for evasion.<br><br>Comparing CETP to ODPC: <br>CETP is more focused on the kernel level and mainly revolves around BYOVD techniques for AV/EDR evasion. Meanwhile, ODPC similar to Maldev Academy, it offers various techniques but focuses on developing a loader or malware capable of evading multiple EDRs using different approaches. It also requires you to obtain a session callback to a C2 and continue all the way through post exploitation<br>The caveat with ODPC is that you must host your own environment on AWS, which can become very expensive depending on your usage.<br>Both courses provides the source code, PDFs, and video materials.
| Hackthebox - Introduction to Windows Evasion Techniques | As the course suggests, it is an introduction so in this Hack The Box module, only a few AV evasion techniques are taught, and no EDR is included. However, the course does cover techniques such as process injection, modifying the source code of open source tools, using reflectively loaded assemblies technique, and more. This module is also part of CAPE certification | Comparing it to CETP,  The HTB module does not include any EDR evasion or kernel-level exploitation. Instead, it focuses on techniques like process injection and goes a bit deeper into topics such as using ThreatCheck to determine whether an executable gets detected and teaching you the basics of evasion and various techniques.<br>If you are specifically looking for EDR evasion, then CETP is the better choice. But if you want to strengthen your understanding of general evasion techniques, or knowing how process injection works you may want to explore HTB’s module. Another thing to note is that HTB does not provide video content, unlike CETP.
| CRTO/CRTO2 of zeropointsecurity, whiteknightlab's ARTOC, ROPS-RT1 roguelabs | I grouped these three together because they are all related to red team operations, and a major part of that involves evading AV/EDR while using a C2 and maintaining good OPSEC. CRTO focuses only on AV and does not include EDR, while CRTO2 and ARTOC include both AV and EDR. I won’t go into much detail about these courses since they are very different from CETP.<br><br>However, the evasion components in these courses showcase multiple techniques, such as building an evasive loader, bypassing detections in open source tools by modifying their code, and moving stealthily from initial access all the way through lateral movement and post-exploitation until you reach your objective. They also teach OPSEC throughout the process. | Compared to the other courses, CETP lacks broader techniques and OPSEC. However, the technique that CETP teaches is guaranteed to work for evasion if you are able to obtain the required permissions. It also goes much deeper into kernel exploitation, which other courses may not cover.<br><br>In that sense, CRTO, CRTO2, and ARTOC are focused on full end to end red teaming with evasion. If your goal is to understand how to evade and bypass AV/EDR while using a C2, then CRTO, ROPS-RT1, CRTO2, or ARTOC would be the better choice. 

* https://maldevacademy.com/maldev-course/syllabus
* https://academy.hackthebox.com/course/preview/
introduction-to-windows-evasion-techniques
* https://training.whiteknightlabs.com/live-training/offensive-development-practitioner-certification/
* https://www.zeropointsecurity.co.uk/courses
* https://training.whiteknightlabs.com/certifications/advanced-red-team-operations-certification/


sauce ruri dragon

![alt text](image.png)

[back to blog](../blog.md)]