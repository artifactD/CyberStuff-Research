# Who Is APT29

APT29 (AKA CozyBear, The Dukes, Group 100, CozyDuke, EuroAPT, CozyCar, Cozer, Office Monkey, YTTRIUM, Iron Hemlock, Iron Ritual, Cloaked Ursa, Nobelium, Group G0016, UNC2452, Dark Halo, NobleBarron) is an advanced persistent threat actor (APT) active since 2008 and considered to be a product of the Russian government’s Foreign Intelligence Service (SVR). Few threat actors show the technical discipline and sophistication of APT29, especially in its ability to adapt to defensive IT security tactics, penetrate well-defended networks, and deploy malware with anti-forensic capabilities.

APT29’s primary targets are governments and government subcontractors, political organizations, research firms, and critical industries such as energy, healthcare, education, finance, and technology in the US and Europe. APT29 primarily intends to disrupt national security, impact critical infrastructure, and cause political interference.

# Campaigns 

 - <b> Operation Ghost (2013-2019) </b>
    * Acquire Infrastructure: Domains, Data Obfuscation: Steganography
    * Develop Capabilities: Malware
    * Establish Accounts: Social Media Accounts
    * Event Triggered Execution: Windows Management Instrumentation Event Subscription
    * Obfuscated Files or Information: Steganography
    * Valid Accounts: Domain Accounts
    * Web Service: Bidirectional Communication

 - <b>Grizzly Steppe (2015-2016)</b>
    * Directed emails containing a malicious link domains, to include domains associated with U.S. organizations and educational institutions, to host malware and send spearphishing emails. 
    * Established persistence, escalated privileges, enumerated active directory accounts, and exfiltrated email from several accounts through encrypted connections back through operational infrastructure.
    *  Directed emails containing link to fake webmail domain tricked recipients into changing their passwords. 
    * Using the harvested credentials, APT28 was able to gain access and steal content, likely leading to the exfiltration of information from multiple senior party members.  
<t>  

 - <b>SolarWinds (2019-2021)</b>
    * Account Discovery: Domain Account
    * Account Manipulation: Device Registration
    * Command and Scripting Interpreter: PowerShell
    * Command and Scripting Interpreter: Visual Basic
    * Command and Scripting Interpreter: Windows Command Shell
    * Compromise Infrastructure: Domains
    * Credentials from Password Stores: Credentials from Web Browsers, Credentials from Password Stores, Data from Information Repositories
    * Data from Information Repositories: Code Repositories, Data from Local System
    * Data Staged: Remote Data Staging, Deobfuscate/Decode Files or Information
    * Develop Capabilities: Malware
    * Domain Policy Modification: Domain Trust Modification, Domain Trust Discovery, Dynamic Resolution
    * Email Collection: Remote Email Collection
    * Event Triggered Execution: Windows Management Instrumentation Event Subscription
    * Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol, Exploit Public-Facing Application, External Remote Services, File and Directory Discovery
    * Forge Web Credentials: Web Cookies, SAML Tokens
    * Gather Victim Identity Information: Credentials
    * Impair Defenses: Disable Windows Event Logging, Disable or Modify Tools, Disable or Modify System Firewall
    * Indicator Removal: File Deletion, Timestomp, Clear Mailbox Data, Ingress Tool Transfer
    * Masquerading: Match Legitimate Name or Location, Masquerade Task or Service, 
    * OS Credential Dumping: DCSync
    * Remote Services: Windows Remote Management, SMB/Windows Admin Shares, Remote Desktop Protocol, Remote System Discovery
    * Scheduled Task/Job: Scheduled Task
    * Steal or Forge Kerberos Tickets: Kerberoasting, Steal Web Session Cookie
    * Subvert Trust Controls: Code Signing
    * System Binary Proxy Execution: Rundll32, System Information Discovery
    * System Network Configuration Discovery: Internet Connection Discovery, Trusted Relationship
    * Unsecured Credentials: Private Keys 
    * Use Alternate Authentication Material: Application Access Token, Web Session Cookie, Use Alternate Authentication Material

# Software Used by APT 29
|Program (Desription)|In Depth Descrition Below Table|
|-|-|
| - AADInternals (Administration) | <span style="color: #007ea7;">- Meek (TOR Domain Fronting Plugin)</span>
|- AdFind (AD Query Tool) | <span style="color: #c34632;">- Mimikatz (Malware)</span>
|<span style="color: #3bd16f;">- BloodHound (Mapper)</span> | - MiniDuke
|<span style="color: #c34632;">- BoomBox (Downloader)</span> | - NativeZone
|<span style="color: #e75480;">- CloudDuke (Toolset)</span> | - Net
|<span style="color: #e75480;">- Cobalt Strike (Toolset)</span> | - OnionDuke
|<span style="color: #e75480;">- CosmicDuke (Toolset)</span> | - PinchDuke
|<span style="color: #b589d6;">- Cozyduke (Backdoor)<span> | - PolyglotDuke
|<span style="color: #c34632;">- EnvyScout (Dropper)</span> | - POSHSPY (WMI/Poweshell Backdoor)
|<span style="color: #b589d6;">- FatDuke (Backdoor)</span> | - PowerDuke
|<span style="color: #b589d6;">- FoggyWeb (Backdoor)</span> | - PsExec
|- GeminiDuke                          | - Raindrop/Teardrop (Memory Only Dropper)
|- GoldMax (Linux Backdoor)            | - RegDuke
|- HAMMERTOSS (Backdoor)               | - ROADTools
|- ipconfig                            | - SDelete
|- LiteDuke                            | - SeaDuke (Trojan)
|- Sibot (Downloader)                  | - Sliver
|- SoreFang (Malware)                  | - SUNBURST (Backdoor)
|- SUNSPOT                             | - Systeminfo
|- Tasklist                            | - TrailBlazer (Malware)
|- WellMess (Malware: Shell over SMTP) | - WellMail (Malware: Shell over SMTP)
|- VaporRage/BOOMMIC (Downloader)      | - Tor

* <span style="color: #3bd16f;"><b>BloodHound</b> <i>(Mapper)</i></span>
    * Reveals hidden and unintended relationships within an Active Directory or Azure to easily gain a deeper understanding of privilege relationships in an environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify.
    * [Link To Project](https://github.com/BloodHoundAD/BloodHound)

* <span style="color: #c34632;"><b>BoomBox</b> <i>(Downloader)</i></span>
    * Malicious downloader that enumerates a victims machine before exporting information to a .pdf and exfiling the data via Dropbox.
    * Will see POST in network traffic confirming information was exfilled.
    * [I Need to Find Link To Project Still...]()

* <span style="color: #e75480;"><b>CloudDuke</b> <i>(Toolset)</i></span>
    * Consists of at least a loader, a downloader, and two backdoor variants.
    * Both backdoors (“BastionSolution” & “OneDriveSolution”) allow the operator to remotely execute commands on the compromised machine. 
        * BastionSolution retrieves commands from a hard-coded C&C server 
        * OneDriveSolution (more difficult to detect) utilizes Microsoft’s OneDrive cloud storage service for communicating with its masters.
    * [I Need to Find Link To Project Still...]()

* <span style="color: #e75480;"><b>Cobalt Strike</b> <i>(Toolset)</i></span>
    * Customizable attack framework distributed as single Java archive file (JAR), but contains several components: 
        * a command-and-control server known as the Team Server
        * a client that runs on the attacker’s machine w/ a GUI for server interaction
        * a remote access implant known as the Beacon
    * [Link To Project](https://github.com/Cobalt-Strike/community_kit)

* <span style="color: #e75480;"><b>CosmicDuke</b> <i>(Toolset)</i></span>
    * Custom written toolset designed around a main information stealer component augmented by a variety of components that establish persistence, perform privilege escalation vulnerabilities, keylogging, taking screenshots, stealing clipboard contents, stealing user files,exporting certificates and private keys, collecting user credentials and passwords, and uses HTTP, HTTPS, FTP or WebDav to exfiltrate the collected data to a hardcoded C&C server.
    * [I Need to Find Link To Project Still...]()

* <span style="color: #b589d6;"><b>CozyDuke</b> <i>(Backdoor)</i></span>
    * Previous CozyDuke spear-phishing emails contained a link to a zip-archive file named “Office Monkeys LOL Video.zip”, which was hosted on the DropBox cloud storage service.
    * A platform formed around a core backdoor component. This component can be instructed by the C&C server to download and execute arbitrary modules, and it is these modules that provide CozyDuke with its vast array of functionality. 
    * Known CozyDuke modules include: 
        * Command execution module for executing arbitrary Windows Command Prompt commands
        * Password stealer module
        * NT LAN Manager (NTLM) hash stealer module
        * System information gathering module
        * Screenshot module In addition to modules
        * Download and execute other independent executables
    * [I Need to Find Link To Project Still...]()

* <span style="color: #c34632;"><b>EnvyScout</b> <i>(Dropper)</i></span>
    * A self-contained HTML file which is a dropper-style malware that writes a malicious ISO to disk via a modified version of the open source FileSaver javascript too. This tool allows the JavaScript to write files directly to disk, allowing the adversary to conduct HTML smuggling.
    * [I Need to Find Link To Project Still...]()

* <span style="color: #b589d6;"><b>FatDuke</b> <i>(Backdoor)</i></span>
    * Backdoor that affects Windows operating systems and has the ability to execute PowerShell scripts, copy files and directories, delete files and directories, get user agent strings for the default browser, communicate using application layer protocols, add entries to the run keys, and list running processes on the localhost. FatDuke has also been observed to use pipes to connect machines with restricted internet access to remote machines via other infected hosts.
    * [I Need to Find Link To Project Still...]()

* <span style="color: #b589d6;"><b>FoggyWeb</b> <i>(Backdoor)</i></span>
    * A passive and highly targeted backdoor capable of exfiltrating sensitive information from compromised AD FS server’s. It can exfiltrate configuration databases, download and execute additional components, as well as receive and execute malicious components from a C2 server.
    * [I Need to Find Link To Project Still...]()

* <span style="color: #007ea7;"><b>Meek</b> <i>(TOR domain fronting plugin)</i></span>
    * Creates a hidden, encrypted network tunnel that connects to Google services over TLS. This tunnel provides the attacker remote access to the host system using the Terminal Services, NetBIOS, and Server Message Block (SMB) services, while appearing to be traffic to legitimate websites.
    * [Link To Project](https://gitlab.torproject.org/legacy/trac/-/wikis/doc/AChildsGardenOfPluggableTransports#meek)

* <span style="color: #c34632;"><b>Mimikatz</b> <i>(Malware)</i></span>
    * Extracts plaintext passwords, hashes, PIN codes and kerberos tickets from memory. It can also perform pass-the-hash, pass-the-ticket or build Golden tickets.
    * [Link To Project](https://github.com/ParrotSec/mimikatz)


Normal  
*Italic*  
**Bold**  


# Information Collection Commands
```
- systeminfo.exe
- ipconfig.exe /all
- cmd.exe /c set
- net.exe user
- HOSTNAME.EXE
- net.exe user /domain
- net.exe group /domain
- tasklist.exe /V
- whoami.exe /all
```

# TTPS 

- Attacker infected 10 systems per day with primary backdoor family 
- Accessed Hundreds of systems for recon and cred theft 
- Removed tools and foresnic artifacts to hide activity 
- Use of SSL for C2 Comms
- Extensive use of Microsoft’s secure delete tool (SDELETE) following interactive operations on a host
- Clean up Prefetch entries
- Exploit VPNs/VPN devices
- Supply chain compromise
- Steal e-mails remotely or harvest local OST and PST files
- Masqueraded malicious scheduled tasks, processes, and shortcut files as legitimate tasks, binaries, and documents
- Spearphishing campaigns leveraging web links to a malicious dropper; once executed, the code delivers RATs
- Used temporary file replacement to remotely execute utilities.
- Updated an existing legitimate task to execute their tools, then returned the scheduled task to its original configuration
- Matched hostnames to the victim environment’s naming convention
- Leveraged native Microsoft tools
- Used a mixture of TOR, VPS, and VPNs to access victim environments
- Modified a legitimate Microsoft DLL to enable the DLL Side Loading of a malicious payload
- Minimized the size of exfiltrated data and used encrypted connections for data exfiltration
- Detected and disabled antivirus and system logging features then reenabled these features upon completion of malicious activity
- Disabled SysInternals Sysmon and Splunk Forwarders on victim machines that they accessed via Microsoft Remote Desktop
- Cleared Windows Event Logs
- Accessed IT personnel mailboxes to monitor remediation efforts and adjust TTPs as needed
- Encrypted C2 traffic is encoded with a slightly modified Base64 algorithm


- MimiKatz Powershell: "C:\Windows\temp\diag3.ps1"
-- Slide 25: https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016
- Self-extracting archive with PsExec.
--https://blog-assets.f-secure.com/wp-content/uploads/2020/03/18122307/F-Secure_Dukes_Whitepaper.pdf
- Moved laterally with PsExec.
--https://www.welivesecurity.com/wp-content/uploads/2019/10/ESET_Operation_Ghost_Dukes.pdf

[link^](https://www.mandiant.com/resources/apt29-domain-frontin)

# Persistence Methods 

- Sliver opensource framework for implants
- reistry run key 
- .lnk files 
- services
- wmi 
- named scheduled tasks
- hijacking scheduled tasks
- over-writing legitimate files
- Path Interception by Search Order Hijacking
- REGEORG web shell

# Persistence Registry/Task/Service Names

WMI event subscription to launch POSHSPY (malicious PowerShell payload). Custom WMI event name: BfeOnServiceStartTypeChange

* Services: 
    - b

* Reg Keys: (-RegKey File)
    - HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\AgendaE
    - HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\AdobeUpdate
    - HKCU\software\Microsoft\Windows\CurrentVersion\Run\Java Update
    - HKU\SOFTWARE\Microsoft\CTF (Vulnerability)


* SchTasks: (-Name File)
    - taskhostsvc.exe (SUNSPOT)
    - Sibot C:\Windows\System32\Tasks\Microsoft\Windows\WindowsUpdate\sibot
    - BfeOnServiceStartTypeChange (Poshspy - configured to execute every Monday, Tuesday, Thursday, Friday, and Saturday at 11:33 am local time)
    - The GoldMax malware was discovered persisting on networks as a scheduled task impersonating systems management software. In the instances it was encountered, the scheduled task was named after software that existed in the environment, and pointed to a subfolder in ProgramData named after that software, with a similar executable name. The executable, however, was the GoldMax implant.

# C2 Domains/IPs
* Domains
    * porodicno[.]ba/wp-content/Agenda.html
    * jmj[.]com/personal/nauerthn_state_gov/TUJE7QJl
    * wethe6and9[.]ca/wp-content/Agenda.html
    * dropbox[.]com/s/raw/dhueerinrg9k97k/agenda.html
    * crossfity[.]com
    * techspaceinfo[.]com
    * sanjosemaristas.com/app/index.php
    * ciss.org/product_thumb/index.php
    * pvt.relance.fr/catalogue/json/index.php
    * getiton.hants.org.uk/themes/front/img/ajax.php
    * seccionpolitica.ar/galeria/index.php
    * 6a57jk2ba1d9keg15cbg.appsync-api.eu-west-1.avsvmcloud[.]com
    * freescanonline[.]com	
    * 7sbvaemscs0mc925tb99.appsync-api.us-west-2.avsvmcloud[.]com
    * deftsecurity[.]com
    * gq1h856599gqh538acqn.appsync-api.us-west-2.avsvmcloud[.]com
    * ihvpgv9psvq02ffo77et.appsync-api.us-east-2.avsvmcloud[.]com
    * thedoccloud[.]com	
    * k5kcubuassl3alrf7gm3.appsync-api.eu-west-1.avsvmcloud[.]com
    * thedoccloud[.]com
    * mhdosoksaccf9sni9icp.appsync-api.eu-west-1.avsvmcloud[.]com
    * websitetheme[.]com
    * highdatabase[.]com
    * incomeupdate[.]com
    * databasegalore[.]com
    * pandorasong[.]com
    * panhardware[.]com
    * zupertech[.]com
    * matysovi@seznam[.]cz

- Domains
    - 204.188.205.176
    - 51.89.125.18
    - 200.119.128.45
    - 202.206.232.20
    - 200.125.133.28
    - 200.125.142.11
    - 203.156.161.49
    - 209.40.72.2
    - 210.59.2.20
    - 121.193.130.170
    - 208.75.241.246
    - 183.78.169.5
    - 201.76.51.10
    - 208.77.177.24
    - 185.47.128[.]39
    - 31.31.74[.]79
    - 103.103.128[.]221
    - 103.13.240[.]46
    - 103.205.8[.]72
    - 103.216.221[.]19
    - 103.253.41[.]102
    - 103.253.41[.]68
    - 103.253.41[.]82
    - 103.253.41[.]90
    - 103.73.188[.]101
    - 111.90.146[.]143
    - 111.90.150[.]176
    - 119.160.234[.]163
    - 119.160.234[.]194
    - 119.81.173[.]130
    - 119.81.178[.]105
    - 120.53.12[.]132
    - 122.114.197[.]185
    - 122.114.226[.]172
    - 141.255.164[.]29
    - 141.98.212[.]55
    - 145.249.107[.]73
    - 146.0.76[.]37
    - 149.202.12[.]210
    - 169.239.128[.]110
    - 176.119.29[.]37
    - 178.211.39[.]6
    - 185.120.77[.]166
    - 185.145.128[.]35
    - 185.99.133[.]112
    - 185.225.69[.]69
    - 191.101.180[.]78
    - 192.48.88[.]107
    - 193.182.144[.]105
    - 202.59.9[.]59
    - 209.58.186[.]196
    - 209.58.186[.]197
    - 209.58.186[.]240
    - 220.158.216[.]130
    - 27.102.130[.]115
    - 31.170.107[.]186
    - 31.7.63[.]141
    - 45.120.156[.]69
    - 45.123.190[.]167
    - 45.123.190[.]168
    - 45.152.84[.]57
    - 46.19.143[.]69
    - 5.199.174[.]164
    - 66.70.247[.]215
    - 79.141.168[.]109
    - 81.17.17[.]213
    - 85.93.2[.]116

# Filenames:

(Note: we believe many of these to be borrowed from legitimate files) 
- Often renames files to appear benign
- Droppers: EnvyScout
- Covid.iso
- AcroSup.dll
- javafx_font.dll (363a95777f401df40db61148593ea387)
- A102-459_javafx_font.dll (363a95777f401df40db61148593ea387)
- SharedReality.dll
- (Legitimate executable, used maliciously) rundll32.exe
- partmgr.sys
- Jmy8PWiOYlMB8nVjO5OHUzRkK.elf
- nm0aKToojAbt7FEeXpUoW.elf
-0c5ad1e8fe43583e279201cdb1046aea742bae59685e6da24e963a41df987494.exe
- xyq2caJ3wOXmGlk.elf
- Qpsz6WZmbj8KVKg.elf
- DAOjk83QWS9nl1ZTQKdUqSeM.elf
- RlCqCu94Au9lh6XvX5SvIvPqk.elf
- VL9XrtPGo2RZxKTCpIQ5Um1.elf
- AFKiuPHVvNh5hQ4w7OEMhVrl06.elf
- LfwBIV5JcftLdgvMlT8cmxhwl9.elf
- %WinDir%\ADFS\version.dll (FoggyWeb)
- %WinDir%\SystemResources\Windows.Data.TimeZones\pris\Windows.Data.TimeZones.zh-PH.pri (FoggyWeb)
- gracious_truth.jpg (fake .jpg header)
- c:\windows\syswow64\netsetupsvc.
- sun.dll
- NV.lnk
- %WinDir%\SystemResources\Windows.Data.TimeZones\pris\Windows.Data.TimeZones.zh-PH.pri
-32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77.exe
- Lexicon.exe
- 488977.exe
- C:\Windows\ELAMBKUP\WdBoot.dll
- C:\Windows\Registration\crmlog.dll
- C:\Windows\SKB\LangModel.dll
- C:\Windows\AppPatch\AcWin.dll
- C:\Windows\PrintDialog\appxsig.dll
- C:\Windows\Microsoft.NET\Framework64\sbscmp30.dll
- C:\Windows\Panther\MainQueueOnline.dll
- C:\Windows\assembly\GAC_64\MSBuild\3.5.0.0__b03f5f7f11d50a3a\msbuild.dll
- C:\Windows\LiveKernelReports\KerRep.dll
- MKDRR.elf
- WysWoIq2nOx8VzJqXV3QWxVHfKc.exe
- \\Sangfor\\SSL\\SanforUPD.exe

# File Locations:
```
c:\Windows\System32 ; malicious DLL's are renamed to appear benign 

Temporary Directories:

%Temp%
%AppData%
%LocalAppData%
%UserProfile%\Local Settings\Temp\


System Directories: 

%SystemRoot%\System32\
%SystemRoot%\SysWOW64\ (on 64-bit systems)
%SystemRoot%\Tasks\
%SystemRoot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\


User Directories:

%UserProfile%\Desktop\
%UserProfile%\Documents\
%UserProfile%\Downloads\
%UserProfile%\AppData\Roaming\


Program Files Directories: Malicious files can be placed in program files directories:

%ProgramFiles%
%ProgramFiles(x86)%\ (on 64-bit systems)

```
---
---
---

# Ideas on actions to use

<u><strong>Initial Access:</strong></u> JDNI? Phishing (HTML smuggling w/ISO attachment)? Alt CVE?

<u><strong>Lateral movement:</strong></u> WMI for less prints than PSExec?

<u><strong>Persistence:</strong></u> Scheduled task on initial box (taskhostsvc.exe), WMI Subscription (event name BfeOnServiceStartTypeChange) on other boxes.  Web Shell on Exchange?

<strong><u>Malware:</strong></u>


# C2 Domains/IPs/Filenames (TOP PICKS)
<b>Domains -</b> 
* twitter.com
* google.com (Drive)

<b>IP's -</b> 


<b>Filenames -</b>


# Persistence (TOP PICKS)
```

``` 

# Research Links for APT 29
| Resources                   | Links                                                                    |
|-----------------------------|--------------------------------------------------------------------------|
| APT 29 MITRE ATTACK         | [Click](https://attack.mitre.org/groups/G0016/)                          |
| Dukes Cobalt Strike Profile | [Click](https://github.com/xx0hcd/Malleable-C2-Profiles/tree/master/APT) |
| Setting up Sticky Keys      | [Click](https://www.top-password.com/blog/reset-windows-10-password-with-sticky-keys/)
| Implementing Sticky Keys backoor using reg keys | [Click](https://doublepulsar.com/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)
| Documents with specific TTPs/files name/File Drop locations | [Click](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/)
| Document on APT29 Phishing campaign with good highlighted TTPs  | [Click](https://www.mandiant.com/resources/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign)
| Code we could upload as Artifacts | [Click](https://github.com/kernweak/POSHSPY/blob/master/poshspy_redacted.txt)
| More Code for possible Artifacts  | [Click](https://github.com/matthewdunwoody/POSHSPY/blob/master/poshspy_redacted.txt)
| Cobalt Strike Artifact kit and anti-virus evasion:  | [Click](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/artifacts-antivirus_main.htm?cshid=1017)
| Deep Dive into Solorigate 2nd Stage Activation | [Click](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/) | 
| TOR Fronting | [Click](https://www.vincentyiu.com/red-team/domain-fronting/tor-fronting-utilising-hidden-services-to-hide-attack-infrastructure)
| Attack Methods (2017) | [Click](https://miguelbigueur.com/2017/10/20/russian-apt-analysis-apt29-aka-the-dukes/)
| Attack Methods (2019) | [Click](https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163418/CozyDuke.pdf)
| Attack Methods (2021) | [Click](https://raw.githubusercontent.com/microsoft/mstic/master/Indicators/May21-NOBELIUM/May21NOBELIUMIoCs.csv) 
| Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY) | [Click](https://www.mandiant.com/resources/dissecting-one-ofap) 
| THERE’S SOMETHING ABOUT WMI PDF | [Click](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf) 
| Canadian Intel on APT29 IOCs and YARA rules | [Click](https://media.defense.gov/2020/Jul/16/2002457639/-1/-1/0/NCSC_APT29_ADVISORY-QUAD-OFFICIAL-20200709-1810.PDF)
| GITHUB APT IOCs List | [Click](https://github.com/RedDrip7/APT_Digital_Weapon)
| Mandient - APT29 Fileless WMI/PS backdoor | [Click](https://www.mandiant.com/resources/dissecting-one-ofap)
| Mandient - APT29 Domain Fronting with TOR | [Click](https://www.mandiant.com/resources/apt29-domain-frontin)
| Mandient - APT29 Phishing Campaign | [Click](https://www.mandiant.com/resources/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign)
| lnk file backdoor | [Click](https://uperesia.com/booby-trapped-shortcut)
| lnk file backdoor Mirosoft Docs | [Click](https://www.microsoft.com/security/blog/2017/02/02/improved-scripts-in-lnk-files-now-deliver-kovter-in-addition-to-locky/?source=mmpc)
|APT29 tradecraft overview | [Click](https://www.mandiant.com/resources/blog/unc2452-merged-into-apt29)
|APT29 some IOCs | [Click](https://raw.githubusercontent.com/microsoft/mstic/master/Indicators/May21-NOBELIUM/May21NOBELIUMIoCs.csv)
|APT29 Phishing & Dropbox | [Click](https://www.microsoft.com/en-us/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/)
|APT29 Phishing, Dropbox, & Google Drive | [Click](https://unit42.paloaltonetworks.com/cloaked-ursa-online-storage-services-campaigns/)
|APT29 targeting COVID-19 research. IOCs and YARA rules | [Click](https://media.defense.gov/2020/Jul/16/2002457639/-1/-1/0/NCSC_APT29_ADVISORY-QUAD-OFFICIAL-20200709-1810.PDF)
|APT29 Emulation Library | [Click](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)
|APT29 SUNSPOT Technical | [Click](https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/)
|"Russian state hackers lure Western diplomats with BMW car ads" 12JUL2023 | [Click](https://www.bleepingcomputer.com/news/security/russian-state-hackers-lure-western-diplomats-with-bmw-car-ads/)
|PHISHING CAMPAIGNS BY THE NOBELIUM INTRUSION SET | [Click](https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-011.pdf)
| SUNBURT IOCs | [Click](https://github.com/mandiant/sunburst_countermeasures/blob/main/indicator_release/Indicator_Release_NBIs.csv)
| Further TTPs associated with SVR cyber actors | [Click](https://www.ncsc.gov.uk/files/Advisory-further-TTPs-associated-with-SVR-cyber-actors.pdf)

---
---
---

# **Resources from the olden days**

# [APT 29 MITRE ATT&CK](https://attack.mitre.org/techniques/T1098/004/)

## **Execution**

### Windows

&nbsp; Scheduled Task/Job:   

- [At](https://attack.mitre.org/techniques/T1053/002/)  
- [Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)  

&nbsp; [Shared Modules](https://attack.mitre.org/techniques/T1129/)  
&nbsp; [System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)  
&nbsp; [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)  

---
## **Persistence**

### Windows

&nbsp; Boot or Logon Autostart Execution: 

- [Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)  
- [Time Provider](https://attack.mitre.org/techniques/T1547/003/)  
- [Login Items](https://attack.mitre.org/techniques/T1547/015/)  
- [Authentication Package](https://attack.mitre.org/techniques/T1547/002/)  
- [Active Setup](https://attack.mitre.org/techniques/T1547/014/)   

&nbsp; [Account Manipulation: SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/)  
&nbsp; [BITS Jobs](https://attack.mitre.org/techniques/T1197/)  

&nbsp; Boot or Logon Intialization Scripts: 

- [Logon Script](https://attack.mitre.org/techniques/T1037/001/)  
- [Network Logon Script](https://attack.mitre.org/techniques/T1037/003/)  

&nbsp; Create Account: 

- [Local Account](https://attack.mitre.org/techniques/T1136/001/)
- [Domain Account](https://attack.mitre.org/techniques/T1136/002/)

&nbsp; [Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)

&nbsp; Event Triggered Execution: 

- [Accessbility Features](https://attack.mitre.org/techniques/T1546/008/)
- [AppCert DLLs](https://attack.mitre.org/techniques/T1546/009/)
- [Appinit DLLs](https://attack.mitre.org/techniques/T1546/010/)
- [Application Shimming](https://attack.mitre.org/techniques/T1546/011/)
- [Change Default File Association](https://attack.mitre.org/techniques/T1546/001/)
- [Component Object Model Hijacking](https://attack.mitre.org/techniques/T1546/015/)
- [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012/)
- [Netsh Helper DLL](https://attack.mitre.org/techniques/T1546/007/)
- [PowerShell Profile](https://attack.mitre.org/techniques/T1546/013/)
- [Screensaver](https://attack.mitre.org/techniques/T1546/002/)
- [WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)

&nbsp; Hijack Execution Flow: 

- [COR_PROFILER](https://attack.mitre.org/techniques/T1574/012/)
- [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/)
- [DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [Executable Installer File Permissions Weakness](https://attack.mitre.org/techniques/T1574/005/)
- [KernelCallbackTable](https://attack.mitre.org/techniques/T1574/013/)
- [Path Interception by PATH Environmental Variable](https://attack.mitre.org/techniques/T1574/007/)
- [Path Interception by Search Order Hijacking](https://attack.mitre.org/techniques/T1574/008/)
- [Path Interception by Unquoted Path](https://attack.mitre.org/techniques/T1574/009/)
- [Services File Permissions Weakness](https://attack.mitre.org/techniques/T1574/010/)
- [Services Registry Permissions Weakness](https://attack.mitre.org/techniques/T1574/011/)

