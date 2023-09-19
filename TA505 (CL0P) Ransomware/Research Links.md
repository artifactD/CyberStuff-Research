About:  
TA505 is a cyber criminal group that has been active since at least 2014. TA505 is known for frequently changing malware, driving global trends in criminal malware distribution, and ransomware campaigns involving Clop.[1][2][3][4][5]  
Ref: https://attack.mitre.org/groups/G0092/  
Ransomware-as-a-Service (RaaS). Suspected to be Russian speaking. No strong attribution currently.  

Recent News:  
"CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability" June 07, 2023  
https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a  

"In the past several days, more state and federal agencies have come forward. The Colorado Department of Health Care Policy and Financing, Maryland Department of Human Services, U.S. Department of Agriculture and U.S. Office of Personnel Management all said they were impacted."   
https://www.govtech.com/security/more-state-fed-agencies-hit-by-moveit-compromise  

"Considered to be one of the largest phishing and malspam distributors worldwide, TA505 is estimated to have compromised more than 3,000 U.S.-based organizations and 8,000 global organizations."  
https://www.msspalert.com/news/cl0p-ransomware-gang-hits-multiple-governments-businesses-in-wide-scale-attack  

"June 27 (Reuters) - Siemens Energy and the University of California, Los Angeles (UCLA) said on Tuesday they were among victims of the MOVEit hack that has affected scores of corporations, governments and other institutions in recent weeks."  
https://www.reuters.com/technology/siemens-energy-no-critical-data-was-compromised-after-moveit-data-breach-2023-06-27/  

Initial Access:  
Exploit Public-Facing Application (CVE-2023-34362 affecting MOVEit Transfer software; begins with a SQL injection to infiltrate the MOVEit Transfer web application.)  
Phishing  
Spear phishing  
- Malicious links  
- Malicious attachments (.doc, .docx .pdf, .iso, .xls, .lnk files)  

TTPs:  
Web Shells  
Process Injection  
Indicator Removal (tool deletion)  
Hijack Execution Flow: DLL Side-Loading  
Remote Service Session Hijacking: RDP Hijacking  
Screen Capture  
Fake Zoom binaries  
Fake Dropbox, Sync, Google Drive, and Microsoft Office websites  
C2: HTTP/s  
PowerShell, cmd, JavaScript, and VBS execution  
Encrypting target data for impact  
Disabled Windows Defender  
UPX packed binaries  
Net commands for enumeration  
msiexec to download and execute malicious Windows Installer files  
rundll32.exe to execute malicious DLLs  
Gather credentials from FTP clients and Outlook  

Tools:  
LEMURLOOT Web Shell  
DEWMODE Web Shell (designed to interact with a MySQL database, and is used to exfiltrate data from the compromised network.)  
TinyMet (a small open-source Meterpreter stager to establish a reverse shell to their C2 server.)  
TrueBot  
SDBot (Backdoor)  
CobaltStrike  
FlawedAmmyy (RAT)  
AdFind  
Amadey  
Azorult  
BloudHound  
Clop  
Dridex  
FlawedGrace  
Get2  
MimiKatz  
PowerSploit  
ServHelper  
TrickBot  
EmailStealer  

Domains/IPs:  
drm-server-booking[.]com  
news-server-drm-google[.com  
googledrive-download[.]com  
office-en-service[.]com  
microsoft-live-us[.]com  
microsoft-live-us[.]com/fidonet  
office365-update-en[.]com  
update365-office-ens[.]com  
dl1.sync-share[.]com	
d1.syncdownloading[.]com  
http://hiperfdhaus[.]com  
http://jirostrogud[.]com  
http://qweastradoc[.]com  
http://qweastradoc[.]com/gate.php  
http://connectzoomdownload[.]com/download/ZoomInstaller.exe  
https://connectzoomdownload[.]com/download/ZoomInstaller.exe  
http://zoom[.]voyage/download/Zoom.exe  
http://guerdofest[.]com/gate.php  
104.194.222[.]107  
146.0.77[.]141  
146.0.77[.]155  
146.0.77[.]183  
148.113.152[.]144  
162.244.34[.]26  
162.244.35[.]6  
179.60.150[.]143  
185.104.194[.]156  
185.104.194[.]24  
185.104.194[.]40  
185.117.88[.]17  
185.162.128[.]75  
185.174.100[.]215  
185.174.100[.]250  
185.181.229[.]240  
185.181.229[.]73  
185.183.32[.]122  
185.185.50[.]172  
185.176.221[.]45  
188.241.58[.]244  
193.169.245[.]79  
194.33.40[.]103  
194.33.40[.]104  
194.33.40[.1]64  
198.12.76[.]214  
198.27.75[.]110  
206.221.182[.]106
209.127.116[.]122  
209.127.4[.]22  
209.222.103[.]170  
45.227.253[.]133  
45.227.253[.]147  
45.227.253[.]50  
45.227.253[.]6  
45.227.253[.]82  
45.56.165[.]248  
5.149.248[.]68  
5.149.250[.]74  
5.149.250[.]92  
5.188.86[.]114  
5.188.86[.]250  
5.188.87[.]194  
5.188.87[.]226  
5.188.87[.]27  
5.252.23[.]116  
5.252.25[.]88  
5.34.180[.]205  
62.112.11[.]57  
62.182.82[.]19  
62.182.85[.]234  
66.85.26[.]215  
66.85.26[.]234  
66.85.26[.]248  
79.141.160[.]78  
79.141.160[.]83  
84.234.96[.]104  
84.234.96[.]31  
89.39.104[.]118  
89.39.105[.]108  
91.202.4[.]76  
91.222.174[.]95  
91.229.76[.]187  
93.190.142[.]131  
92.118.36[.]249  
5.34.180[.]48  
185.33.86[.]225  
148.113.159[.]213  
15.235.13[.]184  
82.117.252[.]141  
185.80.52[.]230  
91.222.174[.]68  
5.34.178[.]31  
185.104.194[.]134  
5.34.178[.]28  
185.81.113[.]156  
5.34.178[.]30  
77.83.197[.]66  
193.42.38[.]196  
209.222.98[.]25  
106.75.139[.]199  
79.141.166[.]119  
185.117.88[.]2  
79.141.160[.]78  
185.33.87[.]126  
82.117.252[.]142  
15.235.83[.]73  
81.56.49[.]148  
96.44.181[.]131  
192.42.116[.]191  
213.121.182[.]84  
104.200.72[.]149  
152.57.231[.]216  
142.44.212[.]178  
54.39.133[.]41  
76.117.196[.]3  
24.3.132[.]168  
166.70.47[.]90  
208.115.199[.]25  
216.144.248[.]20  
173.254.236[.]131  
3.101.53[.]11  
54.184.187[.]134  
100.21.161[.]34  
44.206.3[.]111  
75.101.131[.]237  
20.47.120[.]195  
198.137.247[.]10  

User-Agents:  

Filenames:  
human2.aspx  
larabqFa.exe  
Qboxdv.dll  
%TMP%\7ZipSfx.000\Zoom.exe  
%TMP%\7ZipSfx.000\ANetDiag.dll  
AVICaptures.dll  
kpdphhajHbFerUr.exe  
gamft.dll  
dnSjujahur.exe  
Pxaz.dll  
7ZSfxMod_x86.exe  
ZoomInstaller.exe  
Zoom.exe  
update.jsp  
%TMP%\<folder>\extracted_at_0xe5c8f00.exe  
UhfdkUSwkFKedUUi.exe  
gamft.dll  
x86: %APPDATA%\Microsoft\Windows\Template\vspub1.dll  
x64: %APPDATA%\Microsoft\Windows\Template\vspub2.dll  

Persistence:  
Application shimming (https://attack.mitre.org/versions/v13/techniques/T1546/011/)  

IOCs:  
unlock@rsv-box[.]com  
unlock@support-mult[.]com  
rey14000707@gmail[.]com  
gagnondani225@gmail[.]com  
0b3220b11698b1436d1d866ac07cc90018e59884e91a8cb71ef8924309f1e0e9  
0ea05169d111415903a1098110c34cdbbd390c23016cd4e179dd9ef507104495  
110e301d3b5019177728010202c8096824829c0b11bb0dc0bff55547ead18286  
1826268249e1ea58275328102a5a8d158d36b4fd312009e4a2526f0bfbc30de2  
2413b5d0750c23b07999ec33a5b4930be224b661aaf290a0118db803f31acbc5  
2ccf7e42afd3f6bf845865c74b2e01e2046e541bb633d037b05bd1cdb296fa59  
348e435196dd795e1ec31169bd111c7ec964e5a6ab525a562b17f10de0ab031d  
387cee566aedbafa8c114ed1c6b98d8b9b65e9f178cf2f6ae2f5ac441082747a  
38e69f4a6d2e81f28ed2dc6df0daf31e73ea365bd2cfc90ebc31441404cca264  
3a977446ed70b02864ef8cfa3135d8b134c93ef868a4cc0aa5d3c2a74545725b  
3ab73ea9aebf271e5f3ed701286701d0be688bf7ad4fb276cb4fbe35c8af8409  
3c0dbda8a5500367c22ca224919bfc87d725d890756222c8066933286f26494c  
4359aead416b1b2df8ad9e53c497806403a2253b7e13c03317fc08ad3b0b95bf  
48367d94ccb4411f15d7ef9c455c92125f3ad812f2363c4d2e949ce1b615429a  
58ccfb603cdc4d305fddd52b84ad3f58ff554f1af4d7ef164007cb8438976166  
5b566de1aa4b2f79f579cdac6283b33e98fdc8c1cfa6211a787f8156848d67ff  
6015fed13c5510bbb89b0a5302c8b95a5b811982ff6de9930725c4630ec4011d  
702421bcee1785d93271d311f0203da34cc936317e299575b06503945a6ea1e0  
769f77aace5eed4717c7d3142989b53bd5bac9297a6e11b2c588c3989b397e6b  
7c39499dd3b0b283b242f7b7996205a9b3cf8bd5c943ef6766992204d46ec5f1  
93137272f3654d56b9ce63bec2e40dd816c82fb6bad9985bed477f17999a47db  
98a30c7251cf622bd4abce92ab527c3f233b817a57519c2dd2bf8e3d3ccb7db8  
9d1723777de67bc7e11678db800d2a32de3bcd6c40a629cd165e3f7bbace8ead  
9e89d9f045664996067a05610ea2b0ad4f7f502f73d84321fb07861348fdc24a  
a1269294254e958e0e58fc0fe887ebbc4201d5c266557f09c3f37542bd6d53d7  
a8f6c1ccba662a908ef7b0cb3cc59c2d1c9e2cbbe1866937da81c4c616e68986  
b1c299a9fe6076f370178de7b808f36135df16c4e438ef6453a39565ff2ec272  
b5ef11d04604c9145e4fe1bedaeb52f2c2345703d52115a5bf11ea56d7fb6b03  
b9a0baf82feb08e42fa6ca53e9ec379e79fbe8362a7dac6150eb39c2d33d94ad  
bdd4fa8e97e5e6eaaac8d6178f1cf4c324b9c59fc276fd6b368e811b327ccf8b  
c56bcb513248885673645ff1df44d3661a75cfacdce485535da898aa9ba320d4  
c77438e8657518221613fbce451c664a75f05beea2184a3ae67f30ea71d34f37  
cec425b3383890b63f5022054c396f6d510fae436041add935cd6ce42033f621  
cf23ea0d63b4c4c348865cefd70c35727ea8c82ba86d56635e488d816e60ea45  
d477ec94e522b8d741f46b2c00291da05c72d21c359244ccb1c211c12b635899  
d49cf23d83b2743c573ba383bf6f3c28da41ac5f745cde41ef8cd1344528c195  
daaa102d82550f97642887514093c98ccd51735e025995c2cc14718330a856f4  
e8012a15b6f6b404a33f293205b602ece486d01337b8b3ec331cd99ccadb562e  
ea433739fb708f5d25c937925e499c8d2228bf245653ee89a6f3d26a5fd00b7a  
ed0c3e75b7ac2587a5892ca951707b4e0dd9c8b18aaf8590c24720d73aa6b90c  
f0d85b65b9f6942c75271209138ab24a73da29a06bc6cc4faeddcb825058c09d  
fe5f8388ccea7c548d587d1e2843921c038a9f4ddad3cb03f3aa8a45c29c6a2f  
