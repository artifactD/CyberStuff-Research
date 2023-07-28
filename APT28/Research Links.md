Articles:
"APT28 Exploits Known Vulnerability to Carry Out Reconnaissance and Deploy Malware on Cisco Routers." https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-108
WIPERS

Russian wipers in the cyberwar against Ukraine
https://www.virusbulletin.com/conference/vb2022/abstracts/russian-wipers-cyberwar-against-ukraine/

APT28 using CaddyWiper
https://thehackernews.com/2022/09/researchers-identify-3-hacktivist.html

"Russian Wrecking Crews Go Phishing with Worms and Wipers"
https://blogs.blackberry.com/en/2023/02/russian-wrecking-crews-go-phishing-with-worms-and-wipers

TTPs:
- Exploit public facing software (e.g., firewalls, routers, Exchange servers, etc)
- A LOT of phishing
- Disk wipers for denial of service
- HTTP/S C2
- Google drive C2
- IMAP C2 (internal)
- Webshells on web/exchange servers

Tools:
- Koadic
- PowerShell Empire
- CobaltStrike
- Responder

Domains/IPs:
supservermgr[.]com
hxxp://supservermgr[.]com/sys/upd/pageupd.php
185.25.51[.]198
185.25.50[.]93
220.158.216[.]127
92.114.92[.]102
86.106.131[.]177

User Agents:
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; InfoPath.1)
Mozilla/5.0 (Windows NT 6.1; WOW64) WinHttp/1.6.3.8 (WinHTTP/5.1) like Gecko
Mozilla v5.1 (Windows NT 6.1; rv:6.0.1) Gecko/20100101 Firefox/6.0.1

Filenames:
%Temp%\4.tmp\5.vbs

IOCs:
https://unit42.paloaltonetworks.com/unit42-sofacy-groups-parallel-attacks/#IOC
https://unit42.paloaltonetworks.com/unit42-sofacy-groups-parallel-attacks/

Persistence:
HKCU\Environment\UserInitMprLogonScript