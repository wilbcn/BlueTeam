# 📡 Wireshark Project 1: Traffic Analysis & Scan Detection

This project is part of my Blue Team learning journey. It focuses on using **Wireshark** to investigate real network traffic, understand protocol behaviors, and detect network scans like those performed by tools such as **Nmap**. This project was carried out in a secure virtual environment, leveraging AWS EC2 instances with tight security rules.

## 🎯 Objectives

- Learn to navigate and use Wireshark for traffic analysis
- Understand core protocols: ARP, ICMP, DNS, HTTP, TCP
- Practice writing display filters to isolate traffic patterns
- Practice using Wiresharks UI
- Identify common scan types: TCP Connect, SYN, UDP
- Use Wireshark statistics, conversation views, and stream following

## Tools & Resources
- [PCAP Analysed](https://www.malware-traffic-analysis.net/2019/06/24/index.html)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [VirusTotal](https://www.virustotal.com/gui/)
- [WHOIS](https://whois.domaintools.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [urlscan.io](https://urlscan.io/result/0196005a-b8b1-724a-b146-be02d738fddb/)
- [httpstatus.io](https://httpstatus.io/)
- [Hybrid-Analysis](https://www.hybrid-analysis.com/)

- Wireshark
- Amazon EC2 Instances

---

## 📖 Project Walkthrough: Analysing a Real-World PCAP in Wireshark
This section showcases the steps and thought process behind my decisions to carry out this project. 

### 1. Getting the sample PCAP file. Baseline file analysis.
To kick off this project, I booted up my secure AWS-based Homelab EC2 instance. I then downloaded a real-world packet capture file from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/2019/06/24/index.html), which is also noted in the **Tools & Resources** section.

Once the `.pcap` file was extracted using the password `infected<date>`, I loaded it into Wireshark for investigation.

<img width="1237" alt="image" src="https://github.com/user-attachments/assets/fb37a567-fe0d-4ed0-99a8-e4951037cb2e" />

- Successfully loaded PCAP file into Wireshark

<img width="1439" alt="image" src="https://github.com/user-attachments/assets/373fa684-e2b9-442e-9865-83a7a71f1319" />

### 1.1 Investigating Capture File Properties
The first step after loading the capture was to review its basic properties via **Statistics → Capture File Properties**. This pane provides essential metadata that helps establish a baseline understanding of the capture. Key findings included:
- Number of packets captured: 1633
- SHA1 Hash: 1c8f8d8fc4fa0872de90c126e9187884b54812ae
- SHA256 Hash: 55627f6b1cfa892b52eb0884fdd4545837c23d72a73b6d2ebb951bd7c41cbe46

<img width="958" alt="image" src="https://github.com/user-attachments/assets/fe45f89a-acc6-4f7b-a12f-870374b98619" />

These hashes are useful for ensuring integrity if the file is shared or submitted as evidence. Additionally, this section gives you details on the time span of the capture, data link type, and whether any packets were dropped, which can all affect analysis quality.

### 1.2 Investigating Protocol Hierarchy
Next, I analyed how many packets were associated with key protocols via **Statistics -> Protocol Hierarchy**. This step helps build a profile of the network activity observed. Key findings include:
- TCP Packets: 1631
- HTTP Packets: 10
- SMTP Packets: 55
- IMF Packets: 4
- DNS Packets: 2
- Data packets: 19
- Media type packets: 2
- IPv4 Packets: 100% (no IPv6 packets)

<img width="1152" alt="image" src="https://github.com/user-attachments/assets/37dbc587-8b67-4966-8630-a8f44fb4e0d7" />

### 1.3 Investigating Resolved Addresses
Next, I enabled **Name Resolution** for addresses, and then **Statistics -> Resolved Addresses**. This may allow us to spot suspicious or unusual domains from an instant glance. In our example PCAP, we already are beginning to see some red flags, given the domain `makemoneyeasywith.me`. This is definately worth investigating in later steps of this project and investigation. 

<img width="617" alt="image" src="https://github.com/user-attachments/assets/7570f8e1-3584-4e36-af89-81bae09ddb4a" />

### 1.4 Investigating Conversations
Next, I navigated to **Statistics -> Conversations**. This view allows us to identify which IP addresses our host is communicating with the most — both in terms of volume and direction of traffic. An initial analysis shows that majority of the traffic has 0 bytes and packets returned. However, by filtering by packets returned to the host `Packets B -> A`, we are able to identify several addresses that did return traffic, and are worth investigating further.

- Sender IP (the local machine): `10.6.24.101`

<img width="1430" alt="image" src="https://github.com/user-attachments/assets/7a9bda8a-8ffe-4998-a2dc-b7bb38245642" />

This filtered view helps us zero in on meaningful traffic rather than sifting through every outbound connection manually. In a later segment, I will be investigating further these identified destination IP addresses.

### 1.5 Investigating Endpoints
After analysing the **Conversations** view (which shows IP pairs communicating), I moved on to **Statistics → Endpoints**, which focuses on **individual IP addresses**. By filtering with `packets`, the same addresses are appearing as suspicious. 

`188.225.26.48`
- Most active external IP in this capture. 1028 packets
- High volume communication. 948kB
- Sent 669 Packets to the host
- Delivered most of the data in this payload. 924kB
- Received 359 packets from the host
- Received 24kB back from the host

Verdict: Highly suspicious! Sent nearly 1MB of data to our internal host.

`195.154.255.65`
- Smaller number of connections overall
- Much less traffic than the first IP address
- Sent 20 packets to our local machine
- Delivered a large single response or perhaps a secondary payload, 24kB.
- Host sent 13 packets to this IP address

Verdict: Appears to be a one time connection, possibly a fairly large download. Definately worth investigating further.

### 1.6 Expert Information Analysis

To close off my artifact gathering phase, I checked **Analyse → Expert Information**.

![image](https://github.com/user-attachments/assets/f6c6e5e7-e91b-44f9-85dc-6e6b57ff5398)

In this capture, several key items are highlighted:

- 12 TCP connection resets (RST) — abrupt connection terminations, possibly due to firewalls, payload rejection, or evasive behavior
- 390 suspected retransmissions — a high count, possibly indicating unstable connections, scanning activity, or packet filtering
- Several standard TCP events like SYN, FIN, and ACK — indicating typical connection activity

**🧠 Verdict:**  
The presence of many retransmissions and reset packets further supports the idea that the host (`10.6.24.101`) was either:
- Reaching out to a large number of hosts (likely scanning or beaconing)
- Or receiving responses from systems that then refused or dropped the connection (malware defense or C2 instability)

### 2. Stream & Payload Analysis
The plan of this phase was to investigate the actual contents of the suspicious traffic. To do this, I will determine the nature of the traffic, and uncover any other signs of suspicious/malicious activity.

### 2.1 Investigating the suspicious domain 
Tracking back to the initial load up of this PCAP file, we came accross a suspicious domain: `makemoneyeasywith.me` which I noted warranted further investigation. 

I ran the below filter in Wireshark, to filter for HTTP GET requests.

```
http.request.method == "GET"
```

By right clicking and following the TCP stream, we are presented with supportive information to our earlier findings.

<img width="957" alt="image" src="https://github.com/user-attachments/assets/ba675358-f148-42e5-8ff9-109c48e088b7" />

This is a 302 Redirect / **Malvertising** from makemoneyeasywith.me to 188.225.26.48. A quick `VirusTotal` search further confirms that this domain is malicious.

![image](https://github.com/user-attachments/assets/32be3a7c-4423-450b-88d8-a80e7638acc0)

### 2.2 Identify the ports of interest
Continuining on with our investigation, I returned to **statistics -> conversations**, and navigated to TCP.

![image](https://github.com/user-attachments/assets/fa057803-85ed-402a-83f6-985ee0fe2f8a)

Key Takeaways:
`188.222.26.48`
- Port B: 80 - `http`
- Bytes B -> A: `861kB`
- Stream ID: `3`

This is our main payload candidate.

`195.154.255.65`
- Non-standard port, `2287`
- `25kB` sent to the local host

Could be C2 or dropper delivery on a custom port.

### 2.2 Follow the streams
To investigate further, I navigated to **Statistics -> Conversations -> TCP**, and filtered on various stream ids. After applying the filters, I right clicked and followed the TCP streams.

<img width="956" alt="image" src="https://github.com/user-attachments/assets/2db57923-0d1e-4c7e-ab03-42fafbffbf94" />
- Rig EK sends flash exploit (later on we discover this)

<img width="1432" alt="image" src="https://github.com/user-attachments/assets/b0265131-2300-4901-994d-9cb697d0df1d" />

- `GET /?NDE2NzQw&lgPow ..... HTTP/1.1` Internal host makes a `GET` request to the malicious server
- The response back: A windows executable, of roughly 828kB, which is what we observed earlier

<img width="310" alt="image" src="https://github.com/user-attachments/assets/69079d3b-04f6-4b62-ac1a-d4401f66bf35" />

- Post infection traffic over TCP port `2287`.

<img width="1430" alt="image" src="https://github.com/user-attachments/assets/f78330fe-f379-4d52-9079-154abd7e9098" />

Lets now export the HTTP objects to continue with our investigation. 

### 2.3 Tracing back to the first attack vector
Now that we understand that a redirect the user from a suspicious domain to a malicious landing page, I want to dig deeper into how this happened in the first place. Remember that earlier, we identified that there were 55 SMTP packets in this PCAP via **Protocol Hierarchy**.

Filter ran:

```
smtp
```

![image](https://github.com/user-attachments/assets/fc9523f6-10cd-4bc5-8c53-0dd2a144cf56)

Packet 1157 looks suspicious! Below are some of the artifacts.
- From: tgeorge@alum.rpi.edu
- To: innocent.nshizirungu@edu.janakkala.fi
- Subject: "Erectile Meds"
- Content-Type: text/plain

By following the TCP stream for this packet 1157, we are able to identify further why this is malicious activity.

![image](https://github.com/user-attachments/assets/4e297ea5-4261-43b7-9878-ca90e8f3fed2)

It is becoming obvious now that this is our lure!
- We have a legitimate file hosting service (google), to evade possible detection.
- The email content is highly suspicious. Why do we have a google drive link in relation to "Erectile Meds". Possibly this was done to provoke curiosity from the user to click the link.
- The link in the email starts off the malicious process. Victim clicks the Drive link, downloads and opens the file, gets redirected or executes exploit chain that triggers connection to makemoneyeasywith.me which redirects to 188.225.26.48. Flash exploit → Malware download!

I will continue with this investigation to practive leveraring other tools and to continue using Wireshark software for more hand-on experience.

### 2.4 Extracting and Analyzing HTTP Objects in Wireshark
By navigating to **File -> Export Objects -> HTTP**, I have now discovered 2 additional details that require further analysis. I exported all 3 to my desktop. 
- Packet 95: The initial landing page
- Packet 106: A shockwave flash exploit.
- Packet 999: The malicious payload.

![image](https://github.com/user-attachments/assets/b5665fc9-58b9-4c43-acb2-0072691cd917)

Starting with the first packet (text/html), I opened the file in `notepad++` within a secure analysis VM. This ensures no execution occurs — the project is strictly static analysis and self-development. I then ran an initial analysis of this file, searching via keyword searches such as `script`, `iframe`, `a href`, etc. `Script`, actually returned 14 matches in the file.

<img width="1434" alt="image" src="https://github.com/user-attachments/assets/7147702e-d5ab-4f3c-b612-be683c4ac052" />

Inside this file, I was able to identify many key artifacts, such as:
- `["createElement"]("script")`

This indicates obfuscated or malicious JavaScript to dynamically inject new scripts into the DOM.

- various base64 encoded text -> `var s = ....`

Multiple functions contain extremely long strings assigned to variables (e.g., var s = "..."). These are likely encoded payloads (Base64, hex, or custom encoding) which are then decoded and injected as executable script. This is commonly seen in:

- Drive-by downloads
- Malicious redirects
- Loader/downloader stages of malware

To investigate further, I decided to decode these payloads using CyberChef.

### 2.5 Decoding Base64 in CyberChef
I leveraged ChatGPT to help me analyse this output, as I am seeing this kind of data for the first time. This was a great learning process, and through this tool I was able to pick out several key artifacts. Using CyberChef, I decoded some parts of the first object exported, which contained numerous base64 encoded strings.

![image](https://github.com/user-attachments/assets/16df75c8-6c6c-4011-8659-0ef5db9d25c7)

![image](https://github.com/user-attachments/assets/a6be7043-b989-4362-9f7b-e6c5acac245c)

- The use of unescape() and a hardcoded XOR key ("l0I9r") is common in malware obfuscation. It decrypts embedded or downloaded strings, hiding malicious payloads from static detection.
- C2 Communication to Suspicious IP. This function sends a request to a suspicious IP (188.225.26.48) with an obfuscated, parameter-heavy URL and a decryption key. This is likely a payload delivery or second-stage downloader command.

This function sends a request to a suspicious IP (188.225.26.48) with an obfuscated, parameter-heavy URL and a decryption key.
This same IP was identified earlier in our Wireshark HTTP object list (Packet 95), confirming it as the Command & Control (C2) server involved in the attack.

Before proceeding to investigate the next packet (x-shockwave-flash), I decided to investigate this confirmed malicious IP address `188.222.26.48`, using `WHOIS`, `VirusTotal`, and `AbuseIPDB`.

### 3. Investigating the malicious IP addresses using web analysis tools
Tool: WHOIS Lookup

![image](https://github.com/user-attachments/assets/4f14e9fa-a8d9-4cd1-8b0d-607712bad282)

Key takeaways:
- Registered ISP: Sky UK Limited
- Reverse DNS: bcde1a30.skybroadband.com
- The IP falls under a residential broadband ISP (Sky UK), suggesting this may be a compromised home machine.

Tool: VirusTotal

![image](https://github.com/user-attachments/assets/de220fab-e916-4e0c-96ac-6995f36a7d41)

![image](https://github.com/user-attachments/assets/ae48b5b6-b3f4-4071-b22f-79cb1f118852)

Key takeaways:
- 0/1 flagged vendors, which could happen if the server is down, dormant, or newly re-used. Also, it only delivers malware when a specific User-Agent or JavaScript is sent (common in drive-by or staged attacks). Still, community score was negative, and our analysis revealed obfuscated script targeting it.

Tool: URLScan.io

![image](https://github.com/user-attachments/assets/e5b3abeb-271d-4a15-bfd9-e88ce818312b)

Key takeaways:
- Host is offline, and likely only responds to crafted/targeted requests
- httpstatus.io also generated an error.

Tool: AbuseIPDB

![image](https://github.com/user-attachments/assets/ef70b6b4-210d-451c-8083-e1d2d574b335)

Key takeaways:
-  The mismatch between WHOIS (UK, Sky UK) and AbuseIPDB (Russia, TimeWeb Ltd.) is a red flag.
-  The .tw1.ru subdomain pattern is commonly seen in shady or short-lived domains used in attacks.

Verdict: The IP was actively involved in malicious behavior as seen in the packet capture and JavaScript deobfuscation. It appears to host malware infrastructure, likely C2 or a second-stage payload server. Although WHOIS records list the IP as belonging to Sky UK Limited (UK), AbuseIPDB indicated the IP is currently hosted by TimeWeb Ltd., a Russian hosting provider. This mismatch is a red flag.

### 4. Leveraging Hybrid-Analysis to investigate the remaining and all files
In this phase, I use Hybrid Analysis to assess the three suspicious files extracted via Wireshark's HTTP object export. This tool allows me to perform sandbox-based static and dynamic analysis, helping to uncover malware behavior even if a file evades traditional antivirus detection.

To begin, I generated SHA256 hashes for each file using PowerShell. This is useful for identifying files across platforms, verifying integrity, and performing lookups on services like VirusTotal and Hybrid Analysis.

Example powershell command used:

```
Get-FileHash packet_95
```

output

```
SHA256          F8D568A1A76ECC5382A7E4BADA5CE5241D0DDC0CDCEA1A494925CBD89A2C2B63       C:\Users\Administrator\Desktop\Wireshark PCAPS\packet_95
```

Lets investigate the hash of the landing page using `Hybrid-Analysis`.

<img width="1407" alt="image" src="https://github.com/user-attachments/assets/2e5e95f9-ac15-46be-a572-96590dfa6a79" />

Scan results:

<img width="990" alt="image" src="https://github.com/user-attachments/assets/5eaeeb9f-4c27-413b-ad8f-c27e7292363f" />

Key takeaways:
- Detected by multiple antivirus vendors
- Classified as Trojan – suggesting deceptive functionality, likely a loader or redirector
- Behavioral indicators suggest it initiates further downloads and potentially injects scripts

Next, I scanned XSF files SHA256 hash using the same approach. 

<img width="990" alt="image" src="https://github.com/user-attachments/assets/a7005ba4-bb00-4782-9f69-4e3c8694dba8" />

Key takeaways:
- Detected as Trojan / Exploit / Script
- Exploits CVE-2018-4878, a critical vulnerability in Adobe Flash Player
- Designed to execute arbitrary code via SWF files, typically used in drive-by attacks

Using cve.org, we are able to find out more information about this file, which exploits vulnerabilities in Adobe Flash Player.
[CVE Overview](https://www.cve.org/CVERecord?id=CVE-2018-4878)

Using cve.org, we are able to find out more information about this file, which exploits vulnerabilities in Adobe Flash Player.

![image](https://github.com/user-attachments/assets/fb60e485-54f6-4aa2-9624-3349464bcad4)

Lastly, I ran a scan on the 3rd object, x-msdownload file.

<img width="1149" alt="image" src="https://github.com/user-attachments/assets/e436735d-4bee-43ad-8036-82a599cefd0d" />

Key takeaways:
- Surprisingly, 0 antivirus detections
- Hybrid Analysis did not flag this as malicious
- Minimal observable behavior during sandbox execution

However, we know for a fact that:
- Delivered from a previously confirmed malicious IP
- Large file size (~800kB), consistent with observed transfer
- Behavior may be delayed, encrypted, or triggered by specific runtime arguments (common in droppers or fileless malware)

Verdict:
Just because a file isn’t flagged doesn’t mean it’s safe. This may be a stage-2 payload designed to execute only under specific conditions — for example, when run by a real victim’s machine or after sandbox evasion checks.

### 5. Summary and Blue Team Recommendations
This project was a deep dive into real-world network traffic analysis, using Wireshark to dissect a malicious packet capture (PCAP) file from a real Rig Exploit Kit (EK) infection chain. The hands-on experience gained through this investigation significantly enhanced my skills in packet analysis, protocol comprehension, and identifying Indicators of Compromise (IOCs).

Through this investigation, I:
- Gained proficiency with Wireshark’s UI, filters, and statistical views. This was fairly new to me, so perhaps some of these checks were not required, it was good practice to leverage as much as possible through wireshark.
- Practiced analyzing common protocols like HTTP, DNS, TCP, and ICMP
- Identified a malvertising redirect chain leading to a Flash-based exploit delivery
- Correlated suspicious domains and IPs with external intelligence (VirusTotal, WHOIS, AbuseIPDB)
- Identified CVE-2018-4878 — a critical Adobe Flash vulnerability used in the exploit
- Exported and analyzed malicious HTTP objects including:
  - A redirector/landing page
  - An obfuscated .xsf Flash exploit
  - A potential stage-2 malware payload

In particular, I was able to link the exploit delivery and post-infection traffic back to 188.225.26.48, a confirmed malicious IP. The Flash file exploited a known vulnerability and the downloaded executable, while not flagged by AV, matched the expected behavior and size of a second-stage payload, potentially fileless or sandbox-aware.

This project marks a significant milestone in my Blue Team journey, reinforcing both analytical process and practical tooling. For future development and growth, I now plan to tackle various other training PCAPS, found here [Training PCAPS](https://www.malware-traffic-analysis.net/training-exercises.html)

Security Recommendations:
- Remove Adove Flash, as it is a discontinued software platform, with a known vulnerability. `CVE-2018-4878`
- Regularly patch software
- Block the malicious IPs and Domains:
  - makemoneyeasywith.me
  - 188.225.26.48
  - 195.154.255.65

- Create stricter rules on inbound emails with attachments
- Implement SPF, DKIM, and DMARC checks
- User awareness training! This all started because a user downloaded and ran a malicious google drive link they received via a phishing email.

Please check out my other wireshark investigations!
