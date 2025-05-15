# 📡 Wireshark Investigation 1: First Malware PCAP Analysis!

This project is part of my on going Wireshark series, where I gain hands-on experience investigating real-world malware PCAPs using industry standard network analysis tools. Each project serves as an opportunity to sharpen my practical skills in dissecting malicious traffic, constructing a detailed timeline of events, and an executive summary to simulate the type of reporting expected from a SOC analyst.

## 🎯 Objectives

- Practice navigating and using Wireshark for traffic analysis
- Investigate the malware pcap to collect the key indicators of compromise
- Construct a timeline of events
- Write an executive summary
- Leverage malware analysis and sandbox tools

## 🛠️ Tools & Resources
- [PCAP Analysed](https://www.malware-traffic-analysis.net/2019/06/24/index.html)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [VirusTotal](https://www.virustotal.com/gui/)
- [WHOIS](https://whois.domaintools.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [urlscan.io](https://urlscan.io/result/0196005a-b8b1-724a-b146-be02d738fddb/)
- [httpstatus.io](https://httpstatus.io/)
- [Hybrid-Analysis](https://www.hybrid-analysis.com/)

- Wireshark
- VirtualBox (running kali linux)

## 🕑 Timeline of Events
| **Time (UTC)**        | **Event**                                                                                          | **IOC / Notes**                                                                 |
|-----------------------|-----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| 2019-06-24 14:52:50   | Malspam email sent to victim containing a Google Drive link                                         | `From: k-tsuchida@matsump.co.jp` → `elina.vuorenmaa@elisanet.fi`               |
| 2019-06-24 14:53:50   | Another malspam email sent to a different victim, with a different malicious Drive link             | `From: tgeorge@alum.rpi.edu` → `innocent.nshizirungu@edu.janakkala.fi`         |
| 2019-06-24 16:14:10   | Packet capture begins                                                                               | Wireshark shows capture start                                                   |
| 2019-06-24 16:14:18   | Victim machine makes HTTP GET request to `makemoneyeasywith.me`                                     | Suspicious User-Agent: IE11; domain used for redirection                        |
| 2019-06-24 16:14:18   | HTTP 302 Redirect to `http://188.225.26.48/`                                                        | Underlying IP of `1158715-cy17485.tw1.ru`; redirect sets suspicious cookies     |
| 2019-06-24 16:14:19   | HTTP GET to `188.225.26.48`, receives `application/x-shockwave-flash`                               | Likely Flash-based exploit (CVE-2018-4878)                                      |
| 2019-06-24 16:14:20   | HTTP GET request for `/favicon.ico` from same IP                                                    | Likely part of redirection or stager mechanism                                  |
| 2019-06-24 16:14:22   | HTTP response returns `application/x-msdownload` from `188.225.26.48`                              | Final malware payload downloaded (dropper/loader)                               |
| 2019-06-24 16:16:51   | Packet capture ends                     

## Indicators of compromise
| **Item** | **Description** | **Comment** |
|----------|-----------------|-------------|
| `10.6.24.101` | IP address | Infected host machine | 
| `1158715-cy17485.tw1.ru` `188.255.26.48` | Domain and IP | Malicious Activity over HTTP |
| `makemoneyeasywith.me` `185.254.190.200` | Domain and IP | Malicious Activity over HTTP | 
| `k-tsuchida@matsump.co.jp` | Email address | Comrpomised account | 
| `tgeorge@alum.rpi.edu` | Email address | Compromised account |
| `innocent.nshizirungu@edu.janakkala.fi ` | Email address | Victims account |
| `elina.vuorenmaa@elisanet.fi` | Email address | Victims account |
| `f8d568a1a76ecc5382a7e4bada5ce5241d0ddc0cdcea1a494925cbd89a2c2b63` | Hash Value | Malicious Trojan |
| `9c569f5e6dc2dd3cf1618588f8937513669b967f52b3c19993237c4aa4ac58ea` | Hash Value | CVE-2018-4878 - arbitrary code execution vulnerability in Adobe Flash Player before 28.0.0.161 |
| `d0a066225444fa1f571781ff4982880def633dce816d9540aaa8bb3ac685895f` | Hash Value | Trojan dropper or loader | 
| `https://drive.google.com/file/d/1cfQkpmVt8X04_ILlkRpD-m0jQUVvUQjZ` | Google drive link | Malicious link for payload download |

## ✍🏽 Executive Summary
In this security event, the victim machine `10.6.24.101` was compromised after the user interacted with a **malicious Google Drive link** delivered via a **malspam email**. The emails followed a clear spam pattern, using pharmaceutical bait ("Erectile Meds") and spoofed sender information to appear credible. 

Upon clicking the link, the victim was redirected through the domain `makemoneyeasywith.me` (`185.254.190.200`), which issued a 302 HTTP redirect to `1158715-cy17485.tw1.ru` (`188.225.26.48`). From there, the victim received a sequence of suspicious payloads, including a Flash file (`application/x-shockwave-flash`) tied to CVE-2018-4878, a critical arbitrary code execution vulnerability in Adobe Flash Player (versions prior to 28.0.0.161).

Shortly after, a second object (`application/x-msdownload`) was delivered — likely acting as a trojan dropper or loader. The domain and IP infrastructure used in this attack strongly suggests it was part of a malspam campaign leveraging exploit kits to deliver malware via browser vulnerabilities.

All malicious activity occurred over HTTP, and legitimate services like Google Drive were abused to deliver the initial lure. The payloads were exported and analyzed, with the Flash and HTML files flagged as malicious across multiple platforms, while the executable remained undetected — indicating possible evasion techniques.

This event highlights the ongoing threat of social engineering, combined with legacy exploit delivery, and underscores the importance of patching end-user software and disabling outdated technologies like Flash.

## 📖 Project Walkthrough: Analysing a Real-World PCAP in Wireshark
### 1. 🔎 Baseline file analysis.
To start any PCAP investigation, I always go through the **statistics** tabs of Wireshark. Here we can find key details regarding the most active addresses and most used protocols.

#### Capture File Properties
- **First Packet**: `2019-06-24 17:14:10`
- **Last Packet**: `2019-06-24 17:16:51`
- **PCAP SHA256 Hash**: `55627f6b1cfa892b52eb0884fdd4545837c23d72a73b6d2ebb951bd7c41cbe46`
- **Total Packets**: `1633`

#### Protocol Hierarchy

![image](https://github.com/user-attachments/assets/5ceeff26-528d-4cab-9c14-581b47158459)

- 100% of packets were IPv4
- 99.9% of packets were sent via TCP
- 55 packets for SMTP (Simple Mail Transfer Protocol - Port 25)
- Small amount of HTTP traffic, 10 packets

#### Conversations

![image](https://github.com/user-attachments/assets/8c6dd121-6c43-459b-85e9-59f2fcfdbaef)

- With name resolution toggled on

![image](https://github.com/user-attachments/assets/8ebff910-6228-4d3d-bd34-95730106c878)

- `10.6.24.101`: must be our infected host
- `1158715-cy17485.tw1.ru` `188.255.26.48`: IP address with the most packets (1028) and data sent (948kB). Inheritently suspicious russian domain.
- `makemoneyeasywith.me` `185.254.190.200`: Suspicious domain name, 8 packets.
- There are multiple unresolved IP addresses also to check, some out of screen shot.

#### Conversations & SMTP filter
From the intitial look at the protocol hierarchy, we know that there is some SMTP traffic worth investigating. By applying a filter for smtp traffic and returning to conversations, we can out which addresses were involved with this protocol. 

![image](https://github.com/user-attachments/assets/06c582bf-5c15-4a7c-8dde-77e855e59741)

- With name resoution toggled on

![image](https://github.com/user-attachments/assets/7e1575d9-2261-409f-9568-72402c2ef579)

- The two suspicious domains identified (so far) don't appear to be involved with SMTP traffic. I will however investigate this further to see what exactly went on over SMTP. I repeated these steps for HTTP traffic.

#### Conversations & HTTP filter

![image](https://github.com/user-attachments/assets/701b6dc7-49cc-49de-959a-d70cd2a3b20b)

- It is clear now that the two identified addresses were involved with HTTP traffic. Knowing which addresses were involved in which protocol simplifies my searches during the investigation.

### 2. 🔎 Investigating SMTP traffic

Wireshark query:

```
smtp
```

![image](https://github.com/user-attachments/assets/d9702279-2188-4413-a161-03267e893a8f)

- By searching `smtp`, I am able to see the entirety of smtp traffic. After a brief scan, I came accross packets `1157` and `1268`, which have a suspicious subject "Erectile Meds". I then ran an updated query to hone in on this.

```
smtp && frame contains "Subject: Erectile Meds"
```

![image](https://github.com/user-attachments/assets/a4c5c3a6-194c-4f4b-ab04-81b448ef1e76)

- I then followed the TCP stream for one of these packets.

![image](https://github.com/user-attachments/assets/da8e7452-1226-49fc-9bb2-b443dbd9c67d)

#### Key values
- Mismatch in sender headers:
    - `MAIL From:<k-tsuchida@matsump.co.jp>`
    - `From: "elina.vuorenmaa@elisanet.fi" <k-tsuchida@matsump.co.jp>`
    - `To: <elina.vuorenmaa@elisanet.fi>`
- `Date: 24 Jun 2019 14:52:50 -0100`
- Suspicious and most likely malicious google drive link
    - `https://drive.google.com/file/d/1cfQkpmVt8X04_ILlkRpD-m0jQUVvUQjZ`
 
- The other packets contained similar information. There is again another sender mismatch, with the same subject, and another malicious google drive link.

![image](https://github.com/user-attachments/assets/7e6f67bf-de87-4eda-a0bf-d958c967e267)

![image](https://github.com/user-attachments/assets/228d4d94-705a-4878-9971-5aeda385cb3d)

- In the provided screen shots, we can now conclude this is definately "mal-spam". Abusing legitimate services like google drive, and mass distrubuting a malicious payload. To be sure I had the first instance of this, I ran one more query, followed the TCP stream, and noted down the IOCs.

```
frame contains "drive.google"
```

- `From: "innocent.nshizirungu@edu.janakkala.fi" <tgeorge@alum.rpi.edu>`
- `To: <innocent.nshizirungu@edu.janakkala.fi>`
- `Subject: Erectile Meds`
- `Date: 24 Jun 2019 14:53:50 -0100`
- `https://drive.google.com/file/d/1HmG7RisNCYVkO4aer_eV1nUF4qDp7jLm`

### 3. 🔎 Investigating HTTP traffic
Now that we know how our victim was most likely infected, I investigated further to find out what exactly happened post-compromise. We also gathered two suspicious addresses earlier, which will come in handy now as we diagnose HTTP traffic.
- `1158715-cy17485.tw1.ru` `188.255.26.48`
- `makemoneyeasywith.me` `185.254.190.200`

Wireshark Query:

```
http
```

![image](https://github.com/user-attachments/assets/225c8e75-d385-4625-a20f-f485849e90c0)

- Immediately, we are able to spot suspicious activity related to these two addresses.

#### Key values
- We have multiple get requests, which include long strings with identifyable words such as "blackmail".
- In packet `106` in the HTTP 200 OK response, we have `(application/x-shockwave-flash)`, and also `(application/x-msdownload)`. These are highly suspicious and require object exports to analyse further.
- I then followed packet `6` to begin inspecting.

![image](https://github.com/user-attachments/assets/18e96ebf-f07b-4115-9601-32778da67ad9)

- After the TCP handshake, we have a GET request to the suspicious domain `makemoneyeasywith.me`.

#### Key values
- Timestamp: `Date: Mon, 24 Jun 2019 16:14:18 GMT`
- We have a HTTP Response: 302 Redirect -> Target: `hxxp[://]188[.]225[.]26[.]48/`
- The redirect target is the underlying IP address of the other suspicious domain -> `1158715-cy17485.tw1.ru`.
- It sets cookies that look base64-like and are suspiciously long
- As highlighted already, the domain itself is highly suspicious by name `makemoneyeasywith.me`.

- I then followed the stream for the packet containing `(application/x-shockwave-flash)`

![image](https://github.com/user-attachments/assets/74cf0c7a-a294-409e-a436-3536ec11b7e0)

##### Key values
- Timestamp: `Date: Mon, 24 Jun 2019 16:14:19 GMT`
- `Host: 188.225.26.48`
- `Content-Type: application/x-shockwave-flash` - The victim receives a suspicious flash object.
- Malicious encoded payload
- Second GET request below payload for `GET /favicon.ico HTTP/1.1`.

- Then at `Date: Mon, 24 Jun 2019 16:14:22 GMT`, we have the other mentioned malicious payload `Content-Type: application/x-msdownload`, which is also encoded.

### 4. ⬇️ Exporting HTTP Objects
In Wireshark, by going to **File** -> **Export Objects** -> **HTTP**, I am able to export the identified suspicious files for further analysis. I did this and saved them to my desktop. As these files are likely malicious, this investigation is carried out in a kali-linux based virtual machine.

![image](https://github.com/user-attachments/assets/dc5f21cf-754e-4f81-846b-b42debd5812c)

- To simplify analysis and demonstrating the next steps, I have renamed the exports logically from their long strings.

![image](https://github.com/user-attachments/assets/d79a7679-50e0-4438-bf95-cdb2c974ebeb)

#### Checking Hash Values
The first step of analysing these payloads was to generate hash values for each of them, and then check them in malware analysis tools such as VirusTotal.

Example command ran:

```
┌──(jake㉿jake-kali)-[~/Desktop/wireshark_exports]
└─$ sha256sum ms_download 
d0a066225444fa1f571781ff4982880def633dce816d9540aaa8bb3ac685895f  ms_download
```

| **File** | **SHA256 Hash** | Result|
|----------|-----------------|-------|
|text/html| f8d568a1a76ecc5382a7e4bada5ce5241d0ddc0cdcea1a494925cbd89a2c2b63 | Highly malicious trojan. contains-embedded-js |
|shockwave-flash | 9c569f5e6dc2dd3cf1618588f8937513669b967f52b3c19993237c4aa4ac58ea | Highly malicious, associated with CVE-2018-4878, an arbitrary code execution vulnerability in Adobe Flash Player before 28.0.0.161 |
| ms-download | d0a066225444fa1f571781ff4982880def633dce816d9540aaa8bb3ac685895f | Undetected payload in VT |

I also checked these files using `hybrid-analysis`, further confirming our findings.

- `text/html`
  
![image](https://github.com/user-attachments/assets/72d332f2-767e-4e93-9327-1a385adad4ca)

- `shockwave-flash`
  
![image](https://github.com/user-attachments/assets/950db6e5-c9ee-4f7a-801d-0ad4da6dc3d1)

- `ms-download` -> Undetected. Its very likely this file is simply to download or unpack the malware identified in the other two files.
