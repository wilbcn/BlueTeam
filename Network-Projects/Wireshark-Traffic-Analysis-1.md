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
- [Hybrid-Analysis](https://www.hybrid-analysis.com/)

- Wireshark
- VirtualBox (running kali linux)

## 🕑 Timeline of events
| **Time (UTC)**               | **Event**                                                                                          | **IOC / Notes**                                                                 |
|------------------------------|-----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| 2019-06-24 17:14:10          | Packet capture begins                                                                               | Capture start                                                                  |
| 2019-06-24 17:14:13.1960278  | HTTP GET request initiated to `makemoneyeasywith.me`                                                | Suspicious domain used for redirection                                         |
| 2019-06-24 17:14:13          | HTTP 302 Redirect issued from `makemoneyeasywith.me` to `1158715-cy17485.tw1.ru` (`188.255.26.48`)   | Redirect sets long, base64-like cookies                                        |
| 2019-06-24 17:14:14          | Flash exploit payload (`application/x-shockwave-flash`) received                                     | Exploit tied to CVE-2018-4878 (Adobe Flash)                                    |
| 2019-06-24 17:14:15          | Additional GET request for `/favicon.ico`                                                           | Likely decoy or secondary resource                                             |
| 2019-06-24 17:14:22          | HTTP response with `application/x-msdownload` received; malware dropper/loader delivered              | Final payload download                                                          |
| 2019-06-24 17:16:38.400736   | SMTP traffic begins; outbound spam emails are sent from the compromised host                        | SMTP emails with subject "Erectile Meds" and malicious Google Drive links       |

## Indicators of Compromise (IOCs)
| **Item** | **Description** | **Comment** |
|----------|-----------------|-------------|
| `10.6.24.101` | IP address | Infected host machine |
| `1158715-cy17485.tw1.ru` `188.255.26.48` | Domain and IP | Malicious activity over HTTP (redirect target) |
| `makemoneyeasywith.me` `185.254.190.200` | Domain and IP | Initial redirection point; suspicious domain |
| `k-tsuchida@matsump.co.jp` | Email address | Appears in SMTP "MAIL FROM:" header (spoofed sender) |
| `tgeorge@alum.rpi.edu` | Email address | SMTP traffic; malicious sender |
| `innocent.nshizirungu@edu.janakkala.fi` | Email address | SMTP traffic; recipient account |
| `elina.vuorenmaa@elisanet.fi` | Email address | SMTP traffic; recipient account |
| `f8d568a1a76ecc5382a7e4bada5ce5241d0ddc0cdcea1a494925cbd89a2c2b63` | Hash Value | Malicious Trojan contained in HTML object (embedded JS) |
| `9c569f5e6dc2dd3cf1618588f8937513669b967f52b3c19993237c4aa4ac58ea` | Hash Value | Flash exploit payload associated with CVE-2018-4878 |
| `d0a066225444fa1f571781ff4982880def633dce816d9540aaa8bb3ac685895f` | Hash Value | Trojan dropper/loader (undetected by VT) |
| `https://drive.google.com/file/d/1cfQkpmVt8X04_ILlkRpD-m0jQUVvUQjZ` | Google Drive link | Malicious link for initial payload download |

## ✍🏽 Executive Summary
In this security event, the victim machine `10.6.24.101` was compromised after a user interaction with the malicious domain `makemoneyeasywith.me` on 24th of June 2019, at 17:14:13. This domain redirected to another malicious, russian based domain `1158715-cy17485.tw1.ru` (`188.255.26.48`) where a flash exploit payload was downloaded onto the victims machine. Post system compromise, starting at 17:16:38 on the same day, there was evidence of post infection malspam sent to multiple addresses, containing a malicious google drive link. 

## 🛡️ Mitigation & Recommendations
- Patch outdated software to avoid known exploits like CVE-2018-4878.
- Implement email filtering and sandboxing to prevent malspam payloads from endpoint users.
- Block suspicious domains such as `makemoneyeasywith.me` and any direct IP access in outbound HTTP requests.
- Monitor for anomalous SMTP traffic from endpoints to detect post-compromise spam activity.
- Educate users about phishing and malspam tactics, especially when legitimate platforms such as Google Drive are abused.

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

### 2. 🔎 Investigating HTTP traffic
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

#### HTTP Summary
- First packet `2019-06-24 17:14:13.1960278`
- HTTP redirect from `makemoneyeasywithme` to `1158715-cy17485.tw1.ru` `188.255.26.48`
- Contains multiple malicious GET requests including the Rig landing page/redirect, a flash exploit, and the encrypted payload.

### 3. 🔎 Investigating SMTP traffic

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

- In the provided screen shots, we can now conclude this is definately "mal-spam". Abusing legitimate services like google drive, and mass distrubuting a malicious payload. Under IMF exports, we can see the spam sent from the infected host.

![image](https://github.com/user-attachments/assets/8cfdc674-72f3-4f2c-a34d-99033583f986)

#### SMTP Summary
- First packet: `2019-06-24 17:16:38.400736`
- Post compromise activity - malspam sent after victim downloaded malicous flash exploit.

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
