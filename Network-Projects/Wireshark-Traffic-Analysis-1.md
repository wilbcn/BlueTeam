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

## 🕑 Timeline of events
| **Time** | **Comment** | **IOC** |
|----------|-------------|---------|



## ✍🏽 Executive Summary




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
