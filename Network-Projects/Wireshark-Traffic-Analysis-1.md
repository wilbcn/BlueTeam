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




## ✍🏽 Executive Summary




## 📖 Project Walkthrough: Analysing a Real-World PCAP in Wireshark
### 1. Baseline file analysis.
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

- 
