# 📡 Wireshark Project 4: 

## Overview
Another Wireshark hands-on lab, investigating a malware pcap called "Big Fish in a Little Pong". This investigation was carried out on my own virtual homelab, created on VirtualBox, with a Kali linux distro. 

## Goals
- Executive Summary: State in simple terms what happened (who, what, when)
- Victim Details: Correlate and share the details of the victim (hostname, IP address, MAC address, Windows user account name etc)
- Indentify the IOC's: IP addresses, domains, and urls, associated with the attacker activity. Hashes of any malware from the pcap.
- Apply a logical analysis to the PCAP, leveraring the knowledge I have gained from independant study (Blue Team Level 1), and TryHackMe CTF style Labs.
- Prepare myself for the BTL1 exam, and gain experience with report writing during investigations.

## Tools & Resources
[Malware PCAP](https://www.malware-traffic-analysis.net/2024/09/04/index.html)
[Virtual Machine](https://www.virtualbox.org/)
[Operating System](https://www.kali.org/get-kali/)

<include any tools here i.e. VT>

## Investigation
### 1. PCAP Overview
To begin the investigation, I will perform an initial overview of the PCAP, identifying bits of information which will assist in the overall investigation of the malware PCAP.

- **Capture File Properties**
![image](https://github.com/user-attachments/assets/415bd1c8-28a8-4e53-a823-5a4de8678b44)

#### Key Info
- **PCAP SHA256 Hash**: `8fee06d0b1686faab4364f5b7a741e736ad7e713d5ca9299ff9161a4b4d4862e`
- **First Packet**: `2024-09-04 18:32:31`
- **Last Packet**: `2024-09-04 19:32:07`
- **Total Packets**: `5091`

- **Protocol Hierarchy**
![image](https://github.com/user-attachments/assets/43032c7d-4b71-48de-88ab-575854eb27b4)

#### Key Info
- **Majority of packets are IPv4 traffic**: `94.2%`
- **A large amount of packets sent with TLS encrpytion**: `82.9%`
- 


