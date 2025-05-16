# 📡 Wireshark Investigation 5: **Insert Title**

This project is part of my on going Wireshark series, where I gain hands-on experience investigating real-world malware PCAPs using industry standard network analysis tools. Each project serves as an opportunity to sharpen my practical skills in dissecting malicious traffic, constructing a detailed timeline of events, and an executive summary to simulate the type of reporting expected from a SOC analyst.

## 🎯 Objectives
- Practice navigating and using Wireshark for traffic analysis
- Investigate the malware pcap to collect the key indicators of compromise
- Construct a timeline of events
- Write an executive summary
- Leverage malware analysis and sandbox tools

## 🛠️ Tools & Resources
- [PCAP Analysed](https://www.malware-traffic-analysis.net/2024/07/30/index.html)
- [VirusTotal](https://www.virustotal.com/gui/)

- Wireshark
- VirtualBox (running kali linux)


## 🕑 Timeline of events
| **Time (UTC)**               | **Event**                                                                                          | **IOC / Notes**                                                                 |


## Indicators of Compromise (IOCs)
| **Item** | **Description** | **Comment** |

## ✍🏽 Executive Summary


## 🛡️ Mitigation & Recommendations


## Scenario
LAN segment data:
- LAN segment range:  172.16.1[.]0/24 (172.16.1[.]0 through 172.16.1[.]255)
- Domain:  wiresharkworkshop[.]online
- Domain controller:  172.16.1[.]4 - WIRESHARK-WS-DC
- LAN segment gateway:  172.16.1[.]1
- LAN segment broadcast address:  172.16.1[.]255


## 📖 Project Walkthrough: Analysing a Real-World PCAP in Wireshark
### 1. 🔎 Baseline file analysis.
To start any PCAP investigation, I always go through the **statistics** tabs of Wireshark. Here we can find key details regarding the most active addresses and most used protocols.

#### Capture File Properties
- **First Packet**: `2024-07-30 03:38:48`
- **Last Packet**: `2024-07-30 03:48:34`
- **PCAP SHA256 Hash**: `c48854c24223cf7b4e9880ea72a21a877e4138e4ce36df7b7656e5c6c4043f68`
- **Total Packets**: `11562`

#### Protocol Hierarchy

![image](https://github.com/user-attachments/assets/64b5211f-933a-4ebd-a27c-7f3761f71495)

- TLS accounts for majority of traffic, `1344` packets. Most communication is therefore encrypted.
- NetBIOS Session Service packets `365`: 
- SMBv2 and SMB over NetBIOS are present: SMB compared to v2/3 is outdated and worth investigating. Check for potential SMB traffic to external destinations. 
- Lanman remote API protocol is also considered a legacy protocol and is outdated.
- DCE/RPC & Kerberos Activity: Protocols like DCE/RPC, LDAP, and Kerberos are present. Investigate potential domain login attempts.
- SDP, NetBIOS, and mDNS Activity: This is expected on LANS, but worth checking to see if any external parties show up.
- HTTP Traffic: 4 total packets and very small byte count.

#### Conversations

![image](https://github.com/user-attachments/assets/e001f3ff-db88-4567-91ea-996b0563e5d2)

- Host machine identified `DESKTOP-SKBR25F.wiresharkworkshop.online` `172.16.1.66` - Part of lan segment 172.16.1[.]0/24
- Most traffic sent to `dualstack.sonatype.map.fastly.net` `199.232.196.209` - 455 packets A->B, 6085 packets B->A. A lot of return traffic!
- Second most active address `objects.githubusercontent.com` `195.199.110.133` - Again more inbound traffic than outbound
- 411 packets sent to unresolved IP address 141.98.0.79 - This very likely requires further investigation


### 2. 🔎 Investigating SMB
To begin checking SMB traffic, I filtered with `smb` and re checked conversations.

![image](https://github.com/user-attachments/assets/9f9c5c9b-e160-441a-8b1c-ae40d8b439c3)

- We can see the only two addresses are the domain controller, and `172.16.1.255`, which is the broadcast address of the LAN segment range. I then checked http exports -> SMB.

![image](https://github.com/user-attachments/assets/400e5da6-1bc0-4851-8290-674f07d4b364)

- There for now, I can summarise that no indication of external access, data exfil, or unauthorised occured. 

### 3. 🔎 Investigating HTTP
For HTTP traffic, I ran `http` and looked at the top conversations and file exports. This revealed no indication of suspicious activity.

![image](https://github.com/user-attachments/assets/c07b9f6b-147c-4d9e-93df-a6a11a0e5ec3)

![image](https://github.com/user-attachments/assets/3f7f9081-b784-45d2-84eb-65c80053103b)

### 4. Checking IP 199.232.196.209 (most traffic)
To begin, I ran `ip.addr == 199.232.196.209`. First packet date time: `2024-07-30 03:39:56`. 

