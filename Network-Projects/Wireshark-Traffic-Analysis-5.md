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

- [Trojan info](https://www.pcrisk.com/removal-guides/28668-packing-list-email-virus)
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
- SDP, NetBIOS, and DNS Activity: This is expected on LANS, but worth checking to see if any external parties show up.
- HTTP Traffic: 4 total packets and very small byte count.

#### Conversations

![image](https://github.com/user-attachments/assets/e001f3ff-db88-4567-91ea-996b0563e5d2)

- Host machine identified `DESKTOP-SKBR25F.wiresharkworkshop.online` `172.16.1.66` - Part of lan segment 172.16.1[.]0/24
- Domain controller ` wireshark-ws-dc.wiresharkworkshop.online` `172.16.1.4` - 1713 packets
- Most traffic sent to `dualstack.sonatype.map.fastly.net` `199.232.196.209` - 455 packets A->B, 6085 packets B->A. A lot of return traffic!
- Second most active address `objects.githubusercontent.com` `185.199.110.133` - Again more inbound traffic than outbound
- 411 packets sent to unresolved IP address `141.98.10.79` - This very likely requires further investigation


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
To begin, I ran `ip.addr == 199.232.196.209`. First packet date time: `2024-07-30 03:39:56`. Next query `ip.addr == 199.232.196.209 && tls.record.content_type == 22`, filters only TLS handshake messages.

![image](https://github.com/user-attachments/assets/90005049-eb71-4d83-a4a0-86efba333ede)

#### Key observations
- Domain repo1.maven.org via Fastly CDN
- Use Case Legitimate traffic — repo1.maven.org is the central Maven repository used for Java dependencies
- Pattern	Multiple Client Hellos and Server Hellos, followed by successful TLS key exchange
- Encryption TLSv1.2 is used — all application data is encrypted after the handshake
- TimingPackets clustered tightly together; likely a single dependency fetch or build tool sync (e.g., Maven or Gradle pulling packages)
- For now, no indication of malicious behavior.

### 3. 🔎 Investigating unresolved IP 141.98.10.79
Query ran: `ip.addr == 141.98.10.79`

![image](https://github.com/user-attachments/assets/beab292f-5286-48f4-877a-2379b45472b7)

#### Key observations
- First packet: `2024-07-30 03:40:05`
- Unusual Port 49754 → 12132 (non-standard)
- Lots of [PSH, ACK] traffic
- Data payloads present (Len=7, Len=137, etc.)
- Seemingly bi-directional and sustained traffic

- I then followed the TCP stream of a packet.

![image](https://github.com/user-attachments/assets/a8fa0565-4ee6-45b6-a88d-ec7b20c609eb)

#### Key observations
- This appears to be beaconing behaviour. We have regular and repetitive transmissions.
- Its highly structured with consistent formatting
- Port 12132 is non-standard
- The destination IP address `141.98.10.79` is unresolved.
- Theres no application level protocol involved - No HTTP, no TLS, no DNS — just raw TCP.
- No Legitimate Service or Payload (destination doesn’t provide any web page, file, update, or app-related function.)

#### IP address check
To verify this malicious activity, I utilised various online tools to scan this IP address against known malicious IP database.

- WhoIS lookup:
- No reverse DNS entry
- This provider is known for cheap hosting — often abused by threat actors for temporary infrastructure.

![image](https://github.com/user-attachments/assets/b3266273-7b26-4a95-ac5a-363a76b915a1)

- CiscoTalos:
- Poor sender IP reputation and untrusted web reputation
- Spam level set to critical
- Previosly listed on block lists

![image](https://github.com/user-attachments/assets/3c810944-18ae-42ea-ba91-115f034dfd71)

- VirusTotal:
- Labelled as suspicious / malicious
- Related to `Invoice & Packing List.eml` in relations tab. This is listed as a very malicious trojan.

![image](https://github.com/user-attachments/assets/0826f44b-853b-42de-9284-ec5c0b0454d0)

![image](https://github.com/user-attachments/assets/2357479e-a0bc-486d-879f-ccaca672a0df)

![image](https://github.com/user-attachments/assets/d430c42f-311a-496b-8ce6-1bc83a01f3cd)

- I then did a google search on this trojan. [Resource](https://www.pcrisk.com/removal-guides/28668-packing-list-email-virus)
- This article outlines this Trojan as malspam, containing a malicious attachment. Emails can deliver a variety of malware, including Trojans and cryptocurrency miners.



