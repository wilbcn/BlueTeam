# 📡 Wireshark Project 4: ON-GOING

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
[Joes Sand Box](https://www.joesandbox.com/analysis/1501791/0/html)
[VirusTotal](https://www.virustotal.com/gui/home/upload)

<include any tools here i.e. VT>

## IOC's
<table></table>

## Investigation
### 1. PCAP Overview
Pre-investigation, I performed an initial overview of the PCAP, identifying bits of information which will assist in the overall investigation of the malware PCAP. 

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
- **A large amount of traffic is sent with TLS encrpytion**: `82.9%` - Could hide C2 and data exfiltration.
- **HTTP Traffic**: `2.2%` `114 packets` - HTTP web traffic is unencrypted, could reveal URLS or malicious payloads.
- **Kerberos, DHCP, NetBios**: Useful for who logged in, which devices were given IPs, and hostname information.
- **Domain Name System (DNS)**: `3.4%` `173 packets` - Check for DNS Tunnelling (Attackers hiding extra data inside DNS queries)
- **Address Resolution Protocol**: `5.8%` `294 packets` - Check for ARP Poisoning / MITM attacks. 

- **Capture File Properties**
![image](https://github.com/user-attachments/assets/25bbd600-e5eb-48b1-a4bf-d60b92a83e08)

#### Key Info
- **Victims endpoint**: `DESKTOP-RNVO9AT.bepositive.com (172.17.0.99)`
- **Address with most packets**: `win-ctl9xbq9y19.bepositive.com (172.17.0.17)` - 321kB total - 1308 packets (699 A→B, 609 B→A) 
- **Top Data Receiver**: `ns170.seeoux.com (46.254.34.201)` → 782 packets, 720 kB total, more inbound data ((278 A→B, 504 B→A))
- **Unresolved IP**: `79.124.78.197` - 591 packets - 64kB total
- **Cloud/C2 Services Contacted**: Multiple `*.azure.com`, `cloudapp.azure.com`, `akamai`, `trafficmanager.net`

### 2. Investigating HTTP 
To begin the investigation, I began looking at http traffic. By searching `http`, and then checking **Statistics→Endpoints** to see which IPs were most involved with http:

- `DESKTOP-RNVO9AT.bepositive.com (172.17.0.99)`
- `79.124.78.197`

![image](https://github.com/user-attachments/assets/abe5a3a8-6e6b-4e21-ad0f-5cf7a57f621a)

- I then ran some queries to investigate these two addresses:

```
http && ip.dst == 172.17.0.99
```

![image](https://github.com/user-attachments/assets/6e90531c-25a5-4014-826f-e459ed6e8fee)

#### Key Info
- **All packets are 200 OK responses**: Something is clearly pulling data from the attacker.
- **Consistent packet sizes**: The vast majority of packets are 222 bytes. This suggests some kind of automation or perhaps beaconing activity.
- **Content Types**: text/html might be payloads or commands delivered in plain formats.

- I then filtered on all http traffic for this address.

```
http && ip.addr == 172.17.0.99
```

- The first interaction from our victim to the suspicious ip `79.124.78.197` is at `2024-09-04 18:35:07`. Its a POST http method on `/foots.php`, which Wireshark has marked in yellow as content-encoded entity body (binary) 94 bytes. By following the stream we can see that there are consecutive POSTS, Binary payloads (`content-encoding: binary`), and that the user-agent field has been tampered with. This is typical with obfuscation / evasion tactics from attackers to help bypass detection. 

![image](https://github.com/user-attachments/assets/32aece99-3c38-4fc6-9a42-31d403aa44a1)

![image](https://github.com/user-attachments/assets/4e3b7e53-8b4b-4635-994b-c4f131b59f9c)

- So we have HTTP 200 responses from the malicious IP to our victim, and from victim to the malicious ip frequent post methods of `/foots.php`. With the patterned timing, unusual endpoint `79.124.78.197`, spoofed user agent field, encoded binaries, and consistent 200 responses, this is definately C2 communication. The malware sending binary POSTs to /foots.php.

- By following the TCP stream between the infected host (172.17.0.99) and the known malicious IP (79.124.78.197), I identified multiple HTTP POST requests made to the URI /foots.php. Each POST contained a binary or encoded payload, with content resembling a custom C2 protocol. Though decoding these payloads gave me non readable content.

![image](https://github.com/user-attachments/assets/c639860d-05fe-4bf0-bc57-5e16f6e5cac8)

- I also ran a check on VT for this identified IP address, which supports our findings that this is a malicious address.

![image](https://github.com/user-attachments/assets/4470b997-668a-4b59-91e5-206d485960b4)

- By searching `ip.addr == 79.124.78.197`, I get the full view of traffic related to this address. Immediately I spotted a GET method for `/index.php` at `2024-09-04 18:35:11`.
- TCP Stream:

![image](https://github.com/user-attachments/assets/59788a8c-8a10-400b-86eb-309dd7e6da93)

- We can quite clearly now see the GET and POST requests of the C2 communication. `GET /index.php?id=&subid=qIOuKk7U HTTP/1.1` from the malicious IP. The C2 response `HckDcK0czXjaq48jVHNn|qIOuKk7U|http://79.124.78.197/index.php`, and the POST binary payload.
- I exported the HTTP objects `index.php` to my desktop and generated the MD5 hashes.

```
md5sum index.php
5280f800cb74712cf68bfda2546e1ea5  index.php
```
```
mv 'index.php%3fid=&subid=qIOuKk7U' index2.php
md5sum index2.php 
8b3b8573ed4e48aca7ffba6ae817cc6b  index2.php
```

- I then viewed these files, solidifying our thoughts on this event. index.php is the POST Payload Binary and index2.php	is the GET Response we already identified.

![image](https://github.com/user-attachments/assets/0741f6a8-f10a-46e3-bea2-0df9601ad10b)

![image](https://github.com/user-attachments/assets/891cc716-f0a8-4dbd-891d-c4ba770f247f)

- Although both hashes came up clean in VT, this does not necessarily mean they are harmless. As we already know they are involved in malicious C2 activity.

- The first `POST` (18:35:07) from the victim is the **initial beacon**, reporting in or sending system info.
- The following `GET` (18:35:11) is the victim asking the C2 for instructions.
- Though the `GET` is *outbound*, the actual **command comes in the 200 OK** response.
- This behavior matches known malware C2 patterns: **check-in → receive task → execute → send result**.
  
### 3. DNS Traffic
- I then pivoted to looking at DNS. I initially ran `dns.qry.name.len > 15 and !mdns`, revealing lots of packets with info `The queried domain does not exist`.
- I then ran an updated query `dns.flags.rcode == 3 && !mdns`, showing:

![image](https://github.com/user-attachments/assets/d7f72c29-16bd-4040-bf37-b046d3415950)

#### Key Info
- `win-ctl9xbq9y19.bepositive.com (172.17.0.17)` appears to be the domain controller
- The victim `172.17.0.99` is making repeated DNS queries that were rejected by the internal DNS server.
- This is likely the malware attempting to resolve internal domains.

### 4. Investigating TLS
To begin looking at TLS traffic, I ran `tls` and looked at the top endpoints. This address `ns170.seeoux.com (46.254.34.201)` is the next step in my investigation. 

![image](https://github.com/user-attachments/assets/a24693da-1df3-468c-b1b6-72a3530179a4)

- Next query ran: `tls.handshake.type == 1 && ip.addr == 46.254.34.201`

![image](https://github.com/user-attachments/assets/0d39bbd3-cd90-4ed2-b5d8-ca0d26f32d6e)

- Here I filtered on the ClientHello, which is the client initiating the TLS handshake. We can see the first packet was at `2024-09-04 18:35:04`, which is before our first POST from the victim. I then directly filtered on this IP.

![image](https://github.com/user-attachments/assets/8713d703-c3e0-4b14-9bc5-eba4c7fdb6d5)

- Here we can see the first interaction is the TCP 3 way handshake (SYN→SYN ACK→ACK), confirming first contact was at `2024-09-04 18:35:04`. I then ran another query to check the SNI response to see where the encrypted traffic is actually going. 

```
tls.handshake.extensions_server_name && ip.addr == 46.254.34.201
```

- This revealed SNI `www.bellantonicioccolato.it`, which does not match the identified destination `ns170.seeoux.com`. This is highly suspicious, in normal traffic the SNI should match the domain the user intended to visit.
- I then google searched this domain followed by "Malware", which confirms that this domain is malicious.

![image](https://github.com/user-attachments/assets/6f249bdc-2866-4718-9c7f-629b12d4d525)

- Next query ran matches any packet Wireshark has marked with analysis flags.

```
tcp.analysis.flags && ip.addr == 46.254.34.201
```

![image](https://github.com/user-attachments/assets/318128dd-4193-4f0e-987f-a7506df964a3)

#### Key notes
This surfaced multiple TCP issues, including:
- TCP Dup ACK
- TCP Fast Retransmission
- TCP Out-Of-Order
- TCP Previous segment not captured
- TCP Spurious Retransmission

- This unclean web traffic confirms that `ns170.seeoux.com (46.254.34.201)` was part of the initial staging or command infrastructure.




