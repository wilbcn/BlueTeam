# 📡 Wireshark Project 3: Network Analysis & Incident report writing

This follow-up Wireshark project dives into another real-world malware PCAP. This time focusing on writing an incident report based on malicious network activity from the pcap and from the alerts.

The incident report will contains the following 3 sections:

- Executive Summary: State in simple, direct terms what happened (when, who, what).
- Victim Details: Details of the victim (hostname, IP address, MAC address, Windows user account name).
- Indicators of Compromise (IOCs): IP addresses, domains and URLs associated with the activity.  SHA256 hashes if any malware binaries can be extracted from the pcap.

This PCAP is part of a series of traffic analysis exercises, found in the **Tools & Resources** section.

## 🎯 Objectives
- Analyse the Malware Sample PCAP provided, listed in the tools & resources
- Carry out a detailed incident report, outlined above.
- State any lessons learned and room for future growth.


## Tools & Resources
- [Sample PCAP source](https://www.malware-traffic-analysis.net/2024/11/26/index.html)


## 📖 Project Walkthrough: Incident report writing on a real-world malware PCAP.
This section breaks down the steps and thought process I followed while working through this PCAP. 

### 1. PCAP Summary and Overview
Exploring the file in Wireshark to gain an initial understanding of what we are working with.

**PCAP Info:**
- **Total Packets:** 26,922
- **SHA256:** `a38267943a7bf3b0e445d7e51cb0a68b3dee797d67081bc9a033f73d079c0f50`
- **SHA1:** `cd0210e13050859e745daf9e168df74ed39198d3`
- **IPv4:** 98.6% of traffic
- **TCP:** 96.1% of traffic

**Local Machine Identified:**
- **IP:** `10.11.26.183`
- **Hostname:** `DESKTOP-B8TQK49.local`
- **MAC Address:** `d0:57:7b:ce:fc:8b`

---

### Top IPv4 Conversations:

| Domain                          | IP                | Packet Count | Return Packets | Total Bytes |
|---------------------------------|-------------------|--------------|----------------|-------------|
| `modandcrackedapk.com`          | `193.42.38.139`   | 13,248       | 7,600          | 11 MB       |
| `classicgrand.com`              | `213.246.109.5`   | 3,996        | 2,492          | 4 MB        |
| `e11271.dscg.akamaiedge.net`    | `173.222.49.101`  | 3,442        | 2,283          | 3 MB        |
| `nemotoes-dc.nemotoads.health`  | `10.11.26.3`      | 1,508        | 710            | 343 kB      |

---

### 🔍 Early Observations

- **`modandcrackedapk.com`**  
  - Most data exchanged (~11MB)
  - Multiple `HTTPS` TCP streams  
  - High return packet count  
  - First packet: 26-11-2024 04:50:14

- **`classicgrand.com`**  
  - Second-highest byte count  
  - Encrypted traffic via HTTPS
  - First packet: 26-11-2024 04:50:11

- **`e11271.dscg.akamaiedge.net`**  
  - Akamai CDN; could be legitimate or abused for payload delivery
  - First packet: 26-11-2024 05:04:59

- **`nemotoes-dc.nemotoads.health`**  
  - Internal host communication  
  - SMB (`microsoft-ds`) and DNS (UDP port 53)
  - The internal Domain Controller
  - First packet: 26-11-2024 04:49:38
  - First address with traffic out of the 4 identified

### 2. Investigating the PCAP
After gathering the initial, but important artifacts from this PCAP file, I now invesigated further leveraging these findings.

Firstly i ran the below filter.

```
dns.qry.name == "modandcrackedapk.com"
```

<img width="1440" alt="image" src="https://github.com/user-attachments/assets/d458a634-9adc-4083-b700-2d764da193c5" />

This confirmed that nemotoes-dc.nemotoads.health is functioning as the domain controller (DC) and internal DNS resolver. We can see the infected host, DESKTOP-B8TQK49.local, querying the DC for the domain modandcrackedapk.com. The DC responds with the IP address 193.42.38.139, which becomes the destination for encrypted traffic shortly after.

This address `modandcrackedapk.com` is definately worth investigating further, a VT scan confirms this.

![image](https://github.com/user-attachments/assets/63d1a31f-5291-4a81-89b9-6fe285828a94)

Next filter ran:

```
ip.addr == 193.42.38.139
```

![image](https://github.com/user-attachments/assets/7b9e3f93-0d77-4250-9c0b-7b597c79f732)

![image](https://github.com/user-attachments/assets/0a59e4fb-0e6a-4eb8-bac3-d2902acfc794)

Key takeaways:
- Spurious retransmissions (TCP Spurious Retransmission)
- Duplicate ACKs (TCP Dup ACK)
- Consistent TLS record sizes (e.g. 1430)
- Continuation Data entries with TLSv1.3 and SSLv2 (Encrypted content)

It is now becoming clear that `193.42.38.139` - `modandcrackedapk.com` is the C2 Server. 

Even though there is minimal `http` traffic (74 packets), we should still investigate for any potential web application downloads. 

Filter ran:

```
http
```

<img width="1440" alt="image" src="https://github.com/user-attachments/assets/e36bdd7e-fe33-4fcd-980c-78c8cf6e5361" />

Key takeaways:
- NetSupport RAT traffic: 194.180.191.164:443 – POST http:// 194.180.191.164/fakeurl.htm
- `194.180.191.64` is a known malicious IP on VT. This is a IOC. 
- New address introduced `geo.netsupportsoftware.com` - VT Scan indicates malicious too.

The identified IPs by filtering for `http` are malicious. By following the `http` stream, we can see that `NetSupport Manager` appears to be abused, posting to `http://194.180.191.64/fakeurl.htm`.
`CMD=POLL` and `CMD=ENCD` commands show command polling and data exfiltration. `DATA= values` are encoded/encrypted blobs (not plain exfil, so we won’t see creds or strings in cleartext).

<img width="1433" alt="image" src="https://github.com/user-attachments/assets/fe974e6f-8f7f-4d1d-a36c-91b2ee2aaa73" />

Additionally, `classicgrand.com` - `213.246.109.5` needs investigating. The timestamp of the first packet appears just before contact with the identified malicious addresses. 

Filter ran:
```
dns.qry.name == "classicgrand.com"
```

<img width="1439" alt="image" src="https://github.com/user-attachments/assets/020f42a8-6c5a-4b0b-b5dc-002be80f1b61" />

This screen shot shows the infected host (10.11.26.183) queries this domain very early, with timestamp 04:50:11.

Filter ran:
```
tls.handshake.type == 1 && ip.addr == 213.246.109.5
```

<img width="1440" alt="image" src="https://github.com/user-attachments/assets/537fec0b-95cf-4cfd-9a60-1ca14ec809a5" />

This confirms the first Client Hello happens at 04:50:11.5, which is right before any other TLS connections — very early in the infection timeline. The other domains such as `modandcrackedapk.com` - `194.180.191.64` happen after this domain appears. This makes `classicgrand.com` the earliest external domain in the PCAP aside from expected traffic (like Akamai or Windows connect test).     The domain name doesn’t align with enterprise or common services. Combined with the encrypted traffic and early timing, this is suspicious. Based on everything, the traffic pattern matches what you’d expect from a landing page — first contact, possible payload delivery (though TLS hides content), and immediate follow-ups to malicious domains afterward.



