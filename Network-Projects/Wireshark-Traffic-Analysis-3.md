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
  - **Strong candidate as initial download source**

- **`classicgrand.com`**  
  - Second-highest byte count  
  - Encrypted traffic via HTTPS

- **`e11271.dscg.akamaiedge.net`**  
  - Akamai CDN; could be legitimate or abused for payload delivery

- **`nemotoes-dc.nemotoads.health`**  
  - Internal host communication  
  - SMB (`microsoft-ds`) and DNS (UDP port 53)





