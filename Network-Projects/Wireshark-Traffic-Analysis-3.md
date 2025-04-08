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

Total Packets: 26922
PCAP SHA256 Hash: a38267943a7bf3b0e445d7e51cb0a68b3dee797d67081bc9a033f73d079c0f50
PCAP SHA1 Hash: cd0210e13050859e745daf9e168df74ed39198d3
98.6% of packets are IPv4
96.1% of packets are TCP

Local machine info:
- `10.11.26.183` - `DESKTOP-B8TQK49.local` - `d0:57:7b:ce:fc:8b`

Top IPv4 conversations:
- `modandcrackedapk.com` - `193.42.38.139` - 13248 packets - Most return traffic 7600 packets - 11MB
- `classicgrand.com` - `213.246.109.5` - 3996 packets - 2492 return packets - 4MB
- `e11271.dscg.akamaiedge.net` - `173.222.49.101` - 3442 packets - 2283 return packets - 3MB
- `nemotoes-dc.nemotoads.health` - `10.11.26.3` - 1508 packets - 710 return packets - 343kB

Key Takeaways:
- `modandcrackedapk.com` - Multiple TCP streams `https` - Largest return traffic - First packet: 
- `classicgrand.com` - Multiple TCP streams `https` - Second largest packet count - First packet:
- `e11271.dscg.akamaiedge.net`- Multiple TCP streams `https` - First packet: 
- `nemotoes-dc.nemotoads.health` - Multiple TCP streams `microsoft-ds` - Many UDP Streams `Port 53` - First Packet: 





