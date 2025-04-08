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
For this section, I explored **Statistics** and other options in Wireshark, to gain an initial understanding of what we are working with.
