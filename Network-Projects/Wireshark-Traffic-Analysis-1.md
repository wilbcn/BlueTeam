 📡 Wireshark Project 1: Traffic Analysis & Scan Detection

This project is part of my Blue Team learning journey. It focuses on using **Wireshark** to investigate real network traffic, understand protocol behaviors, and detect network scans like those performed by tools such as **Nmap**.

## 🎯 Objectives

- Learn to navigate and use Wireshark for traffic analysis
- Understand core protocols: ARP, ICMP, DNS, HTTP, TCP
- Practice writing display filters to isolate traffic patterns
- Practice using Wiresharks UI
- Identify common scan types: TCP Connect, SYN, UDP
- Use Wireshark statistics, conversation views, and stream following

## Tools & Resources
- [PCAP Analysed](https://www.malware-traffic-analysis.net/2019/06/24/index.html)

---

## 📖 Project Walkthrough: Analyzing a Real-World PCAP in Wireshark
This section showcases the steps and thought process behind my decisions to carry out this project. 

### 1. Getting the sample PCAP file for analysis
To kick off this project, I booted up my secure AWS-based Homelab EC2 instance. I then downloaded a real-world packet capture file from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/2019/06/24/index.html), which is also noted in the **Tools & Resources** section.

Once the `.pcap` file was extracted using the password `infected<date>`, I loaded it into Wireshark for investigation.

<img width="1237" alt="image" src="https://github.com/user-attachments/assets/fb37a567-fe0d-4ed0-99a8-e4951037cb2e" />

- Successfully loaded PCAP file into Wireshark

<img width="1439" alt="image" src="https://github.com/user-attachments/assets/373fa684-e2b9-442e-9865-83a7a71f1319" />

### 1.1 Initial PCAP analysis - Leveraging Wireshark Statistics
The first step after loading the capture was to review its basic properties via **Statistics → Capture File Properties**. This pane provides essential metadata that helps establish a baseline understanding of the capture. Key findings included:
- Number of packets captured: 1633
- SHA1 Hash: 1c8f8d8fc4fa0872de90c126e9187884b54812ae
- SHA256 Hash: 55627f6b1cfa892b52eb0884fdd4545837c23d72a73b6d2ebb951bd7c41cbe46

<img width="958" alt="image" src="https://github.com/user-attachments/assets/fe45f89a-acc6-4f7b-a12f-870374b98619" />

These hashes are useful for ensuring integrity if the file is shared or submitted as evidence. Additionally, this section gives you details on the time span of the capture, data link type, and whether any packets were dropped, which can all affect analysis quality.

### 1.2 Investigating Protocol Hierarchy
Next, I analyed how many packets were associated with key protocols via **Statistics -> Protocol Hierarchy**. This step helps build a profile of the network activity observed. Key findings include:
- TCP Packets: 1631
- HTTP Packets: 10
- SMTP Packets: 55
- IMF Packets: 4
- DNS Packets: 2
- Data packets: 19
- Media type packets: 2
- IPv4 Packets: 100% (no IPv6 packets)

<img width="1152" alt="image" src="https://github.com/user-attachments/assets/37dbc587-8b67-4966-8630-a8f44fb4e0d7" />

### 1.3 Investigating Resolved Addresses
Next, I enabled **Name Resolution** for addresses, and then **Statistics -> Resolved Addresses**. This may allow us to spot suspicious or unusual domains from an instant glance. In our example PCAP, we already are beginning to see some red flags, given the domain `makemoneyeasywith.me`. This is definately worth investigating in later steps of this project and investigation. 

<img width="617" alt="image" src="https://github.com/user-attachments/assets/7570f8e1-3584-4e36-af89-81bae09ddb4a" />




