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

## Project walk-through
This section showcases the steps and thought process behind my decisions to carry out this project. 

### 1. Getting the sample PCAP file for analysis
To kick off this project, I went over to AWS and booted up my secure Homelab EC2 instance. I then downloaded the sample PCAP file, which is noted in the **tools & resources** section.

<img width="1237" alt="image" src="https://github.com/user-attachments/assets/fb37a567-fe0d-4ed0-99a8-e4951037cb2e" />

- Successfully loaded PCAP file into Wireshark

<img width="1439" alt="image" src="https://github.com/user-attachments/assets/373fa684-e2b9-442e-9865-83a7a71f1319" />

### 1.1 Artifact gathering and familiarity using Wireshark
The first thing I did after loading in the PCAP, was go to **statistics** and **capture file properties**. This provides us a new window pane which is full of useful information such as:
- Number of packets captured: 1633
- SHA1 Hash: 1c8f8d8fc4fa0872de90c126e9187884b54812ae
- SHA256 Hash: 55627f6b1cfa892b52eb0884fdd4545837c23d72a73b6d2ebb951bd7c41cbe46

<img width="958" alt="image" src="https://github.com/user-attachments/assets/fe45f89a-acc6-4f7b-a12f-870374b98619" />




