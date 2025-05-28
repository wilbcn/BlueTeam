# 👁️ Simulated Endpoint Exposure Assessment Using Nmap

This project demonstrates my growing hands-on experience with industry-standard security tools, specifically **Nmap**, within a cloud-based environment. The goal is to simulate a realistic scenario in which a Security Operations Center (SOC) analyst is investigating a potentially misconfigured or exposed cloud instance.

To achieve this, I deployed a fresh AWS EC2 instance and intentionally configured it to expose common services such as **FTP**, **HTTP**, and **Telnet**, which are often flagged in real-world SOC environments due to misconfiguration or legacy use. I then used Nmap from my local machine to assess the host's network posture, identify exposed ports and services, and simulate a basic triage process.

For security reasons, this EC2 instance was terminated post project completion.

---

## 🎯 Objectives

- Deploy a new EC2 instance in AWS with publicly accessible services
- Simulate exposure of a web server, FTP server, and Telnet service
- Perform network reconnaissance using Nmap from my local machine
- Analyze scan results and document potential risks from a SOC analyst's perspective

## 🛠️ Tools & Resources
- Amazon EC2
- [nmap](https://nmap.org/download.html#windows)
- [learning material](https://tryhackme.com/room/nmap02)

## 📖 Project Walkthrough
### 1. 🚀 Launching the EC2 instance
Firstly, I headed over to Amazon EC2 on my admin account (not root), and launched a fresh EC2 instance with the following configuration.

| Attribute              | Value                                                                 |
|------------------------|-----------------------------------------------------------------------|
| Instance Name          | `nmap_project`                                                    |
| Instance Type          | `t3.micro`                                   |
| AMI Used               | Ubuntu 24.04 LTS 							|
| Storage                | 8 GB EBS (General Purpose SSD)                                      |
| Admin SSH Access       | Port `22`        |
| Web Server             | Port `80`        |
| FTP Server             | Port `21`        |
| Telnet Service         | Port `23`        |
| Key Pair Auth          | Key-based authentication for admin access                            |
| Region / Subnet        | `eu-north-1a`, custom VPC with auto-assigned public IP               |
| Purpose                | Simple EC2 configuration to simulate nmap tests  |

### 2. ⚙️ Configuring the EC2 instance
Once the instance had successfully launched and had a public IP address, I logged in via SSH and key authentication. Inside, I ran the following to successfully configure and simulate the exposed services (HTTP, FTP, TELNET).


