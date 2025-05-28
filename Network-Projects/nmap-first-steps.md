# 👁️ Simulated Endpoint Exposure Assessment Using Nmap

This project demonstrates my growing hands-on experience with industry-standard security tools, specifically **Nmap**, within a cloud-based environment. The goal is to simulate a realistic scenario in which a Security Operations Center (SOC) analyst is investigating a potentially misconfigured or exposed cloud instance.

To achieve this, I deployed a fresh AWS EC2 instance and intentionally configured it to expose common services such as **FTP**, **HTTP**, and **Telnet**, which are often flagged in real-world SOC environments due to misconfiguration or legacy use. I then used Nmap from my local machine to assess the host's network posture, identify exposed ports and services, and simulate a basic triage process.

For security reasons, this EC2 instance was terminated post project completion. Machine IP may vary.

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
- [VirusTotal](https://www.virustotal.com/gui/home/upload)

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

#### Update packages
```
sudo apt update && sudo apt upgrade -y
```

#### Install web server
```
sudo apt install apache2 -y
sudo systemctl enable apache2
sudo systemctl start apache2
```

#### Install FTP server
```
sudo apt install vsftpd -y
sudo systemctl enable vsftpd
sudo systemctl start vsftpd
```

#### Install Telnet server
```
sudo apt install inetutils-telnetd -y

sudo vi /etc/inetd.conf
```

Uncomment line:

![image](https://github.com/user-attachments/assets/f7108397-1ee6-4cdf-af49-75bd0fc01966)

```
sudo systemctl start inetd
```

#### Confirm services are listening
```
sudo ss -tuln
```

![image](https://github.com/user-attachments/assets/ee1ed602-8d45-4cb8-92dc-cb24b6486979)

### 3. 🔎 Investigating with nmap
After confirming that the three services are running and listening on the correct ports, I downloaded and installed nmap for windows, and ran my first command on our target machine.

#### Initial Discovery Scan
```
nmap MACHINE_IP
```

![image](https://github.com/user-attachments/assets/b902cbe0-23d8-4df1-8e14-d41d5a697213)

This command is for Host discovery + port scan (top 1000 ports). The output shows which commonly-used ports are open (like 21, 22, 23, 80), and is a good first step to verify exposure. Since HTTP (port 80) was detected, it is good practice to verify the web service via a browser to confirm whether it is functional and to observe any publicly visible content.

![image](https://github.com/user-attachments/assets/bfbe0517-7139-408a-83ba-eb4a7220df67)

#### Full TCP Port Scan
```
nmap -p- MACHINE_IP
```

![image](https://github.com/user-attachments/assets/8b7c91c4-36c9-492d-9ad4-9d9e3c4425a8)

This command scans all 65,535 TCP ports, which could catch services on non-standard ports. However in our case, we know which ports and services are exposed.

#### Version Detection
```
nmap -sV MACHINE_IP
```

![image](https://github.com/user-attachments/assets/244d7847-625d-488a-a91a-b55b60fa5306)

This command identifies the version of software/services that are running on the open ports. This is useful for detecting legacy or outdated services which may be known for vulnerabilities/CVEs.

#### OS Detection
```
nmap -O MACHINE_IP
```

To fingerprint the operating system of the target host, I used ran the above command. 

![image](https://github.com/user-attachments/assets/aa54ce6e-5b81-4cd7-807c-9cc6a5105d11)

OS Guess:
- Linux 4.x/5.x (multiple possible kernel versions)
- MikroTik RouterOS 7.x (87% confidence)

This command is useful for asset clarification. Were the results as expected? Is this really a Linux server?

![image](https://github.com/user-attachments/assets/ec980bd3-bef6-479a-b64b-f76ee3858194)

#### Aggressive Scan
```
nmap -A MACHINE_IP
```

An aggresive scan consoldates multiple searches in one ago: OS detection, version, traceroute.

Traceroute (12 hops) confirmed the host is accessible across the internet with normal latency. OS detection returned the same information as earlier.

#### TCP SYN Scan
Unlike a TCP connect scan which tries to complete the three-way handshake, the SYN scan only executes the first step. It sends a TCP SYN packet, and upon receiving a SYN, ACK in response, we immediately close the connection with RST (Case: TCP port is actually open).

This method is:
- Faster and stealthier than a full TCP connect `-sT` scan
- Less likely to be logged by some host-based firewalls or intrusion detection systems
- Commonly used during initial triage or discovery by security analysts

```
nmap -sS MACHINE_IP
```

#### Bypassing Host Discovery
By default, Nmap pings a host first to determine if it's up/online before scanning it. However, firewalls or cloud providers often block ping (ICMP) and even TCP ping probes, causing false negatives as Nmap thinks the host is down when it isn’t. The `-Pn` option skips host discovery and treats the target as online, forcing Nmap to scan it regardless of ping response.

```
nmap -Pn MACHINE_IP
```

### 4. Scanning a known malicious IP address.
During one of my honeypot deployments, where SSH port 22 was publicly exposed, I identified a malicious IP: 211.101.246.5

This IP attempted to brute force SSH access, initiating repeated connection attempts from a wide range of source ports — a behavior commonly associated with automated scanning or botnet activity.

[Honeypot Project](https://github.com/wilbcn/BlueTeam/blob/main/Honeypots/Cowrie-Virtual-Honeypot-2.0.md)

As a continuation of this project and to gain further experience, I then ran various nmap commands on this IP address and recorded the findings. Command ran:

```
nmap -Pn -sV 211.101.246.5
```

- `-Pn`: Disables nmaps host discovery step. Many malicious IPs block pings to avoid detection. We already know the IP is active from our honeypot alert logs.
- `-sV`: Scans open ports to try and identify the service and version running on each.

#### Key Findings

| **Port** | **State** | **Service** | **Version** |
|----------|-----------|-------------|-------------|
| 22 | Open | SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0) |
| 135 | filtered | msrpc | - | 
| 139 | filtered | netbios-ssn | - |
| 445 | filtered | microsoft-ds | - |

- The target is running `OpenSSH 8.2p1 Ubuntu`, consistent with a Linux-based system
- Ports `135`, `139`, `445` are filtered. This could be a firewall or IDS which is actively surpressing access.
- OS Fingerprinting suggests a Linux host: `OS: Linux; CPE: cpe:/o:linux:linux_kernel`
- The discovery of open port **22/tcp (SSH)** on the remote IP aligns with the behavior observed in my honeypot logs. My Cowrie honeypot was configured to expose only port 22, and this IP initiated numerous SSH connection attempts during the deployment period.

![image](https://github.com/user-attachments/assets/b2951223-5945-4eb2-bd63-1bd07400b000)

![image](https://github.com/user-attachments/assets/de78a85e-6916-4e41-86b8-e4945d4cfcca)

This remote host is actively scanning, and attempting to brute-force SSH services. The findings from the honeypot investigation, enrichment tools like VirusTotal, and nmap scan results, support escalation and blocklist actions.

### 5. Project Summary and Key takeaways
This project served as a hands-on introduction to Nmap in the context of practical security investigations. After completing a number of learning paths on TryHackMe, this was my way of solidifying the material — and applying it in a cloud-based lab environment that simulates real-world SOC scenarios.

Key takeaways:
- Nmap is an essential tool in blue team workflows, helping analysts profile hosts, investigate suspicious traffic, and enrich alerts.
- Flags like -sV, -Pn, -O, and -A serve different purposes depending on the investigation scope.
- Understanding when and why to use different scan types is just as important as running them.
- Investigating real-world malicious activity (e.g., honeypot attacks) adds critical realism to defensive learning.
- To note: I am also building a personal SOC playbook from my notes and labs to support continuous learning across platforms like TryHackMe, HTB, and BlueTeam Labs.


