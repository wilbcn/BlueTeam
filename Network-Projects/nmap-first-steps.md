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

This command identifies what software/services are running on the open ports. This is useful for detecting legacy or outdated services which may be known for vulnerabilities/CVEs.

#### OS Detection




