# Cowrie-Based Honeypot Deployment on AWS 2.0

## 📚 Overview
This follow up project is an adaptation and refinement of my original Cowrie honeypot deployment, found here: [link](https://github.com/wilbcn/BlueTeam/edit/main/Honeypots/Cowrie-Virtual-Honeypot.md). This project serves as both a trial phase towards my research project proposal on honeypot realism and fingerprinting (University project), as well as a continuation of hands-on experience that covers multiple security domains like OS hardening and network security.

---

## 🎯 Project Goals

- Deploy a secure SSH honeypot in AWS (secure admin access)
- Simulate a vulnerable SSH service to attract real-world attacks
- Log attacker behavior and extract useful insights
- Configure the EC2 instance with the `CIS Hardened Image Level 1 on Ubuntu Linux Server 24.04 LTS`
- Allow brute force attempts after a defined number - Edit the config file
- Lay the foundation for the next trial phase, of Splunk integration for log aggregation and analysis

---

## Acknowledgements
- [Cowrie Documentation](https://docs.cowrie.org/en/latest/README.html)

## Tools & Resources
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [Hardened AMI](https://aws.amazon.com/marketplace/pp/prodview-6l5e56nst6r3g)
- [WHOIS Lookup](https://whois.domaintools.com/)
- Amazon EC2 Instances
- Cowrie SSH Honeypot

---

## 📦 1. – Cloud Setup
In this follow up project, I create a brand new ec2 instance with similar configurations as the original deployment. This time, leveraging the hardened AMI from AWS marketplace. I also deployed the instance with instance type `t3.medium`, as this is currently what I intend to use during my research project implementation. 

- Public IP redacted for security reasons

### 1.1 - Honeypot Overview
Once inside my AWS account, I navigated to EC2 and selected launch instance. I named it `Cowrie-Trial-01`, and went to `Browse more AMIs`. 

![image](https://github.com/user-attachments/assets/8e84ae31-c71e-469e-b0f8-5be83fec9b21)

From here, I selected the appropriate AMI, and `subscribe on instance launch`.

![image](https://github.com/user-attachments/assets/f124ff8d-eef5-4ffc-8eef-450939138e92)

With the AMI successfully selected, I then chose our instance type `t3.medium`. I aim to deploy two contrasting honeypots for a comparative analysis, and therefore predict that this instance type will be a cost effective yet appropriate solution for my project.

![image](https://github.com/user-attachments/assets/a35c94ad-2985-4ea3-a1e8-6081bc6e20bb)

I then created a new key pair for secure admin access. We use SSH keys to access the system securely, while cowrie as a honeypot simulates password logins for the attacker. Attackers interact with Cowries fake shell, not the real system.

![image](https://github.com/user-attachments/assets/f090f1a7-882d-448d-a501-4eab90ada4ac)

I then created a brand new VPC and subnet in `eu-north-1a` (not shown), and enabled auto-assign public IP.

![image](https://github.com/user-attachments/assets/62569a11-dd8c-4176-9e27-59cc9f0e75d2)

Next, I needed a new Security Group to allow remote Admin access. For this deployment, I allowed inbound Custom TP connections from my IP only, on port 22222. This is because later we will add an additional rule to allow public access on standard ssh port 22.

For storage, I chose `30 GB of EBS General Purpose (SSD)`

#### Honeypot summary
| Attribute              | Value                                                                 |
|------------------------|-----------------------------------------------------------------------|
| Instance Name          | `Cowrie-Trial-01`                                                    |
| Instance Type          | `t3.medium` (2 vCPUs, 4 GB RAM)                                      |
| AMI Used               | CIS Hardened Ubuntu 24.04 LTS (AWS Marketplace)                      |
| Storage                | 30 GB EBS (General Purpose SSD)                                      |
| Admin SSH Access       | Port `22222`, restricted to admin IP only                            |
| Attacker SSH Port      | Port `22` (planned to be opened publicly later on)                   |
| Key Pair Auth          | Key-based authentication for admin access                            |
| Region / Subnet        | `eu-north-1a`, custom VPC with auto-assigned public IP               |
| Purpose                | Trial phase setup to validate Cowrie configuration and EC2 settings  |

### 2. - Honeypot Installation

