# Cowrie-Based Honeypot Deployment on AWS

## 📚 Overview

<project intro>

---


## 🎯 Project Goals

- Deploy a low-interaction honeypot in the cloud securely
- Simulate a vulnerable SSH service to attract real-world attacks
- Log attacker behavior and extract useful insights
- Gain practical experience with legal and ethical security practices
- Establish groundwork for future behavioral honeypot research

---

## 📦 1 – Cloud Setup
In this phase, I outline the steps taken to configure and launch a new EC2 instance that will serve as our SSH honeypot. This virtual machine must be carefully provisioned—with appropriate instance specifications, network isolation, and security controls—to ensure it can run the honeypot reliably and safely in a cloud environment. 

### 1.1 ☁Honeypot Overview
Firsly I logged into my AWS account, and navigated to `EC2`. From here, I selected `launch instance` to begin setting up our Virtual Machine. I have provided an overview of the EC2 configuration as well as any necessary explanations. 

- **Instance Name**: `Cowrie-Honeypot`
- **Region**: `eu-north-1a` (GDPR-compliant region)
- **Instance Type**: `t3.xlarge` (4 vCPU, 16GB RAM)
- **AMI**: `Ubuntu Server 24.04 LTS (HVM),EBS General Purpose (SSD) Volume Type`.
- **Storage**: `128GB`

### 1.2 Network settings
- **VPC**: A new VPC was created to ensure full isolation of the honeypot from any other cloud resources. An Internet Gateway was attached to allow inbound and outbound traffic.
- **Subnet**: A new Subnet was created within eu-north-1a for logical separation.
- **Auto-assign public IP**: This is required so the honeypot can be accessed by external attackers. Without a public IP, no unsolicited traffic can reach the system.

### Security Group Rules

| Port | Purpose | Source | Description |
|------|---------|--------|-------------|
| 22 | SSH access | Your IP only | For administrative access to the server |
| 2222 | Cowrie honeypot port | 0.0.0.0/0 | Used to attract SSH scans/attacks (Rule to be activated after Cowrie is running) |

### SSH Key Pair
- Create a new key pair
- Run `chmod 600 example_key.pem`. This permission is required by SSH to prevent unauthorised access and is enforced by AWS security standards.
- Connect with:  
  `ssh -i "example_key.pem" ubuntu@<public-ip>`

---

## 2 – Honeypot Installation


